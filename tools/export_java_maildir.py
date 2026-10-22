"""Offline, copy-only Java rollback export; never changes the source or database.

Both application runtimes must be stopped throughout the export. PostgreSQL
stays running. Use a new output path and retain the original Maildir/spool and
Redis state: pending tasks can still contain absolute paths into that source.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import stat
import tempfile
import time
from pathlib import Path

import psycopg


def walk_error(error: OSError):
    raise error


def java_alias(address: str, *, writer: bool = False) -> str:
    value = "".join("_" if char in '/\\:*?"<>|' else char
                    for char in address.strip().lower()
                    if ord(char) > 31 and ord(char) != 127)
    if not value:
        return "unknown"
    if writer:
        if value.startswith("."):
            value = "_" + value[1:]
        if value.endswith("."):
            value = value[:-1] + "_"
        return value
    return value.replace("..", "__")


def v2_path(address: str) -> Path:
    raw = address.strip().lower().encode()
    return Path("v2", *("c-" + raw[offset:offset + 120].hex().upper()
                        for offset in range(0, len(raw), 120)), f"z-{len(raw):08X}")


def v1_path(address: str) -> Path:
    safe = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@._-+"
    return Path("v1-" + "".join(chr(byte) if byte in safe else f"%{byte:02X}"
                               for byte in address.strip().lower().encode()))


def component(value: str) -> str:
    if not value or value in (".", "..") or "/" in value or "\\" in value or "\0" in value:
        raise ValueError("non-component in indexed Maildir path")
    if len(value.encode()) > 255:
        raise ValueError("Java path component exceeds Linux NAME_MAX")
    return value


def real_directory(path: Path) -> Path:
    path = path.absolute()
    for parent in (path, *path.parents):
        metadata = parent.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"directory or ancestor is not a real directory: {parent}")
    return path.resolve(strict=True)


def digest(path: Path, *, deadline: float | None = None) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError(f"source is not a regular file: {path}")
        checksum = hashlib.sha256()
        while True:
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("offline Maildir export deadline exceeded")
            chunk = source.read(1024 * 1024)
            if not chunk:
                return checksum.hexdigest()
            checksum.update(chunk)


def export_maildir(source: Path, output: Path, dsn: str, *, offline: bool,
                   max_bytes: int, max_files: int = 1_000_000,
                   max_mailboxes: int = 100_000, timeout_seconds: float = 3600) -> dict:
    if not offline:
        raise ValueError("stop both application runtimes and explicitly select offline export")
    if (min(max_bytes, max_files, max_mailboxes, timeout_seconds) <= 0
            or not math.isfinite(timeout_seconds) or timeout_seconds > 86400):
        raise ValueError("export budgets must be positive")
    source = real_directory(source)
    output = output.absolute()
    parent = real_directory(output.parent)
    output = parent / output.name
    if output.exists() or output.is_symlink() or output.is_relative_to(source):
        raise ValueError("output must be a new path outside the source Maildir")
    started = time.monotonic()
    deadline = started + timeout_seconds
    stage = Path(tempfile.mkdtemp(prefix=".lmyzmail-java-export-", dir=parent))
    inventory = {}
    copied_bytes = 0
    copied_files = 0
    mappings = 0
    source_directories = 0

    def budget():
        if time.monotonic() >= deadline:
            raise TimeoutError("offline Maildir export deadline exceeded")

    def copy_file(original: Path, destination: Path):
        nonlocal copied_bytes, copied_files
        budget()
        if copied_files >= max_files:
            raise ValueError("export file budget exceeded")
        metadata = original.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"source is not a regular file: {original}")
        if copied_bytes + metadata.st_size > max_bytes:
            raise ValueError("export disk budget exceeded")
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(original, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        sha = hashlib.sha256()
        count = 0
        with os.fdopen(descriptor, "rb") as input_file, destination.open("xb") as output_file:
            before = os.fstat(input_file.fileno())
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                    metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns):
                raise ValueError("source changed before export copy")
            while chunk := input_file.read(1024 * 1024):
                budget()
                count += len(chunk)
                if copied_bytes + count > max_bytes:
                    raise ValueError("export disk budget exceeded while streaming")
                output_file.write(chunk)
                sha.update(chunk)
            after = os.fstat(input_file.fileno())
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
                    ) or count != metadata.st_size:
                raise ValueError("source changed during export copy")
            output_file.flush()
            os.fsync(output_file.fileno())
        copied_bytes += count
        copied_files += 1
        return sha.hexdigest()

    # Source remains untouched on failure; the unpublished staging directory is
    # deliberately retained for diagnosis and must never be used as a Maildir.
    with psycopg.connect(dsn) as database:
        database.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        database.execute("SET LOCAL statement_timeout='30s'")
        owners = database.execute("SELECT address FROM mailbox ORDER BY id LIMIT %s",
                                  (max_mailboxes + 1,)).fetchall()
        if len(owners) > max_mailboxes:
            raise ValueError("export mailbox ownership budget exceeded")
        aliases = {}
        for (raw_owner,) in owners:
            owner = raw_owner.strip().lower()
            for writer in (False, True):
                aliases.setdefault(java_alias(owner, writer=writer), set()).add(owner)
        for root, directories, files in os.walk(source, followlinks=False, onerror=walk_error):
            budget()
            source_directories += 1
            if source_directories > max_files:
                raise ValueError("export directory budget exceeded")
            root_path = Path(root)
            relative = root_path.relative_to(source)
            for name in directories:
                if (root_path / name).is_symlink():
                    raise ValueError("symlinked source directory in offline Maildir export")
                (stage / relative / name).mkdir(parents=True, exist_ok=True)
            for name in files:
                original = root_path / name
                relative_file = original.relative_to(source)
                sha = copy_file(original, stage / relative_file)
                inventory[relative_file] = (original.stat().st_size, sha)
        manifest_path = stage / ".lmyzmail-java-rollback.jsonl"
        if copied_files >= max_files:
            raise ValueError("export file budget excludes required manifest")
        copied_files += 1
        with manifest_path.open("x", encoding="utf-8") as manifest:
            with database.cursor(name="rollback_index", withhold=False) as rows:
                rows.itersize = 256
                rows.execute("SELECT id,mailbox_address,folder,file_name,subdirectory "
                             "FROM email_index ORDER BY id")
                for index_id, address, folder, filename, subdirectory in rows:
                    budget()
                    if mappings >= max_files:
                        raise ValueError("export indexed-row budget exceeded")
                    address = address.strip().lower()
                    if aliases.get(java_alias(address)) != {address}:
                        raise ValueError(f"unsafe Java mailbox alias for indexed owner {address}")
                    suffix = Path(component(folder))
                    if subdirectory is not None and subdirectory > 0:
                        suffix /= str(subdirectory)
                    if subdirectory is not None and subdirectory < 0:
                        raise ValueError("negative indexed Maildir subdirectory")
                    suffix /= component(filename)
                    candidates = [v2_path(address)]
                    for alias in (java_alias(address), java_alias(address, writer=True)):
                        if aliases.get(alias) == {address}:
                            candidates.append(Path(component(alias)))
                    v1 = v1_path(address)
                    if not (aliases.get(str(v1), set()) - {address}):
                        candidates.append(v1)
                    available = list(dict.fromkeys(path / suffix for path in candidates
                                                   if path / suffix in inventory))
                    if not available:
                        raise ValueError(f"no exclusively owned indexed source for row {index_id}")
                    hashes = {inventory[path][1] for path in available}
                    if len(hashes) != 1:
                        raise ValueError(f"conflicting indexed source bytes for row {index_id}")
                    selected = available[0]
                    target = Path(component(java_alias(address))) / suffix
                    if target in inventory:
                        if inventory[target][1] not in hashes:
                            raise ValueError("Java rollback destination conflicts with existing bytes")
                    else:
                        expected = inventory[selected][1]
                        if (stage / target).exists():
                            if digest(stage / target, deadline=deadline) != expected:
                                raise ValueError("Java rollback alias conflicts across index rows")
                        elif copy_file(source / selected, stage / target) != expected:
                            raise ValueError("source changed while exporting Java alias")
                    entry = json.dumps({"index_id": index_id, "owner": address,
                        "source": str(selected), "java_path": str(target),
                        "sha256": next(iter(hashes))}, ensure_ascii=False) + "\n"
                    copied_bytes += len(entry.encode())
                    if copied_bytes > max_bytes:
                        raise ValueError("export disk budget exceeded by manifest")
                    manifest.write(entry)
                    mappings += 1
            manifest.flush()
            os.fsync(manifest.fileno())
        # A live writer or unexpected source mutation invalidates publication.
        observed = set()
        for root, directories, files in os.walk(source, followlinks=False, onerror=walk_error):
            for name in directories:
                if (Path(root) / name).is_symlink():
                    raise ValueError("source directory changed during export")
            for name in files:
                budget()
                path = Path(root) / name
                relative = path.relative_to(source)
                if relative not in inventory or (
                        path.lstat().st_size, digest(path, deadline=deadline)) != inventory[relative]:
                    raise ValueError("source contents changed during offline export")
                observed.add(relative)
        if observed != set(inventory):
            raise ValueError("source files disappeared during offline export")
    for root, _, _ in os.walk(stage, topdown=False, onerror=walk_error):
        budget()
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    # Fail again if another operator claimed the new wrapper name.
    budget()
    if output.exists() or output.is_symlink():
        raise ValueError("output appeared during export; staging was not published")
    # Atomic exclusive creation prevents replacing an existing user directory.
    # The private wrapper receives one atomic, fully-fsynced Maildir publication.
    output.mkdir(mode=0o700)
    os.rename(stage, output / "maildir")
    descriptor = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {"status": "passed", "source_unchanged": True, "database_read_only": True,
            "source_files": len(inventory), "export_files": copied_files,
            "copied_bytes": copied_bytes, "indexed_mappings": mappings,
            "output": str(output / "maildir"), "elapsed_seconds": time.monotonic() - started,
            "pending_spool_requirement": "retain the original source path and Redis state"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dsn", default="", help="libpq DSN; defaults to standard PG* environment")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--max-bytes", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=3600)
    args = parser.parse_args()
    print(json.dumps(export_maildir(args.source, args.output, args.dsn,
        offline=args.offline, max_bytes=args.max_bytes, timeout_seconds=args.timeout),
        indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
