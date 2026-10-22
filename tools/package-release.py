#!/usr/bin/env python3
"""Package a verified ELF, installation assets, complete tracked source and history."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import shutil
import subprocess
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def git(*arguments: str) -> str:
    return subprocess.check_output(["git", "-C", str(ROOT), *arguments], text=True).strip()


def sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    commit = git("rev-parse", "HEAD")
    if git("diff", "HEAD", "--name-only"):
        raise SystemExit("commit tracked source changes before packaging")
    evidence = json.loads(arguments.evidence.read_text(encoding="utf-8"))
    if evidence["commit"] != commit or not evidence["verification"]["byte_identical"]:
        raise SystemExit("reproducibility evidence must match this exact commit")
    if sha256(arguments.binary) != evidence["artifact"]["sha256"]:
        raise SystemExit("binary differs from the independently reproduced ELF")
    if sha256(ROOT / "Cargo.lock") != evidence["cargo_lock_sha256"]:
        raise SystemExit("Cargo.lock differs from the verified build")
    epoch = int(git("show", "-s", "--format=%ct", "HEAD"))
    name = f"lmyzmail-0.1.0-rc.{commit[:8]}"
    arguments.output.mkdir(parents=True, exist_ok=False)
    runtime = arguments.output / f"{name}-linux-x86_64.tar.gz"
    source = arguments.output / f"{name}-source.tar.gz"
    bundle = arguments.output / f"{name}-history.bundle"
    manifest = {
        "schema_version": 1,
        "name": name,
        "status": "release-candidate",
        "production_acceptance": "See docs/acceptance-status.md; packaging does not satisfy pending gates.",
        "source_commit": commit,
        "source_date_epoch": epoch,
        "target": "x86_64-unknown-linux-gnu",
        "rust_toolchain": "1.94.0",
        "binary": evidence["artifact"],
        "cargo_lock_sha256": evidence["cargo_lock_sha256"],
        "model": json.loads((ROOT / "models/skibidi-inferx-compact-20261022/SOURCE.json").read_text()),
        "runtime_dependencies": evidence["verification"]["needed_dynamic_libraries"],
        "java_runtime_required": False,
    }
    payload = (json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    files = {
        "bin/lmyzmail": arguments.binary,
        "evidence/build/release-reproducibility-v1.json": arguments.evidence,
    }
    for relative in (
        "README.md", "SECURITY.md", "docs/acceptance-status.md", "docs/release.md",
        "docs/skibidi-inferx-contract.md", "docs/compatibility.md", "docs/architecture.md",
        "docs/maildir-takeover.md",
        "tools/install-lmyzmail.sh", "tools/uninstall-lmyzmail.sh",
        "config/lmyzmail.properties.example", "deploy/lmyzmail.service",
        "models/skibidi-inferx-compact-20261022/SOURCE.json",
        "models/skibidi-inferx-compact-20261022/skibidi_ai.safetensors",
        "models/skibidi-inferx-compact-20261022/tokenizer.json",
        "crates/lmyzmail/assets/skibidi_toilet_episode_1.mp4",
    ):
        files[relative] = ROOT / relative
    with runtime.open("xb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=epoch) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|") as archive:
            for relative, path in sorted(files.items()):
                if path.is_symlink() or not path.is_file():
                    raise SystemExit(f"packaged input must be a regular file: {path}")
                entry = archive.gettarinfo(str(path), arcname=f"{name}/{relative}")
                entry.uid = entry.gid = 0
                entry.uname = entry.gname = ""
                entry.mtime = epoch
                entry.mode = 0o755 if relative == "bin/lmyzmail" or relative.endswith(".sh") else 0o644
                with path.open("rb") as stream:
                    archive.addfile(entry, stream)
            entry = tarfile.TarInfo(f"{name}/RELEASE.json")
            entry.size, entry.mtime, entry.mode = len(payload), epoch, 0o644
            archive.addfile(entry, io.BytesIO(payload))
    with source.open("xb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=epoch) as compressed:
        with subprocess.Popen(["git", "-C", str(ROOT), "archive", "--format=tar",
                               f"--prefix={name}-source/", commit], stdout=subprocess.PIPE) as process:
            assert process.stdout is not None
            shutil.copyfileobj(process.stdout, compressed, length=1024 * 1024)
            if process.wait() != 0:
                raise SystemExit("source archive failed")
    subprocess.run(["git", "-C", str(ROOT), "bundle", "create", str(bundle.resolve()), "--all"], check=True)
    subprocess.run(["git", "-C", str(ROOT), "bundle", "verify", str(bundle.resolve())], check=True)
    (arguments.output / "RELEASE.json").write_bytes(payload)
    (arguments.output / "SHA256SUMS").write_text("".join(
        f"{sha256(path)}  {path.name}\n" for path in (runtime, source, bundle, arguments.output / "RELEASE.json")
    ), encoding="ascii")
    print(arguments.output.resolve())


if __name__ == "__main__":
    main()
