#!/usr/bin/env python3
"""Verify release checksums, complete source stream, Git history and packaged ELF."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import subprocess
import tarfile
from pathlib import Path


def digest(stream):
    return hashlib.file_digest(stream, "sha256").hexdigest()


def verify(repository: Path, package: Path):
    manifest = json.loads((package / "RELEASE.json").read_text())
    commit = manifest["source_commit"]
    if len(commit) != 40 or any(char not in "0123456789abcdef" for char in commit):
        raise ValueError("invalid release source commit")
    name = manifest["name"]
    if name != f"lmyzmail-0.1.0-rc.{commit[:8]}":
        raise ValueError("release name does not identify its source commit")
    checked = []
    for line in (package / "SHA256SUMS").read_text().splitlines():
        expected, filename = line.split("  ", 1)
        if Path(filename).name != filename:
            raise ValueError("checksum target must be a plain filename")
        with (package / filename).open("rb") as source:
            if digest(source) != expected:
                raise ValueError(f"package checksum mismatch: {filename}")
        checked.append(filename)
    required = {f"{name}-linux-x86_64.tar.gz", f"{name}-source.tar.gz",
                f"{name}-history.bundle", "RELEASE.json"}
    if set(checked) != required:
        raise ValueError("package checksum inventory is incomplete")
    with subprocess.Popen(["git", "-C", str(repository), "archive", "--format=tar",
                           f"--prefix={name}-source/", commit], stdout=subprocess.PIPE) as process:
        expected_source = digest(process.stdout)
        if process.wait() != 0:
            raise ValueError("source commit cannot be archived")
    with gzip.open(package / f"{name}-source.tar.gz", "rb") as source:
        if digest(source) != expected_source:
            raise ValueError("source archive differs from complete tracked commit")
    tree = subprocess.check_output(["git", "-C", str(repository), "ls-tree",
                                    "-r", "--name-only", "-z", commit])
    paths = set(tree.rstrip(b"\0").decode().split("\0"))
    with tarfile.open(package / f"{name}-source.tar.gz", "r:gz") as archive:
        archived = {member.name.removeprefix(f"{name}-source/")
                    for member in archive if not member.isdir()}
    if archived != paths:
        raise ValueError("source archive does not contain all tracked paths")
    with tarfile.open(package / f"{name}-linux-x86_64.tar.gz", "r:gz") as archive:
        member = archive.getmember(f"{name}/bin/lmyzmail")
        if not member.isfile() or member.mode != 0o755:
            raise ValueError("packaged ELF is not an executable regular file")
        with archive.extractfile(member) as source:
            binary_sha256 = digest(source)
        if binary_sha256 != manifest["binary"]["sha256"]:
            raise ValueError("packaged ELF differs from release manifest")
    bundle = package / f"{name}-history.bundle"
    subprocess.run(["git", "-C", str(repository), "bundle", "verify", str(bundle)], check=True)
    refs = subprocess.check_output(["git", "bundle", "list-heads", str(bundle)], text=True)
    if commit not in refs:
        raise ValueError("bundle does not retain the release source commit")
    return {"status": "passed", "source_commit": commit,
            "tracked_source_paths": len(paths), "exact_git_archive_sha256": expected_source,
            "binary_sha256": binary_sha256, "package_checksums": len(checked),
            "complete_history_bundle": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = verify(args.repository.resolve(strict=True), args.package.resolve(strict=True))
    payload = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as output:
            output.write(payload)
    print(payload, end="")


if __name__ == "__main__":
    main()
