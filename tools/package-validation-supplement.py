#!/usr/bin/env python3
"""Export a separately identified complete validation-source/history supplement."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from importlib.util import module_from_spec, spec_from_file_location


ROOT = Path(__file__).resolve().parents[1]
PRODUCT_PATHS = (
    "crates", "native", "vendor", "models", "Cargo.toml", "Cargo.lock",
    "rust-toolchain.toml", ".cargo", "config", "deploy",
    "tools/install-lmyzmail.sh", "tools/uninstall-lmyzmail.sh",
)


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(["git", "-C", str(ROOT), *args], text=True).strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    args = parser.parse_args()
    package = args.package.resolve(strict=True)
    if not package.is_dir():
        raise ValueError("package must be a directory")
    spec = spec_from_file_location("release_package_verifier", ROOT / "tools/verify-release-package.py")
    assert spec is not None and spec.loader is not None
    verifier = module_from_spec(spec)
    spec.loader.exec_module(verifier)
    original = verifier.verify(ROOT, package)
    release = original["source_commit"]
    validation = git("rev-parse", "HEAD")
    if git("diff", "HEAD", "--name-only") or git("diff", "--cached", "--name-only"):
        raise ValueError("commit the validation source before exporting")
    if git("diff", "--name-only", release, validation, "--", *PRODUCT_PATHS):
        raise ValueError("product differs from the packaged release; build a new release")

    stem = f"lmyzmail-{release[:8]}-validation-{validation[:8]}"
    names = [f"{stem}-source.tar.gz", f"{stem}-history.bundle", "VALIDATION.json",
             "README.zh-CN.md", "VALIDATION.md", "REPRODUCIBILITY.json", "VALIDATION-SHA256SUMS"]
    if any((package / name).exists() for name in names):
        raise ValueError("validation supplement already exists; refusing to overwrite")
    source = package / names[0]
    with source.open("xb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
            with subprocess.Popen(["git", "-C", str(ROOT), "archive", "--format=tar",
                                   f"--prefix={stem}-source/", validation], stdout=subprocess.PIPE) as process:
                assert process.stdout is not None
                shutil.copyfileobj(process.stdout, compressed, 1024 * 1024)
                if process.wait() != 0:
                    raise ValueError("complete validation source export failed")
    with subprocess.Popen(["git", "-C", str(ROOT), "archive", "--format=tar",
                           f"--prefix={stem}-source/", validation], stdout=subprocess.PIPE) as process:
        assert process.stdout is not None
        expected = hashlib.file_digest(process.stdout, "sha256").hexdigest()
        if process.wait() != 0:
            raise ValueError("validation source stream could not be verified")
    with gzip.open(source, "rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
            raise ValueError("complete validation source archive differs from Git")
    bundle = package / names[1]
    subprocess.run(["git", "-C", str(ROOT), "bundle", "create", str(bundle), "--all"], check=True)
    subprocess.run(["git", "-C", str(ROOT), "bundle", "verify", str(bundle)], check=True)
    refs = subprocess.check_output(["git", "bundle", "list-heads", str(bundle)], text=True)
    if validation not in refs:
        raise ValueError("validation commit is absent from the bundle refs")
    copies = {
        "docs/release-22dae7d0-README.zh-CN.md": "README.zh-CN.md",
        "docs/release-22dae7d0-validation.md": "VALIDATION.md",
        "evidence/build/release-reproducibility-22dae7d0.json": "REPRODUCIBILITY.json",
    }
    for relative, filename in copies.items():
        subprocess.run(["git", "-C", str(ROOT), "diff", "--exit-code", "HEAD", "--", relative], check=True)
        with (ROOT / relative).open("rb") as input_file, (package / filename).open("xb") as output_file:
            shutil.copyfileobj(input_file, output_file)
    value = {
        "schema_version": 1, "status": "release-candidate-validation-supplement",
        "runtime_source_commit": release, "validation_source_commit": validation,
        "runtime_sha256": original["binary_sha256"],
        "unchanged_product_paths": list(PRODUCT_PATHS),
        "complete_source_archive": source.name, "exact_git_archive_sha256": expected,
        "complete_history_bundle": bundle.name,
        "source_tracked_paths": len(git("ls-tree", "-r", "--name-only", validation).splitlines()),
        "production_goal_complete": False,
        "acceptance_status": "docs/acceptance-status.md in the validation source archive",
    }
    with (package / "VALIDATION.json").open("x", encoding="utf-8") as output:
        output.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
    with (package / "VALIDATION-SHA256SUMS").open("x", encoding="ascii") as output:
        for name in names[:-1]:
            output.write(f"{sha256(package / name)}  {name}\n")
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
