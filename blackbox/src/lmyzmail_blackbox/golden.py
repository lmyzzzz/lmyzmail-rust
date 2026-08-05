from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import GoldenMismatch, HarnessError
from .snapshots import bytes_snapshot

_ATTESTED_INPUTS = (
    "blackbox/pyproject.toml",
    "blackbox/requirements.lock",
    "blackbox/python-installed.lock",
    "blackbox/runtime-packages.lock",
    "blackbox/runtime-extracted.sha256",
    "blackbox/runtime-extracted-links.lock",
    "blackbox/runtime-extracted-modes.lock",
    "blackbox/manifests/playwright-files.sha256",
    "blackbox/manifests/playwright-links.lock",
    "blackbox/manifests/playwright-modes.lock",
)

_DEFINITION_ROOTS = (
    "blackbox/bin",
    "blackbox/src",
    "blackbox/tests",
    "blackbox/manifests",
    "blackbox/fixtures",
)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _sha256_definition_tree(repository: Path) -> str:
    digest = hashlib.sha256()
    files: list[Path] = []
    for relative_root in _DEFINITION_ROOTS:
        root = repository / relative_root
        if not root.exists():
            continue
        if root.is_symlink() or not root.is_dir():
            raise HarnessError(f"invalid harness definition root: {root}")
        for path in root.rglob("*"):
            if path.is_symlink():
                raise HarnessError(f"symlink is not allowed in harness definitions: {path}")
            if path.is_file() and "__pycache__" not in path.parts:
                files.append(path)
    for path in sorted(files):
        relative = path.relative_to(repository).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        with path.open("rb") as stream:
            file_digest = hashlib.file_digest(stream, "sha256").digest()
        digest.update(file_digest)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class GoldenAttestation:
    oracle_commit: str
    oracle_jar_sha256: str
    input_sha256: tuple[tuple[str, str], ...]
    harness_definition_sha256: str
    profile: str
    normalizers: tuple[str, ...]

    @classmethod
    def from_repository(
        cls,
        repository: Path,
        *,
        profile: str,
        normalizers: tuple[str, ...],
    ) -> GoldenAttestation:
        manifest_path = repository / "evidence/freeze/java-oracle/baseline.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        try:
            commit = str(manifest["commit"])
            jar_sha256 = str(manifest["oracle_jar"]["selected_sha256"])
        except (KeyError, TypeError) as error:
            raise HarnessError(f"invalid Java freeze manifest: {manifest_path}") from error
        input_hashes: list[tuple[str, str]] = []
        for relative_path in _ATTESTED_INPUTS:
            path = repository / relative_path
            if path.is_symlink() or not path.is_file():
                raise HarnessError(f"attested harness input is missing or symlinked: {path}")
            input_hashes.append((relative_path, _sha256_file(path)))
        return cls(
            oracle_commit=commit,
            oracle_jar_sha256=jar_sha256,
            input_sha256=tuple(input_hashes),
            harness_definition_sha256=_sha256_definition_tree(repository),
            profile=profile,
            normalizers=normalizers,
        )

    def as_json(self) -> dict[str, Any]:
        return {
            "oracle": {
                "commit": self.oracle_commit,
                "jar_sha256": self.oracle_jar_sha256,
            },
            "harness": {
                "definition_tree_sha256": self.harness_definition_sha256,
                "input_sha256": dict(self.input_sha256),
            },
            "profile": self.profile,
            "normalizers": list(self.normalizers),
        }


@dataclass(frozen=True, slots=True)
class GoldenStore:
    root: Path
    attestation: GoldenAttestation
    record: bool = False

    def _resolve(self, relative_path: str) -> Path:
        path = (self.root / relative_path).resolve()
        root = self.root.resolve()
        if root not in path.parents:
            raise ValueError("golden path escaped the configured root")
        return path

    @staticmethod
    def _write_exclusive(path: Path, value: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                return
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory_fd = os.open(path.parent, directory_flags)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)

    def _envelope(self, observation: Any) -> bytes:
        return canonical_json(
            {
                "schema_version": 2,
                "attestation": self.attestation.as_json(),
                "observation": observation,
            }
        )

    def assert_observation(self, relative_path: str, observation: Any) -> None:
        path = self._resolve(relative_path)
        actual = self._envelope(observation)
        if not path.exists():
            if not self.record:
                raise GoldenMismatch(
                    f"missing golden {relative_path}; "
                    "an attested Java recording session is required"
                )
            self._write_exclusive(path, actual)
        expected = path.read_bytes()
        if expected != actual:
            raise GoldenMismatch(
                f"golden mismatch for {relative_path}: expected sha256="
                f"{hashlib.sha256(expected).hexdigest()}, actual sha256="
                f"{hashlib.sha256(actual).hexdigest()}"
            )

    def assert_artifact(self, relative_path: str, value: bytes) -> None:
        path = self._resolve(relative_path)
        if not path.exists():
            if not self.record:
                raise GoldenMismatch(
                    f"missing golden artifact {relative_path}; "
                    "an attested Java recording session is required"
                )
            self._write_exclusive(path, value)
        expected = path.read_bytes()
        if expected != value:
            raise GoldenMismatch(
                f"golden artifact mismatch for {relative_path}: expected sha256="
                f"{hashlib.sha256(expected).hexdigest()}, actual sha256="
                f"{hashlib.sha256(value).hexdigest()}"
            )
        self.assert_observation(f"{relative_path}.golden.json", bytes_snapshot(value))
