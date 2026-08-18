#!/usr/bin/env python3
"""Qualified renderer SIMD benchmark and evidence publisher."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import math
import os
import pathlib
import platform
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - the formal runner is Linux-only.
    fcntl = None  # type: ignore[assignment]


SCHEMA = "lmyzmail.renderer-simd-evidence.v2"
PROBE_SCHEMA = "lmyzmail.renderer-simd-unsupported-probe.v1"
BENCHMARK_SCHEMA = "lmyzmail.renderer-simd-benchmark.v1"
BACKENDS = ("scalar", "avx2+fma", "avx512f")
DITHERS = (0, 1, 2)
SIZES = (64, 128, 256, 512)
FRAME_INDEX = 0
CONTRAST = 1.2
FORMAL_WARMUP = 5
FORMAL_ITERATIONS = 30
FORMAL_ROUNDS = 6
SMOKE_WARMUP = 1
SMOKE_ITERATIONS = 3
SMOKE_ROUNDS = 1
MAX_CASE_SLOWDOWN = 1.00
MAX_CASE_P95_SLOWDOWN = 1.00
MIN_FAMILY_SPEEDUP = 1.00
MIN_OVERALL_SPEEDUP = {"avx2+fma": 1.10, "avx512f": 1.15}
MIN_PALETTE_SPEEDUP = {"avx2+fma": 1.20, "avx512f": 1.35}
PALETTE_STAGES = frozenset(("block_palette_rgb", "map_palette", "block_states"))
STAGES = ("resize", "contrast", "block_palette_rgb", "map_palette", "block_states")
BLOCK_STATES_LIMIT = 4096
FRAME_WIDTH = 1920
FRAME_HEIGHT = 1080
TIMING_UNIT = "nanoseconds"
P95_METHOD = "nearest-rank"
MAX_JSON_BYTES = 64 * 1024 * 1024
EVIDENCE_LOCK_PATH = pathlib.Path("/tmp/lmyzmail-renderer-evidence.lock")
SOURCE_PATHS = (
    ".cargo",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain",
    "rust-toolchain.toml",
    "crates",
    "evidence/performance/run-renderer-simd-v1.sh",
    "evidence/performance/renderer_simd_runner_v2.py",
    "evidence/performance/run-renderer-e2e-matrix-v1.py",
    "evidence/performance/test_run_renderer_simd_launcher_v1.py",
    "blackbox/tools/test_minecraft_video.py",
    "blackbox/tools/test_minecraft_mail_view.py",
    "blackbox/golden/java/managed-minecraft-video-v12",
    "blackbox/golden/java/managed-minecraft-mail-view-v13",
)


class RunnerError(RuntimeError):
    pass


def reject_json_constant(value: str) -> None:
    raise RunnerError(f"non-finite JSON number is forbidden: {value}")


def reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RunnerError(f"duplicate JSON object key is forbidden: {key}")
        result[key] = value
    return result


def strict_json_bytes(value: bytes, *, label: str) -> Any:
    if not value or len(value) > MAX_JSON_BYTES:
        raise RunnerError(f"{label}: JSON size is empty or exceeds {MAX_JSON_BYTES} bytes")
    try:
        return json.loads(
            value.decode("utf-8"),
            parse_constant=reject_json_constant,
            object_pairs_hook=reject_duplicate_json_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RunnerError(f"{label}: invalid strict UTF-8 JSON: {error}") from error


def strict_json_file(path: pathlib.Path, *, label: str) -> Any:
    with path.open("rb") as source:
        value = source.read(MAX_JSON_BYTES + 1)
    return strict_json_bytes(value, label=label)


def require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise RunnerError(f"{label}: expected object")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise RunnerError(f"{label}: expected array")
    return value


def require_string(value: Any, label: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        raise RunnerError(f"{label}: expected {'non-empty ' if nonempty else ''}string")
    return value


def require_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise RunnerError(f"{label}: expected boolean")
    return value


def require_int(value: Any, label: str, *, positive: bool = False) -> int:
    if type(value) is not int:
        raise RunnerError(f"{label}: expected integer (booleans are forbidden)")
    if positive and value <= 0:
        raise RunnerError(f"{label}: expected positive integer")
    return value


def require_number(value: Any, label: str, *, positive: bool = False) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise RunnerError(f"{label}: expected finite number (booleans are forbidden)")
    result = float(value)
    if positive and result <= 0:
        raise RunnerError(f"{label}: expected positive number")
    return result


def require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise RunnerError(
            f"{label}: object fields changed; missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )


def require_sha256(value: Any, label: str) -> str:
    digest = require_string(value, label)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise RunnerError(f"{label}: expected lowercase SHA-256")
    return digest


def repository_file_path(
    repository: pathlib.Path, relative: str, *, label: str
) -> pathlib.Path:
    value = pathlib.PurePosixPath(relative)
    if (
        value.is_absolute()
        or not value.parts
        or any(part in ("", ".", "..") for part in value.parts)
        or value.as_posix() != relative
    ):
        raise RunnerError(f"{label}: expected canonical repository-relative path")
    return repository.joinpath(*value.parts)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = read_fd_at(descriptor, 1024 * 1024, offset)
        if not chunk:
            return digest.hexdigest()
        digest.update(chunk)
        offset += len(chunk)


def read_fd_at(descriptor: int, size: int, offset: int) -> bytes:
    pread = getattr(os, "pread", None)
    if pread is not None:
        return pread(descriptor, size, offset)
    original = os.lseek(descriptor, 0, os.SEEK_CUR)
    try:
        os.lseek(descriptor, offset, os.SEEK_SET)
        return os.read(descriptor, size)
    finally:
        os.lseek(descriptor, original, os.SEEK_SET)


class PinnedFile:
    def __init__(self, path: pathlib.Path, *, label: str, executable: bool = False) -> None:
        self.path = path.absolute()
        self.label = label
        self.descriptor = -1
        if self.path.is_symlink():
            raise RunnerError(f"{label}: symbolic links are forbidden: {self.path}")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise RunnerError(f"{label}: expected a regular file: {self.path}")
            if executable and not os.access(self.path, os.X_OK):
                raise RunnerError(f"{label}: file is not executable: {self.path}")
            path_metadata = os.stat(self.path, follow_symlinks=False)
            if (path_metadata.st_dev, path_metadata.st_ino) != (
                metadata.st_dev,
                metadata.st_ino,
            ):
                raise RunnerError(f"{label}: path changed while it was being pinned")
            self.descriptor = descriptor
            descriptor = -1
            self.identity = {
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "size": metadata.st_size,
                "mtime_ns": metadata.st_mtime_ns,
                "ctime_ns": metadata.st_ctime_ns,
            }
            self.sha256 = sha256_fd(self.descriptor)
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def read_bytes(self, *, maximum: int = MAX_JSON_BYTES) -> bytes:
        if self.identity["size"] > maximum:
            raise RunnerError(f"{self.label}: pinned file exceeds {maximum} bytes")
        value = bytearray()
        offset = 0
        while len(value) <= maximum:
            chunk = read_fd_at(
                self.descriptor,
                min(1024 * 1024, maximum + 1 - len(value)),
                offset,
            )
            if not chunk:
                return bytes(value)
            value.extend(chunk)
            offset += len(chunk)
        raise RunnerError(f"{self.label}: pinned file exceeds {maximum} bytes")

    def verify(self, label: str) -> dict[str, Any]:
        metadata = os.fstat(self.descriptor)
        current_identity = {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "size": metadata.st_size,
            "mtime_ns": metadata.st_mtime_ns,
            "ctime_ns": metadata.st_ctime_ns,
        }
        if current_identity != self.identity or sha256_fd(self.descriptor) != self.sha256:
            raise RunnerError(f"{label}: pinned {self.label} object changed")
        try:
            path_metadata = os.stat(self.path, follow_symlinks=False)
        except FileNotFoundError as error:
            raise RunnerError(f"{label}: pinned {self.label} path disappeared") from error
        if not stat.S_ISREG(path_metadata.st_mode) or (
            path_metadata.st_dev,
            path_metadata.st_ino,
        ) != (metadata.st_dev, metadata.st_ino):
            raise RunnerError(f"{label}: pinned {self.label} path was replaced")
        return {"label": label, **self.identity, "sha256": self.sha256}

    def proc_path(self) -> str:
        if platform.system() != "Linux":
            raise RunnerError(f"{self.label}: pinned descriptor execution requires Linux")
        return f"/proc/self/fd/{self.descriptor}"

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def __enter__(self) -> PinnedFile:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __del__(self) -> None:
        with contextlib.suppress(OSError):
            self.close()


class EvidenceLock:
    def __init__(self, descriptor: int) -> None:
        self.descriptor = descriptor

    @classmethod
    def acquire(cls) -> EvidenceLock:
        if fcntl is None:
            raise RunnerError("workspace evidence locking requires Linux fcntl")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(EVIDENCE_LOCK_PATH, flags, 0o600)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise RunnerError("workspace evidence lock is not a regular file")
            if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
                raise RunnerError("workspace evidence lock has unsafe ownership or mode")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise RunnerError("another renderer evidence run holds the workspace lock") from error
            return cls(descriptor)
        except BaseException:
            os.close(descriptor)
            raise

    def close(self) -> None:
        if self.descriptor >= 0:
            if fcntl is not None:
                fcntl.flock(self.descriptor, fcntl.LOCK_UN)
            os.close(self.descriptor)
            self.descriptor = -1

    def __del__(self) -> None:
        with contextlib.suppress(OSError):
            self.close()


def git_bytes(repository: pathlib.Path, *arguments: str) -> bytes:
    return subprocess.check_output(
        ("git", *arguments), cwd=repository, stderr=subprocess.STDOUT
    )


def source_file_digest(path: pathlib.Path) -> str:
    if path.is_symlink():
        return sha256_bytes(b"symlink\0" + os.fsencode(os.readlink(path)))
    if not path.is_file():
        raise RunnerError(f"snapshot source is not a regular file: {path}")
    return sha256_file(path)


def source_snapshot(repository: pathlib.Path) -> dict[str, Any]:
    listed = git_bytes(
        repository,
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
        "--",
        *SOURCE_PATHS,
    )
    relative_paths = sorted(
        {os.fsdecode(value) for value in listed.split(b"\0") if value}
    )
    source_files = {
        relative: source_file_digest(repository / relative) for relative in relative_paths
    }
    digest = hashlib.sha256()
    for relative, file_digest in source_files.items():
        digest.update(os.fsencode(relative))
        digest.update(b"\0")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\0")
    status = git_bytes(
        repository, "status", "--porcelain=v1", "-z", "--untracked-files=all"
    )
    tracked_diff = git_bytes(repository, "diff", "--binary", "HEAD", "--")
    return {
        "head": git_bytes(repository, "rev-parse", "HEAD").decode("ascii").strip(),
        "status_porcelain_v1": [
            os.fsdecode(value) for value in status.split(b"\0") if value
        ],
        "status_sha256": sha256_bytes(status),
        "tracked_diff_sha256": sha256_bytes(tracked_diff),
        "cargo_lock_sha256": sha256_file(repository / "Cargo.lock"),
        "source_sha256": digest.hexdigest(),
        "source_files": source_files,
    }


def pin_source_snapshot(
    repository: pathlib.Path, frozen: Mapping[str, Any]
) -> dict[str, PinnedFile]:
    files = require_mapping(frozen.get("source_files"), "frozen source files")
    pinned: dict[str, PinnedFile] = {}
    try:
        for relative, expected_digest in sorted(files.items()):
            relative_path = require_string(relative, "frozen source relative path")
            expected = require_sha256(expected_digest, f"frozen source {relative_path}")
            item = PinnedFile(
                repository_file_path(
                    repository, relative_path, label=f"source {relative_path}"
                ),
                label=f"source {relative_path}",
            )
            if item.sha256 != expected:
                item.close()
                raise RunnerError(f"source changed while pinning: {relative_path}")
            pinned[relative_path] = item
        return pinned
    except BaseException:
        for item in pinned.values():
            item.close()
        raise


def verify_pinned_files(pinned: Mapping[str, PinnedFile], label: str) -> None:
    for relative, item in pinned.items():
        item.verify(f"{label}: {relative}")


def verify_attribution(
    repository: pathlib.Path,
    frozen: Mapping[str, Any],
    binary: pathlib.Path,
    binary_sha256: str,
    asset: pathlib.Path,
    asset_sha256: str,
    label: str,
    *,
    source_pins: Mapping[str, PinnedFile] | None = None,
    binary_pin: PinnedFile | None = None,
    asset_pin: PinnedFile | None = None,
) -> dict[str, Any]:
    if source_pins is not None:
        verify_pinned_files(source_pins, label)
    if binary_pin is not None:
        binary_pin.verify(label)
    if asset_pin is not None:
        asset_pin.verify(label)
    current = source_snapshot(repository)
    if current != dict(frozen):
        changed = sorted(
            key for key in set(current) | set(frozen) if current.get(key) != frozen.get(key)
        )
        raise RunnerError(f"{label}: frozen source/status/lock changed: {', '.join(changed)}")
    if sha256_file(binary) != binary_sha256:
        raise RunnerError(f"{label}: benchmark binary hash changed")
    if sha256_file(asset) != asset_sha256:
        raise RunnerError(f"{label}: benchmark input asset hash changed")
    return {
        "label": label,
        "verified_utc": dt.datetime.now(dt.UTC).isoformat(),
        "source_sha256": current["source_sha256"],
        "status_sha256": current["status_sha256"],
        "cargo_lock_sha256": current["cargo_lock_sha256"],
        "binary_sha256": binary_sha256,
        "asset_sha256": asset_sha256,
    }


def parse_allowed_cpus(specification: str) -> list[int]:
    values: list[int] = []
    for part in specification.split(","):
        if "-" in part:
            start, end = (int(value) for value in part.split("-", 1))
            values.extend(range(start, end + 1))
        else:
            values.append(int(part))
    if not values:
        raise RunnerError("CPU affinity set is empty")
    return values


def select_cpu(requested: int | None) -> tuple[int, str, str]:
    allowed_specification = ""
    for line in pathlib.Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        if line.startswith("Cpus_allowed_list:"):
            allowed_specification = line.partition(":")[2].strip()
            break
    if not allowed_specification:
        raise RunnerError("/proc/self/status did not expose Cpus_allowed_list")
    allowed = parse_allowed_cpus(allowed_specification)
    if requested is not None:
        if requested not in allowed:
            raise RunnerError(
                f"requested CPU {requested} is outside allowed set {allowed_specification}"
            )
        return requested, allowed_specification, "explicit"
    return allowed[-1], allowed_specification, "automatic-highest-allowed"


def text_probe(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = path.read_text(encoding="ascii", errors="replace").strip()
    except OSError as error:
        return {"status": "unavailable", "path": str(path), "reason": str(error)}
    if not value:
        return {"status": "unavailable", "path": str(path), "reason": "empty"}
    return {"status": "available", "path": str(path), "value": value}


def capture_telemetry(cpu: int, label: str) -> dict[str, Any]:
    cpu_root = pathlib.Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq")
    frequency = text_probe(cpu_root / "scaling_cur_freq")
    if frequency["status"] != "available":
        frequency = text_probe(cpu_root / "cpuinfo_cur_freq")
    temperatures: list[dict[str, Any]] = []
    for path in sorted(pathlib.Path("/sys/class/thermal").glob("thermal_zone*/temp")):
        probe = text_probe(path)
        if probe["status"] == "available":
            temperatures.append(probe)
    return {
        "label": label,
        "captured_utc": dt.datetime.now(dt.UTC).isoformat(),
        "cpu": cpu,
        "governor": text_probe(cpu_root / "scaling_governor"),
        "frequency": frequency,
        "temperatures": {
            "status": "available" if temperatures else "unavailable",
            "values": temperatures,
        },
    }


def command_output(repository: pathlib.Path, *arguments: str) -> str:
    return subprocess.check_output(
        arguments, cwd=repository, text=True, stderr=subprocess.STDOUT
    ).rstrip()


def atomic_publish(path: pathlib.Path, value: Mapping[str, Any]) -> None:
    path = path.absolute()
    if path.exists():
        raise RunnerError(f"refusing to overwrite existing evidence: {path}")
    if not path.parent.is_dir():
        raise RunnerError(f"evidence output directory is missing: {path.parent}")
    encoded = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode("utf-8") + b"\n"
    if os.name == "posix":
        for ancestor in (path.parent, *path.parent.parents):
            if ancestor.is_symlink():
                raise RunnerError(f"evidence output traverses a symbolic link: {ancestor}")
        directory = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        temporary_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
        descriptor = -1
        published = False
        try:
            directory_identity = os.fstat(directory)
            try:
                os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RunnerError(f"refusing to overwrite existing evidence: {path}")
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory,
            )
            with os.fdopen(descriptor, "wb", closefd=True) as destination:
                descriptor = -1
                destination.write(encoded)
                destination.flush()
                os.fsync(destination.fileno())
            current_parent = os.stat(path.parent, follow_symlinks=False)
            if (current_parent.st_dev, current_parent.st_ino) != (
                directory_identity.st_dev,
                directory_identity.st_ino,
            ):
                raise RunnerError("evidence output directory was replaced during publication")
            os.link(
                temporary_name,
                path.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
            published = True
            linked = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            temporary_metadata = os.stat(
                temporary_name, dir_fd=directory, follow_symlinks=False
            )
            if (linked.st_dev, linked.st_ino) != (
                temporary_metadata.st_dev,
                temporary_metadata.st_ino,
            ):
                raise RunnerError("evidence hard-link publication changed object identity")
            os.fsync(directory)
            os.unlink(temporary_name, dir_fd=directory)
            os.fsync(directory)
            final_parent = os.stat(path.parent, follow_symlinks=False)
            if (final_parent.st_dev, final_parent.st_ino) != (
                directory_identity.st_dev,
                directory_identity.st_ino,
            ):
                raise RunnerError("evidence output directory changed after publication")
            published = False
            return
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=directory)
            if published:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(path.name, dir_fd=directory)
                    os.fsync(directory)
            os.close(directory)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as destination:
            descriptor = -1
            destination.write(encoded)
            destination.flush()
            os.fsync(destination.fileno())
        os.link(temporary, path)
        temporary.unlink()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def integer_median(values: Iterable[int]) -> int:
    ordered = sorted(values)
    if not ordered:
        raise RunnerError("cannot summarize an empty timing group")
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return ordered[middle - 1] + (ordered[middle] - ordered[middle - 1]) // 2


def nearest_rank_p95(values: Iterable[int]) -> int:
    ordered = sorted(values)
    if not ordered:
        raise RunnerError("cannot summarize an empty P95 timing group")
    rank = (95 * len(ordered) + 99) // 100
    return ordered[rank - 1]


def verify_benchmark_report(
    value: Any,
    *,
    expected_backend: str,
    expected_dither: int,
    expected_input: str,
    expected_warmup: int,
    expected_iterations: int,
    require_timed: bool,
) -> dict[str, Any]:
    label = f"{expected_backend} dither={expected_dither}"
    report = require_mapping(value, label)
    require_exact_keys(
        report,
        {
            "schema",
            "status",
            "requested_backend",
            "resolved_backend",
            "fallback_used",
            "host_capabilities",
            "unsupported_reason",
            "input",
            "frame_index",
            "frame",
            "parameters",
            "sizes",
        },
        label,
    )
    if report["schema"] != BENCHMARK_SCHEMA:
        raise RunnerError(f"{label}: unexpected benchmark schema")
    if report["requested_backend"] != expected_backend:
        raise RunnerError(f"{label}: requested backend identity changed")
    if require_string(report["input"], f"{label}.input") != expected_input:
        raise RunnerError(f"{label}: benchmark input changed")
    if require_int(report["frame_index"], f"{label}.frame_index") != FRAME_INDEX:
        raise RunnerError(f"{label}: frame index changed")

    capabilities = require_mapping(report["host_capabilities"], f"{label}.host_capabilities")
    require_exact_keys(capabilities, {"avx2", "fma", "avx512f"}, f"{label}.host_capabilities")
    capability_values = {
        name: require_bool(capabilities[name], f"{label}.host_capabilities.{name}")
        for name in ("avx2", "fma", "avx512f")
    }

    parameters = require_mapping(report["parameters"], f"{label}.parameters")
    require_exact_keys(
        parameters,
        {"contrast", "dither", "warmup", "iterations", "timing_unit", "p95_method"},
        f"{label}.parameters",
    )
    if require_number(parameters["contrast"], f"{label}.parameters.contrast") != CONTRAST:
        raise RunnerError(f"{label}: contrast changed")
    if require_int(parameters["dither"], f"{label}.parameters.dither") != expected_dither:
        raise RunnerError(f"{label}: dither identity changed")
    if require_int(parameters["warmup"], f"{label}.parameters.warmup", positive=True) != expected_warmup:
        raise RunnerError(f"{label}: warmup count changed")
    if (
        require_int(parameters["iterations"], f"{label}.parameters.iterations", positive=True)
        != expected_iterations
    ):
        raise RunnerError(f"{label}: iteration count changed")
    if parameters["timing_unit"] != TIMING_UNIT or parameters["p95_method"] != P95_METHOD:
        raise RunnerError(f"{label}: timing metadata changed")

    status_value = require_string(report["status"], f"{label}.status")
    fallback = require_bool(report["fallback_used"], f"{label}.fallback_used")
    resolved = require_string(report["resolved_backend"], f"{label}.resolved_backend")
    sizes = require_list(report["sizes"], f"{label}.sizes")
    if status_value == "unsupported":
        if require_timed:
            raise RunnerError(f"{label}: formal report did not truly execute the backend")
        if not fallback or resolved == expected_backend:
            raise RunnerError(f"{label}: unsupported report did not record a real fallback")
        require_string(report["unsupported_reason"], f"{label}.unsupported_reason")
        if report["frame"] is not None or sizes:
            raise RunnerError(f"{label}: unsupported report contains timed output")
        return {
            "status": "unsupported",
            "resolved_backend": resolved,
            "capabilities": capability_values,
            "hashes": {},
            "timings": [],
        }
    if status_value != "ok":
        raise RunnerError(f"{label}: invalid report status")
    if fallback or resolved != expected_backend or report["unsupported_reason"] is not None:
        raise RunnerError(f"{label}: timed a fallback or claimed an unsupported reason")
    if expected_backend == "avx2+fma" and not (
        capability_values["avx2"] and capability_values["fma"]
    ):
        raise RunnerError(f"{label}: host capability report cannot execute AVX2+FMA")
    if expected_backend == "avx512f" and not capability_values["avx512f"]:
        raise RunnerError(f"{label}: host capability report cannot execute AVX-512F")

    frame = require_mapping(report["frame"], f"{label}.frame")
    require_exact_keys(frame, {"width", "height", "rgb24_sha256"}, f"{label}.frame")
    if require_int(frame["width"], f"{label}.frame.width", positive=True) != FRAME_WIDTH:
        raise RunnerError(f"{label}: decoded frame width changed")
    if require_int(frame["height"], f"{label}.frame.height", positive=True) != FRAME_HEIGHT:
        raise RunnerError(f"{label}: decoded frame height changed")
    hashes = {"frame:rgb24": require_sha256(frame["rgb24_sha256"], f"{label}.frame.sha256")}
    if len(sizes) != len(SIZES):
        raise RunnerError(f"{label}: output size matrix changed")

    timings: list[dict[str, Any]] = []
    for index, expected_edge in enumerate(SIZES):
        size_label = f"{label}.sizes[{index}]"
        size = require_mapping(sizes[index], size_label)
        require_exact_keys(size, {"edge", "pixels", "stages"}, size_label)
        edge = require_int(size["edge"], f"{size_label}.edge", positive=True)
        pixels = require_int(size["pixels"], f"{size_label}.pixels", positive=True)
        if edge != expected_edge or pixels != expected_edge * expected_edge:
            raise RunnerError(f"{size_label}: edge or pixel count changed")
        stages = require_list(size["stages"], f"{size_label}.stages")
        if len(stages) != len(STAGES):
            raise RunnerError(f"{size_label}: stage set changed")
        for stage_index, expected_stage in enumerate(STAGES):
            stage_label = f"{size_label}.stages[{stage_index}]"
            stage = require_mapping(stages[stage_index], stage_label)
            if stage.get("stage") != expected_stage:
                raise RunnerError(f"{stage_label}: stage order or identity changed")
            key = f"{edge}:{expected_stage}"
            if expected_stage == "block_states" and pixels > BLOCK_STATES_LIMIT:
                require_exact_keys(stage, {"stage", "status", "reason"}, stage_label)
                if stage["status"] != "not_applicable" or stage["reason"] != (
                    "pixel count exceeds MAX_BLOCK_PIXELS=4096; production does not chunk block frames"
                ):
                    raise RunnerError(f"{stage_label}: invalid not-applicable block stage")
                continue
            require_exact_keys(
                stage,
                {
                    "stage",
                    "status",
                    "output_sha256",
                    "measured_output_hash_validation",
                    "measured_iterations_hashed",
                    "median_ns",
                    "p95_ns",
                    "samples_ns",
                },
                stage_label,
            )
            if stage["status"] != "timed":
                raise RunnerError(f"{stage_label}: expected timed stage")
            output_hash = require_sha256(stage["output_sha256"], f"{stage_label}.output_sha256")
            if stage["measured_output_hash_validation"] != "passed":
                raise RunnerError(f"{stage_label}: measured output hash validation failed")
            if (
                require_int(
                    stage["measured_iterations_hashed"],
                    f"{stage_label}.measured_iterations_hashed",
                    positive=True,
                )
                != expected_iterations
            ):
                raise RunnerError(f"{stage_label}: not every measured iteration was hashed")
            samples_value = require_list(stage["samples_ns"], f"{stage_label}.samples_ns")
            if len(samples_value) != expected_iterations:
                raise RunnerError(f"{stage_label}: timing sample count changed")
            samples = [
                require_int(sample, f"{stage_label}.samples_ns[{sample_index}]", positive=True)
                for sample_index, sample in enumerate(samples_value)
            ]
            median = require_int(stage["median_ns"], f"{stage_label}.median_ns", positive=True)
            p95 = require_int(stage["p95_ns"], f"{stage_label}.p95_ns", positive=True)
            if median != integer_median(samples) or p95 != nearest_rank_p95(samples):
                raise RunnerError(f"{stage_label}: median/P95 does not match raw samples")
            hashes[key] = output_hash
            timings.append(
                {
                    "edge": edge,
                    "stage": expected_stage,
                    "median_ns": median,
                    "p95_ns": p95,
                }
            )
    return {
        "status": "ok",
        "resolved_backend": resolved,
        "capabilities": capability_values,
        "hashes": hashes,
        "timings": timings,
    }


def output_hashes(report: Mapping[str, Any]) -> dict[str, str]:
    frame = report.get("frame")
    if not isinstance(frame, dict):
        raise RunnerError("timed report has no decoded frame")
    hashes = {"frame:rgb24": frame["rgb24_sha256"]}
    measured_iterations = report["parameters"]["iterations"]
    for size in report["sizes"]:
        edge = size["edge"]
        for stage in size["stages"]:
            key = f"{edge}:{stage['stage']}"
            if stage["status"] == "timed":
                output_hash = stage.get("output_sha256")
                if (
                    not isinstance(output_hash, str)
                    or len(output_hash) != 64
                    or any(character not in "0123456789abcdef" for character in output_hash)
                ):
                    raise RunnerError(f"{key}: invalid output SHA-256")
                if stage.get("measured_output_hash_validation") != "passed":
                    raise RunnerError(f"{key}: measured iteration hash gate did not pass")
                if stage.get("measured_iterations_hashed") != measured_iterations:
                    raise RunnerError(f"{key}: not every measured iteration was hashed")
                if len(stage.get("samples_ns", [])) != measured_iterations:
                    raise RunnerError(f"{key}: timing sample count changed")
                hashes[key] = output_hash
            elif not (
                stage["stage"] == "block_states"
                and size["pixels"] > 4096
                and stage["status"] == "not_applicable"
            ):
                raise RunnerError(f"{key}: unexpected untimed stage")
    return hashes


def aggregate_medians(
    records: list[dict[str, Any]], reports: list[dict[str, Any]], round_count: int
) -> list[dict[str, Any]]:
    groups: dict[tuple[str, int, int, str], list[tuple[int, int, int]]] = defaultdict(list)
    for record, report in zip(records, reports, strict=True):
        if report["status"] != "ok":
            continue
        backend = report["requested_backend"]
        dither = report["parameters"]["dither"]
        for size in report["sizes"]:
            for stage in size["stages"]:
                if stage["status"] == "timed":
                    groups[(backend, dither, size["edge"], stage["stage"])].append(
                        (record["round_index"], stage["median_ns"], stage["p95_ns"])
                    )
    aggregate: list[dict[str, Any]] = []
    for (backend, dither, edge, stage), round_values in sorted(groups.items()):
        round_values.sort()
        if len(round_values) != round_count:
            raise RunnerError(f"{backend} dither={dither} {edge}:{stage}: missing round")
        medians = [median for _, median, _ in round_values]
        p95_values = [p95 for _, _, p95 in round_values]
        aggregate.append(
            {
                "backend": backend,
                "dither": dither,
                "edge": edge,
                "stage": stage,
                "round_medians_ns": medians,
                "cross_round_median_ns": integer_median(medians),
                "round_p95_ns": p95_values,
                "cross_round_p95_ns": integer_median(p95_values),
            }
        )
    return aggregate


def geometric_mean(values: Iterable[float], label: str) -> float:
    items = list(values)
    if not items or any(not math.isfinite(value) or value <= 0 for value in items):
        raise RunnerError(f"{label}: geometric mean requires finite positive values")
    return math.exp(math.fsum(math.log(value) for value in items) / len(items))


def evaluate_performance(aggregate: list[dict[str, Any]]) -> dict[str, Any]:
    timings: dict[tuple[str, int, int, str], int] = {}
    p95_timings: dict[tuple[str, int, int, str], int] = {}
    for index, raw_row in enumerate(aggregate):
        row = require_mapping(raw_row, f"aggregate[{index}]")
        backend = require_string(row.get("backend"), f"aggregate[{index}].backend")
        dither = require_int(row.get("dither"), f"aggregate[{index}].dither")
        edge = require_int(row.get("edge"), f"aggregate[{index}].edge", positive=True)
        stage = require_string(row.get("stage"), f"aggregate[{index}].stage")
        if backend not in BACKENDS or dither not in DITHERS or edge not in SIZES or stage not in STAGES:
            raise RunnerError(f"aggregate[{index}]: unknown performance case identity")
        key = (backend, dither, edge, stage)
        if key in timings:
            raise RunnerError(f"aggregate[{index}]: duplicate performance case {key}")
        timings[key] = require_int(
            row.get("cross_round_median_ns"),
            f"aggregate[{index}].cross_round_median_ns",
            positive=True,
        )
        p95_timings[key] = require_int(
            row.get("cross_round_p95_ns"),
            f"aggregate[{index}].cross_round_p95_ns",
            positive=True,
        )
    scalar_keys = {
        key[1:] for key in timings if key[0] == "scalar" and (key[1] == 0 or key[3] == "map_palette")
    }
    if not scalar_keys:
        raise RunnerError("performance gate has no canonical measurements")
    backend_results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for backend in BACKENDS[1:]:
        cases: list[dict[str, Any]] = []
        family_speedups: dict[str, list[float]] = defaultdict(list)
        family_p95_speedups: dict[str, list[float]] = defaultdict(list)
        overall_speedups: list[float] = []
        overall_p95_speedups: list[float] = []
        palette_speedups: list[float] = []
        palette_p95_speedups: list[float] = []
        for dither, edge, stage in sorted(scalar_keys):
            scalar = timings[("scalar", dither, edge, stage)]
            candidate = timings.get((backend, dither, edge, stage))
            if candidate is None:
                raise RunnerError(f"performance gate is missing {backend} {dither}:{edge}:{stage}")
            speedup = scalar / candidate
            scalar_p95 = p95_timings[("scalar", dither, edge, stage)]
            candidate_p95 = p95_timings.get((backend, dither, edge, stage))
            if candidate_p95 is None:
                raise RunnerError(f"performance gate is missing P95 {backend} {dither}:{edge}:{stage}")
            p95_speedup = scalar_p95 / candidate_p95
            passed = (
                candidate <= scalar * MAX_CASE_SLOWDOWN
                and candidate_p95 <= scalar_p95 * MAX_CASE_P95_SLOWDOWN
            )
            case = {
                "dither": dither,
                "edge": edge,
                "stage": stage,
                "scalar_ns": scalar,
                "candidate_ns": candidate,
                "speedup": speedup,
                "minimum_speedup": 1.0 / MAX_CASE_SLOWDOWN,
                "scalar_p95_ns": scalar_p95,
                "candidate_p95_ns": candidate_p95,
                "p95_speedup": p95_speedup,
                "minimum_p95_speedup": 1.0 / MAX_CASE_P95_SLOWDOWN,
                "status": "passed" if passed else "failed",
            }
            cases.append(case)
            if not passed:
                failures.append({"backend": backend, "scope": "case", **case})
            family_speedups[stage].append(speedup)
            family_p95_speedups[stage].append(p95_speedup)
            overall_speedups.append(speedup)
            overall_p95_speedups.append(p95_speedup)
            if stage in PALETTE_STAGES:
                palette_speedups.append(speedup)
                palette_p95_speedups.append(p95_speedup)
        families = []
        for stage, speedups in sorted(family_speedups.items()):
            speedup = geometric_mean(speedups, f"{backend} {stage} median")
            p95_speedup = geometric_mean(
                family_p95_speedups[stage], f"{backend} {stage} P95"
            )
            passed = speedup >= MIN_FAMILY_SPEEDUP and p95_speedup >= MIN_FAMILY_SPEEDUP
            result = {
                "stage": stage,
                "speedup": speedup,
                "p95_speedup": p95_speedup,
                "minimum_speedup": MIN_FAMILY_SPEEDUP,
                "minimum_p95_speedup": MIN_FAMILY_SPEEDUP,
                "case_count": len(speedups),
                "weighting": "equal-weight-geometric-mean",
                "status": "passed" if passed else "failed",
            }
            families.append(result)
            if not passed:
                failures.append({"backend": backend, "scope": "family", **result})
        overall_speedup = geometric_mean(overall_speedups, f"{backend} overall median")
        overall_p95_speedup = geometric_mean(overall_p95_speedups, f"{backend} overall P95")
        palette_speedup = geometric_mean(palette_speedups, f"{backend} palette median")
        palette_p95_speedup = geometric_mean(
            palette_p95_speedups, f"{backend} palette P95"
        )
        overall_passed = (
            overall_speedup >= MIN_OVERALL_SPEEDUP[backend]
            and overall_p95_speedup >= MIN_OVERALL_SPEEDUP[backend]
        )
        palette_passed = (
            palette_speedup >= MIN_PALETTE_SPEEDUP[backend]
            and palette_p95_speedup >= MIN_PALETTE_SPEEDUP[backend]
        )
        if not overall_passed:
            failures.append(
                {
                    "backend": backend,
                    "scope": "overall",
                    "speedup": overall_speedup,
                    "p95_speedup": overall_p95_speedup,
                    "minimum_speedup": MIN_OVERALL_SPEEDUP[backend],
                }
            )
        if not palette_passed:
            failures.append(
                {
                    "backend": backend,
                    "scope": "palette",
                    "speedup": palette_speedup,
                    "p95_speedup": palette_p95_speedup,
                    "minimum_speedup": MIN_PALETTE_SPEEDUP[backend],
                }
            )
        backend_results.append(
            {
                "backend": backend,
                "cases": cases,
                "families": families,
                "overall": {
                    "speedup": overall_speedup,
                    "p95_speedup": overall_p95_speedup,
                    "minimum_speedup": MIN_OVERALL_SPEEDUP[backend],
                    "minimum_p95_speedup": MIN_OVERALL_SPEEDUP[backend],
                    "case_count": len(overall_speedups),
                    "weighting": "equal-weight-geometric-mean",
                    "status": "passed" if overall_passed else "failed",
                },
                "palette": {
                    "speedup": palette_speedup,
                    "p95_speedup": palette_p95_speedup,
                    "minimum_speedup": MIN_PALETTE_SPEEDUP[backend],
                    "minimum_p95_speedup": MIN_PALETTE_SPEEDUP[backend],
                    "case_count": len(palette_speedups),
                    "weighting": "equal-weight-geometric-mean",
                    "status": "passed" if palette_passed else "failed",
                },
            }
        )
    return {
        "status": "passed" if not failures else "failed",
        "rationale": {
            "case_max_slowdown": MAX_CASE_SLOWDOWN,
            "case_max_p95_slowdown": MAX_CASE_P95_SLOWDOWN,
            "family_minimum_speedup": MIN_FAMILY_SPEEDUP,
            "overall_minimum_speedup": MIN_OVERALL_SPEEDUP,
            "palette_minimum_speedup": MIN_PALETTE_SPEEDUP,
            "canonical_weighting": "dither=0 for shared stages plus map_palette at dithers 0,1,2",
            "aggregation": "equal-weight geometric mean of per-case normalized speedups",
            "p95_policy": "same family, overall, and palette speedup thresholds as median",
        },
        "backends": backend_results,
        "failures": failures,
    }


def validate_report_identity(
    report: Mapping[str, Any],
    expected_backend: str,
    expected_dither: int,
    expected_input: str,
    warmup: int,
    iterations: int,
    *,
    require_timed: bool,
) -> None:
    verify_benchmark_report(
        report,
        expected_backend=expected_backend,
        expected_dither=expected_dither,
        expected_input=expected_input,
        expected_warmup=warmup,
        expected_iterations=iterations,
        require_timed=require_timed,
    )


def verify_formal_evidence(value: Any) -> dict[str, Any]:
    evidence = require_mapping(value, "renderer evidence")
    if evidence.get("schema") != SCHEMA or evidence.get("profile") != "formal":
        raise RunnerError("renderer evidence is not the formal v2 schema")
    round_count = require_int(evidence.get("round_count"), "round_count", positive=True)
    if round_count != FORMAL_ROUNDS:
        raise RunnerError("renderer formal round count changed")
    formal = require_mapping(evidence.get("formal_contract"), "formal_contract")
    require_exact_keys(
        formal,
        {"input", "frame_index", "sizes", "contrast", "dithers", "warmup", "iterations", "rounds"},
        "formal_contract",
    )
    if formal["input"] != "crates/lmyzmail/assets/skibidi_toilet_episode_1.mp4":
        raise RunnerError("renderer formal input changed")
    if require_int(formal["frame_index"], "formal_contract.frame_index") != FRAME_INDEX:
        raise RunnerError("renderer formal frame index changed")
    if formal["sizes"] != list(SIZES) or any(type(item) is not int for item in formal["sizes"]):
        raise RunnerError("renderer formal sizes changed")
    if require_number(formal["contrast"], "formal_contract.contrast") != CONTRAST:
        raise RunnerError("renderer formal contrast changed")
    if formal["dithers"] != list(DITHERS) or any(
        type(item) is not int for item in formal["dithers"]
    ):
        raise RunnerError("renderer formal dithers changed")
    for field, expected in (
        ("warmup", FORMAL_WARMUP),
        ("iterations", FORMAL_ITERATIONS),
        ("rounds", FORMAL_ROUNDS),
    ):
        if require_int(formal[field], f"formal_contract.{field}", positive=True) != expected:
            raise RunnerError(f"renderer formal {field} changed")

    artifacts = require_mapping(evidence.get("artifacts"), "artifacts")
    asset = require_mapping(artifacts.get("asset"), "artifacts.asset")
    require_string(asset.get("path"), "artifacts.asset.path")
    expected_input = require_string(
        asset.get("benchmark_input", asset.get("path")),
        "artifacts.asset.benchmark_input",
    )
    require_sha256(asset.get("sha256"), "artifacts.asset.sha256")

    reports = require_list(evidence.get("benchmark_reports"), "benchmark_reports")
    records = require_list(evidence.get("run_records"), "run_records")
    expected_report_count = FORMAL_ROUNDS * len(DITHERS) * len(BACKENDS)
    if len(reports) != expected_report_count or len(records) != expected_report_count:
        raise RunnerError("renderer benchmark matrix has missing or duplicate reports")

    summaries: list[dict[str, Any]] = []
    expected_index = 0
    for round_index in range(FORMAL_ROUNDS):
        for dither_index, dither in enumerate(DITHERS):
            rotation = (round_index + dither_index) % len(BACKENDS)
            order = BACKENDS[rotation:] + BACKENDS[:rotation]
            for position, backend in enumerate(order):
                record = require_mapping(records[expected_index], f"run_records[{expected_index}]")
                require_exact_keys(
                    record,
                    {"report_index", "round_index", "dither", "position", "backend"},
                    f"run_records[{expected_index}]",
                )
                expected_record = {
                    "report_index": expected_index,
                    "round_index": round_index,
                    "dither": dither,
                    "position": position,
                    "backend": backend,
                }
                for field, expected in expected_record.items():
                    actual = record[field]
                    if isinstance(expected, int):
                        actual = require_int(actual, f"run_records[{expected_index}].{field}")
                    if actual != expected:
                        raise RunnerError(
                            f"run_records[{expected_index}]: selective, duplicate, or reordered case"
                        )
                summaries.append(
                    verify_benchmark_report(
                        reports[expected_index],
                        expected_backend=backend,
                        expected_dither=dither,
                        expected_input=expected_input,
                        expected_warmup=FORMAL_WARMUP,
                        expected_iterations=FORMAL_ITERATIONS,
                        require_timed=True,
                    )
                )
                expected_index += 1

    rounds = require_list(evidence.get("benchmark_rounds"), "benchmark_rounds")
    if len(rounds) != FORMAL_ROUNDS:
        raise RunnerError("renderer benchmark round metadata is incomplete")
    for round_index, raw_round in enumerate(rounds):
        round_value = require_mapping(raw_round, f"benchmark_rounds[{round_index}]")
        require_exact_keys(
            round_value,
            {"round_index", "orders", "telemetry_pre", "telemetry_post"},
            f"benchmark_rounds[{round_index}]",
        )
        if require_int(round_value["round_index"], f"benchmark_rounds[{round_index}].round_index") != round_index:
            raise RunnerError("renderer round metadata was reordered")
        orders = require_list(round_value["orders"], f"benchmark_rounds[{round_index}].orders")
        if len(orders) != len(DITHERS):
            raise RunnerError("renderer round order metadata omitted a dither")
        for dither_index, dither in enumerate(DITHERS):
            order_value = require_mapping(
                orders[dither_index], f"benchmark_rounds[{round_index}].orders[{dither_index}]"
            )
            require_exact_keys(
                order_value,
                {"dither", "backend_order"},
                f"benchmark_rounds[{round_index}].orders[{dither_index}]",
            )
            rotation = (round_index + dither_index) % len(BACKENDS)
            expected_order = list(BACKENDS[rotation:] + BACKENDS[:rotation])
            if (
                require_int(
                    order_value["dither"],
                    f"benchmark_rounds[{round_index}].orders[{dither_index}].dither",
                )
                != dither
                or order_value["backend_order"] != expected_order
            ):
                raise RunnerError("renderer balanced backend rotation was forged or reduced")
        require_mapping(round_value["telemetry_pre"], f"benchmark_rounds[{round_index}].telemetry_pre")
        require_mapping(round_value["telemetry_post"], f"benchmark_rounds[{round_index}].telemetry_post")

    capabilities = summaries[0]["capabilities"]
    if any(summary["capabilities"] != capabilities for summary in summaries[1:]):
        raise RunnerError("renderer host capability report changed within the formal matrix")
    if not (capabilities["avx2"] and capabilities["fma"] and capabilities["avx512f"]):
        raise RunnerError("renderer formal host does not support every required backend")

    scalar_hashes: dict[int, dict[str, str]] = {}
    for dither in DITHERS:
        matching = [
            summary["hashes"]
            for record, summary in zip(records, summaries, strict=True)
            if record["backend"] == "scalar" and record["dither"] == dither
        ]
        if len(matching) != FORMAL_ROUNDS or any(item != matching[0] for item in matching[1:]):
            raise RunnerError(f"dither={dither}: scalar output hashes changed across rounds")
        scalar_hashes[dither] = matching[0]
    for record, summary in zip(records, summaries, strict=True):
        if summary["hashes"] != scalar_hashes[record["dither"]]:
            raise RunnerError(
                f"{record['backend']} dither={record['dither']}: output differs from scalar"
            )

    aggregate = aggregate_medians(records, reports, FORMAL_ROUNDS)
    performance = evaluate_performance(aggregate)
    if performance["status"] != "passed":
        raise RunnerError(f"renderer formal performance gate failed: {performance['failures']}")
    if evidence.get("cross_round_medians") != aggregate:
        raise RunnerError("renderer reported aggregates disagree with raw timing samples")
    if evidence.get("performance_gate") != performance:
        raise RunnerError("renderer reported performance gate disagrees with recomputation")
    cross_backend = require_mapping(
        evidence.get("cross_backend_hashes"), "cross_backend_hashes"
    )
    if (
        cross_backend.get("status") != "passed"
        or cross_backend.get("baseline") != "scalar"
        or cross_backend.get("mismatches") != []
    ):
        raise RunnerError("renderer reported cross-backend gate disagrees with recomputation")
    reported_hashes = require_mapping(
        cross_backend.get("hashes_by_dither"), "cross_backend_hashes.hashes_by_dither"
    )
    for dither, expected_hashes in scalar_hashes.items():
        actual_hashes = reported_hashes.get(dither, reported_hashes.get(str(dither)))
        if actual_hashes != expected_hashes:
            raise RunnerError(f"renderer dither={dither} reported hashes were forged")
    if len(reported_hashes) != len(DITHERS):
        raise RunnerError("renderer reported hash matrix contains extra dithers")
    if evidence.get("status") != "passed":
        raise RunnerError("renderer evidence self-status disagrees with recomputed formal result")
    return {
        "actual_backends": {"SCALAR": "scalar", "AVX2": "avx2+fma", "AVX512": "avx512f"},
        "capabilities": capabilities,
        "scalar_hashes": scalar_hashes,
        "aggregate": aggregate,
        "performance": performance,
    }


def build_environment_report(
    repository: pathlib.Path,
    target: str,
    target_directory: pathlib.Path,
    selected_cpu: int,
    allowed_cpus: str,
    cpu_selection: str,
) -> dict[str, Any]:
    cpuinfo = pathlib.Path("/proc/cpuinfo").read_text(
        encoding="ascii", errors="replace"
    )
    cpu_model = ""
    cpu_flags: list[str] = []
    for line in cpuinfo.splitlines():
        if not cpu_model and line.startswith("model name"):
            cpu_model = line.partition(":")[2].strip()
        if not cpu_flags and (line.startswith("flags") or line.startswith("Features")):
            cpu_flags = line.partition(":")[2].strip().split()
    return {
        "cpu_model": cpu_model,
        "cpu_flags": cpu_flags,
        "rustc_vv": command_output(repository, "rustc", "-vV"),
        "cargo_version": command_output(repository, "cargo", "-V"),
        "target": target,
        "cargo_target_directory": str(target_directory),
        "cargo_profile": "release",
        "rustflags": os.environ.get("RUSTFLAGS", ""),
        "cpu_affinity": {
            "selected_cpu": selected_cpu,
            "allowed_cpus": allowed_cpus,
            "selection": cpu_selection,
            "enforcement": "taskset --cpu-list for every backend process",
        },
        "telemetry": {
            "scope": "before and after every balanced round",
            "governor": "recorded with explicit available/unavailable status",
            "frequency": "recorded with explicit available/unavailable status",
            "temperature": "recorded with explicit available/unavailable status",
        },
    }


def _run_locked(arguments: argparse.Namespace, resources: contextlib.ExitStack) -> int:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RunnerError("renderer SIMD evidence requires Linux x86_64")
    for tool in ("cargo", "rustc", "git", "taskset"):
        if shutil.which(tool) is None:
            raise RunnerError(f"required tool is unavailable: {tool}")
    workspace_lock = EvidenceLock.acquire()
    resources.callback(workspace_lock.close)

    repository = pathlib.Path(__file__).resolve().parents[2]
    asset_relative = pathlib.Path("crates/lmyzmail/assets/skibidi_toilet_episode_1.mp4")
    asset = (repository / asset_relative).resolve(strict=True)
    output = arguments.output.resolve()
    if output.exists():
        raise RunnerError(f"refusing to overwrite existing evidence: {output}")
    if not output.parent.is_dir():
        raise RunnerError(f"evidence output directory is missing: {output.parent}")

    selected_cpu, allowed_cpus, cpu_selection = select_cpu(arguments.cpu)
    subprocess.check_call(("taskset", "--cpu-list", str(selected_cpu), "true"))
    frozen = source_snapshot(repository)
    source_pins = pin_source_snapshot(repository, frozen)
    for pin in source_pins.values():
        resources.callback(pin.close)
    frozen_utc = dt.datetime.now(dt.UTC).isoformat()
    asset_pin = PinnedFile(asset, label="renderer input asset")
    resources.callback(asset_pin.close)
    asset_sha256 = asset_pin.sha256
    target_lines = command_output(repository, "rustc", "-vV").splitlines()
    target = next(
        (line.partition(":")[2].strip() for line in target_lines if line.startswith("host:")),
        "",
    )
    if not target:
        raise RunnerError("rustc did not report its host target")
    subprocess.check_call(
        (
            "cargo",
            "build",
            "--locked",
            "--release",
            "--target",
            target,
            "--features",
            "renderer-simd-bench",
            "--bin",
            "renderer-simd-bench",
        ),
        cwd=repository,
    )
    target_directory = pathlib.Path(os.environ.get("CARGO_TARGET_DIR", repository / "target"))
    if not target_directory.is_absolute():
        target_directory = repository / target_directory
    target_directory = target_directory.resolve()
    binary = target_directory / target / "release" / "renderer-simd-bench"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RunnerError(f"benchmark binary was not produced: {binary}")
    binary_pin = PinnedFile(binary, label="renderer benchmark binary", executable=True)
    resources.callback(binary_pin.close)
    binary_sha256 = binary_pin.sha256
    verifications = [
        verify_attribution(
            repository,
            frozen,
            binary,
            binary_sha256,
            asset,
            asset_sha256,
            "post-build",
            source_pins=source_pins,
            binary_pin=binary_pin,
            asset_pin=asset_pin,
        )
    ]

    if arguments.unsupported_probe:
        benchmark_backends = (arguments.unsupported_probe,)
        dithers = (0,)
        warmup = 1
        iterations = 1
        rounds = 1
        profile_name = "unsupported-probe"
    elif arguments.smoke:
        benchmark_backends = BACKENDS
        dithers = DITHERS
        warmup = SMOKE_WARMUP
        iterations = SMOKE_ITERATIONS
        rounds = SMOKE_ROUNDS
        profile_name = "smoke"
    else:
        benchmark_backends = BACKENDS
        dithers = DITHERS
        warmup = FORMAL_WARMUP
        iterations = FORMAL_ITERATIONS
        rounds = FORMAL_ROUNDS
        profile_name = "formal"

    reports: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    benchmark_rounds: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="lmyzmail-renderer-simd-v2.") as temp_name:
        temporary = pathlib.Path(temp_name)
        for round_index in range(rounds):
            verifications.append(
                verify_attribution(
                    repository,
                    frozen,
                    binary,
                    binary_sha256,
                    asset,
                    asset_sha256,
                    f"round-{round_index}-pre",
                    source_pins=source_pins,
                    binary_pin=binary_pin,
                    asset_pin=asset_pin,
                )
            )
            telemetry_pre = capture_telemetry(selected_cpu, f"round-{round_index}-pre")
            orders: list[dict[str, Any]] = []
            for dither_index, dither in enumerate(dithers):
                if len(benchmark_backends) == len(BACKENDS):
                    rotation = (round_index + dither_index) % len(BACKENDS)
                    order = BACKENDS[rotation:] + BACKENDS[:rotation]
                else:
                    order = benchmark_backends
                orders.append({"dither": dither, "backend_order": list(order)})
                for position, backend in enumerate(order):
                    report_path = temporary / (
                        f"round-{round_index}-dither-{dither}-position-{position}.json"
                    )
                    command = [
                        "taskset",
                        "--cpu-list",
                        str(selected_cpu),
                        binary_pin.proc_path(),
                        "--input",
                        asset_pin.proc_path(),
                        "--frame-index",
                        str(FRAME_INDEX),
                        "--backend",
                        backend,
                        "--sizes",
                        ",".join(map(str, SIZES)),
                        "--contrast",
                        str(CONTRAST),
                        "--dither",
                        str(dither),
                        "--warmup",
                        str(warmup),
                        "--iterations",
                        str(iterations),
                        "--unsupported",
                        "record",
                        "--output",
                        str(report_path),
                    ]
                    subprocess.check_call(
                        command,
                        cwd=repository,
                        pass_fds=(binary_pin.descriptor, asset_pin.descriptor),
                    )
                    report = strict_json_file(report_path, label=str(report_path))
                    validate_report_identity(
                        report,
                        backend,
                        dither,
                        asset_pin.proc_path(),
                        warmup,
                        iterations,
                        require_timed=profile_name == "formal",
                    )
                    records.append(
                        {
                            "report_index": len(reports),
                            "round_index": round_index,
                            "dither": dither,
                            "position": position,
                            "backend": backend,
                        }
                    )
                    reports.append(report)
            telemetry_post = capture_telemetry(selected_cpu, f"round-{round_index}-post")
            benchmark_rounds.append(
                {
                    "round_index": round_index,
                    "orders": orders,
                    "telemetry_pre": telemetry_pre,
                    "telemetry_post": telemetry_post,
                }
            )
            verifications.append(
                verify_attribution(
                    repository,
                    frozen,
                    binary,
                    binary_sha256,
                    asset,
                    asset_sha256,
                    f"round-{round_index}-post",
                    source_pins=source_pins,
                    binary_pin=binary_pin,
                    asset_pin=asset_pin,
                )
            )

    if profile_name == "unsupported-probe":
        report = reports[0]
        if not (
            report.get("status") == "unsupported"
            and report.get("fallback_used") is True
            and report.get("requested_backend") != report.get("resolved_backend")
            and report.get("frame") is None
            and report.get("sizes") == []
        ):
            raise RunnerError("unsupported probe did not observe an untimed production fallback")
        status = "unsupported_observed"
        cross_backend: dict[str, Any] = {"status": "not_applicable"}
        aggregate: list[dict[str, Any]] = []
        performance: dict[str, Any] = {"status": "not_applicable"}
    else:
        statuses: dict[tuple[str, int], set[str]] = defaultdict(set)
        supported_reports: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for record, report in zip(records, reports, strict=True):
            status_value = report.get("status")
            statuses[(record["backend"], record["dither"])].add(str(status_value))
            if status_value == "ok":
                if (
                    report.get("resolved_backend") != record["backend"]
                    or report.get("fallback_used") is not False
                ):
                    raise RunnerError(f"{record['backend']}: timed a backend fallback")
                supported_reports.append((record, report))
            elif status_value == "unsupported":
                if not (
                    report.get("fallback_used") is True
                    and report.get("frame") is None
                    and report.get("sizes") == []
                ):
                    raise RunnerError(f"{record['backend']}: invalid unsupported report")
            else:
                raise RunnerError(f"{record['backend']}: invalid report status")
        if any(len(values) != 1 for values in statuses.values()):
            raise RunnerError(f"backend support changed across rounds: {statuses}")
        if profile_name == "formal" and any(
            statuses[(backend, dither)] != {"ok"}
            for backend in BACKENDS
            for dither in DITHERS
        ):
            raise RunnerError(
                "formal evidence requires real Scalar, AVX2+FMA, and AVX-512F execution for every dither"
            )
        scalar_baselines: dict[int, dict[str, str]] = {}
        mismatches: list[dict[str, Any]] = []
        for dither in dithers:
            scalar = [
                report
                for _, report in supported_reports
                if report["requested_backend"] == "scalar"
                and report["parameters"]["dither"] == dither
            ]
            if len(scalar) != rounds:
                if profile_name == "formal":
                    raise RunnerError(f"dither={dither}: missing scalar baselines")
                continue
            scalar_baselines[dither] = output_hashes(scalar[0])
        for record, report in supported_reports:
            baseline = scalar_baselines.get(record["dither"])
            if baseline is None:
                continue
            candidate = output_hashes(report)
            if candidate != baseline:
                mismatches.append(
                    {
                        "backend": record["backend"],
                        "dither": record["dither"],
                        "round_index": record["round_index"],
                        "scalar": baseline,
                        "candidate": candidate,
                    }
                )
        if mismatches:
            raise RunnerError(f"cross-backend output hash mismatch: {mismatches}")
        cross_backend = {
            "status": "passed" if profile_name == "formal" else "smoke_only",
            "baseline": "scalar",
            "hashes_by_dither": scalar_baselines,
            "mismatches": [],
        }
        aggregate = aggregate_medians(records, reports, rounds)
        performance = (
            evaluate_performance(aggregate)
            if profile_name == "formal"
            else {"status": "not_evaluated_smoke"}
        )
        if performance["status"] == "failed":
            raise RunnerError(
                f"renderer SIMD performance gate failed: {performance['failures']}"
            )
        status = "passed" if profile_name == "formal" else "smoke_only"

    verifications.append(
        verify_attribution(
            repository,
            frozen,
            binary,
            binary_sha256,
            asset,
            asset_sha256,
            "pre-publish",
            source_pins=source_pins,
            binary_pin=binary_pin,
            asset_pin=asset_pin,
        )
    )
    frame_hashes = {
        report["frame"]["rgb24_sha256"]
        for report in reports
        if report.get("frame") is not None
    }
    if len(frame_hashes) > 1:
        raise RunnerError("supported backends decoded different source frames")
    evidence = {
        "schema": PROBE_SCHEMA if profile_name == "unsupported-probe" else SCHEMA,
        "status": status,
        "generated_utc": dt.datetime.now(dt.UTC).isoformat(),
        "profile": profile_name,
        "round_count": rounds,
        "formal_contract": (
            {
                "input": asset_relative.as_posix(),
                "frame_index": FRAME_INDEX,
                "sizes": list(SIZES),
                "contrast": CONTRAST,
                "dithers": list(DITHERS),
                "warmup": FORMAL_WARMUP,
                "iterations": FORMAL_ITERATIONS,
                "rounds": FORMAL_ROUNDS,
            }
            if profile_name == "formal"
            else None
        ),
        "benchmark_reports": reports,
        "run_records": records,
        "benchmark_rounds": benchmark_rounds,
        "cross_round_medians": aggregate,
        "cross_backend_hashes": cross_backend,
        "performance_gate": performance,
        "environment": build_environment_report(
            repository,
            target,
            target_directory,
            selected_cpu,
            allowed_cpus,
            cpu_selection,
        ),
        "artifacts": {
            "binary": {
                "path": str(binary),
                "sha256": binary_sha256,
                "identity": binary_pin.identity,
            },
            "cargo_lock": {
                "path": "Cargo.lock",
                "sha256": frozen["cargo_lock_sha256"],
            },
            "source": {
                "sha256": frozen["source_sha256"],
                "files": frozen["source_files"],
            },
            "asset": {
                "path": str(asset),
                "benchmark_input": asset_pin.proc_path(),
                "sha256": asset_sha256,
                "identity": asset_pin.identity,
            },
            "frame_rgb24_sha256": next(iter(frame_hashes), None),
            "scalar_golden_hashes": cross_backend.get("hashes_by_dither", {}),
        },
        "git": {
            "head": frozen["head"],
            "dirty": bool(frozen["status_porcelain_v1"]),
            "status_porcelain_v1": frozen["status_porcelain_v1"],
            "status_sha256": frozen["status_sha256"],
            "tracked_diff_sha256": frozen["tracked_diff_sha256"],
        },
        "attribution": {
            "snapshot_timing": "frozen before cargo build",
            "snapshot_frozen_utc": frozen_utc,
            "identity": {
                "source_sha256": frozen["source_sha256"],
                "status_sha256": frozen["status_sha256"],
                "cargo_lock_sha256": frozen["cargo_lock_sha256"],
                "binary_sha256": binary_sha256,
                "asset_sha256": asset_sha256,
            },
            "verifications": verifications,
        },
    }
    if profile_name == "formal":
        verify_formal_evidence(evidence)
    atomic_publish(output, evidence)
    print(f"renderer SIMD evidence written to {output}")
    return 0


def run() -> int:
    parser = argparse.ArgumentParser()
    profile = parser.add_mutually_exclusive_group()
    profile.add_argument("--smoke", action="store_true")
    profile.add_argument(
        "--unsupported-probe", choices=BACKENDS[1:], metavar="BACKEND"
    )
    parser.add_argument("--cpu", type=int)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    arguments = parser.parse_args()
    with contextlib.ExitStack() as resources:
        return _run_locked(arguments, resources)


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except (RunnerError, OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"renderer SIMD evidence failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
