#!/usr/bin/env python3
"""Produce attributed end-to-end renderer SIMD evidence.

The script consumes a passed renderer SIMD formal artifact, rebuilds the
production candidate from the same frozen source/lock state, and runs the
Minecraft video and mail-view Java-golden comparisons once per explicit
renderer backend. It publishes only after every normalized observation is
byte-identical across Scalar, AVX2+FMA, and AVX-512F.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import importlib.util
import json
import os
import pathlib
import platform
import secrets
import subprocess
import sys
import threading
import time
import signal
from collections.abc import Iterable, Mapping
from typing import Any


SCHEMA = "lmyzmail.renderer-e2e-evidence.v1"
RENDERER_SCHEMA = "lmyzmail.renderer-simd-evidence.v2"
MODES = (
    ("SCALAR", "scalar"),
    ("AVX2", "avx2+fma"),
    ("AVX512", "avx512f"),
)
TESTS = (
    ("minecraft-video", "managed-minecraft-video-v12"),
    ("minecraft-mail-view", "managed-minecraft-mail-view-v13"),
)
GOLDEN_PATHS = (
    pathlib.Path("blackbox/golden/java/managed-minecraft-video-v12"),
    pathlib.Path("blackbox/golden/java/managed-minecraft-mail-view-v13"),
)
OBSERVER_SCHEMA = "lmyzmail.renderer-dispatch-observation.v1"
OBSERVER_MAX_BYTES = 128 * 1024
OBSERVER_ENV_FD = "LMYZMAIL_RENDER_OBSERVER_FD"
OBSERVER_ENV_SESSION = "LMYZMAIL_RENDER_OBSERVER_SESSION"
OBSERVER_ENV_SOURCE = "LMYZMAIL_RENDER_OBSERVER_SOURCE_SHA256"
OBSERVER_ENV_BUILD = "LMYZMAIL_RENDER_OBSERVER_BUILD_SHA256"
OBSERVER_ENV_BINARY_FD = "LMYZMAIL_RENDER_OBSERVER_BINARY_FD"
EXPECTED_COMPONENTS = {
    "minecraft-video": {
        "mail_render.resize_rgb24_box",
        "mail_render.apply_rgb24_contrast",
        "minecraft.map_palette",
        "minecraft.block_palette_rgb",
        "minecraft.block_palette_states",
    },
    "minecraft-mail-view": {"mail_render.map_palette"},
}


def _load_renderer_verifier() -> Any:
    path = pathlib.Path(__file__).with_name("renderer_simd_runner_v2.py")
    specification = importlib.util.spec_from_file_location("lmyzmail_renderer_verifier_v2", path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load renderer verifier: {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


RENDERER_VERIFIER = _load_renderer_verifier()


class EvidenceError(RuntimeError):
    pass


@contextlib.contextmanager
def scenario_deadline(seconds: int) -> Any:
    def expired(_signal: int, _frame: Any) -> None:
        raise EvidenceError(f"renderer end-to-end scenario exceeded {seconds} seconds")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def source_file_digest(path: pathlib.Path) -> str:
    if path.is_symlink():
        return sha256_bytes(b"symlink\0" + os.fsencode(os.readlink(path)))
    if not path.is_file():
        raise EvidenceError(f"attributed source is not a regular file: {path}")
    return sha256_file(path)


def git_bytes(repository: pathlib.Path, *arguments: str) -> bytes:
    return subprocess.check_output(
        ("git", *arguments), cwd=repository, stderr=subprocess.STDOUT
    )


def normalized_status_bytes(
    repository: pathlib.Path, ignored_untracked_paths: Iterable[pathlib.Path]
) -> bytes:
    status = git_bytes(
        repository, "status", "--porcelain=v1", "-z", "--untracked-files=all"
    )
    ignored: set[bytes] = set()
    resolved_repository = repository.resolve()
    for path in ignored_untracked_paths:
        resolved = path.resolve()
        try:
            relative = resolved.relative_to(resolved_repository).as_posix()
        except ValueError:
            continue
        ignored.add(b"?? " + os.fsencode(relative))
    entries = [entry for entry in status.split(b"\0") if entry]
    actual_ignored = {entry for entry in entries if entry in ignored}
    if actual_ignored != ignored:
        missing = sorted(os.fsdecode(value) for value in ignored - actual_ignored)
        raise EvidenceError(
            f"expected published evidence is not an untracked Git entry: {missing}"
        )
    remaining = [entry for entry in entries if entry not in ignored]
    return b"\0".join(remaining) + (b"\0" if remaining else b"")


def current_identity(
    repository: pathlib.Path,
    renderer_evidence: Any,
    candidate_binary: Any | None,
) -> dict[str, Any]:
    renderer_evidence.verify("identity")
    status = normalized_status_bytes(repository, (renderer_evidence.path,))
    identity: dict[str, Any] = {
        "head": git_bytes(repository, "rev-parse", "HEAD").decode("ascii").strip(),
        "status_sha256": sha256_bytes(status),
        "cargo_lock_sha256": sha256_file(repository / "Cargo.lock"),
        "renderer_evidence_sha256": renderer_evidence.sha256,
        "renderer_evidence_identity": renderer_evidence.identity,
    }
    if candidate_binary is not None:
        candidate_binary.verify("identity")
        identity["candidate_binary_sha256"] = candidate_binary.sha256
        identity["candidate_binary_identity"] = candidate_binary.identity
    return identity


def pin_source_snapshot(
    repository: pathlib.Path, evidence: Mapping[str, Any]
) -> dict[str, Any]:
    try:
        expected_files = evidence["artifacts"]["source"]["files"]
    except (KeyError, TypeError) as error:
        raise EvidenceError("renderer evidence has no attributed source file map") from error
    if not isinstance(expected_files, dict) or not expected_files:
        raise EvidenceError("renderer evidence source file map is empty")
    pins: dict[str, Any] = {}
    try:
        actual_digest = hashlib.sha256()
        for relative, expected in sorted(expected_files.items()):
            if not isinstance(relative, str) or not isinstance(expected, str):
                raise EvidenceError("renderer evidence source file map is malformed")
            pin = RENDERER_VERIFIER.PinnedFile(
                RENDERER_VERIFIER.repository_file_path(
                    repository, relative, label=f"attributed source {relative}"
                ),
                label=f"attributed source {relative}",
            )
            if pin.sha256 != expected:
                pin.close()
                raise EvidenceError(f"attributed source changed: {relative}")
            pins[relative] = pin
            actual_digest.update(os.fsencode(relative))
            actual_digest.update(b"\0")
            actual_digest.update(pin.sha256.encode("ascii"))
            actual_digest.update(b"\0")
        expected_digest = evidence["artifacts"]["source"].get("sha256")
        if actual_digest.hexdigest() != expected_digest:
            raise EvidenceError("renderer evidence source aggregate changed")
        return pins
    except BaseException:
        for pin in pins.values():
            pin.close()
        raise


def verify_source_snapshot(pins: Mapping[str, Any], label: str) -> None:
    for relative, pin in pins.items():
        try:
            pin.verify(f"{label}: {relative}")
        except RENDERER_VERIFIER.RunnerError as error:
            raise EvidenceError(str(error)) from error


def tree_manifest(root: pathlib.Path, relative_roots: Iterable[pathlib.Path]) -> dict[str, str]:
    manifest: dict[str, str] = {}
    for relative_root in relative_roots:
        absolute_root = root / relative_root
        if not absolute_root.is_dir():
            raise EvidenceError(f"golden directory is missing: {relative_root}")
        for path in sorted(absolute_root.rglob("*")):
            if path.is_file() or path.is_symlink():
                relative = path.relative_to(root).as_posix()
                manifest[relative] = source_file_digest(path)
    if not manifest:
        raise EvidenceError("golden manifest is empty")
    return manifest


def pin_tree_manifest(
    root: pathlib.Path, relative_roots: Iterable[pathlib.Path]
) -> tuple[dict[str, str], dict[str, Any]]:
    manifest: dict[str, str] = {}
    pins: dict[str, Any] = {}
    try:
        for relative_root in relative_roots:
            absolute_root = root / relative_root
            if not absolute_root.is_dir() or absolute_root.is_symlink():
                raise EvidenceError(f"golden directory is missing or linked: {relative_root}")
            for path in sorted(absolute_root.rglob("*")):
                if path.is_dir():
                    if path.is_symlink():
                        raise EvidenceError(f"golden tree contains a linked directory: {path}")
                    continue
                relative = path.relative_to(root).as_posix()
                pin = RENDERER_VERIFIER.PinnedFile(path, label=f"Java golden {relative}")
                pins[relative] = pin
                manifest[relative] = pin.sha256
        if not manifest:
            raise EvidenceError("golden manifest is empty")
        return manifest, pins
    except BaseException:
        for pin in pins.values():
            pin.close()
        raise


def verify_pins(pins: Mapping[str, Any], label: str) -> None:
    for relative, pin in pins.items():
        try:
            pin.verify(f"{label}: {relative}")
        except RENDERER_VERIFIER.RunnerError as error:
            raise EvidenceError(str(error)) from error


def manifest_sha256(manifest: Mapping[str, str]) -> str:
    digest = hashlib.sha256()
    for relative, file_digest in sorted(manifest.items()):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def validate_renderer_evidence(value: Mapping[str, Any]) -> dict[str, str]:
    try:
        recomputed = RENDERER_VERIFIER.verify_formal_evidence(value)
    except RENDERER_VERIFIER.RunnerError as error:
        raise EvidenceError(f"renderer formal evidence failed recomputation: {error}") from error
    return dict(recomputed["actual_backends"])


class ObserverPipe:
    def __init__(self) -> None:
        flags = getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "pipe2"):
            self.read_descriptor, self.write_descriptor = os.pipe2(flags)
        else:  # pragma: no cover - formal execution is Linux-only.
            self.read_descriptor, self.write_descriptor = os.pipe()
        self._buffer = bytearray()
        self._error: BaseException | None = None
        self._writer_closed = False
        self._thread = threading.Thread(
            target=self._read,
            name="lmyzmail-render-observer",
            daemon=True,
        )
        self._thread.start()

    def _read(self) -> None:
        try:
            while True:
                chunk = os.read(self.read_descriptor, 4096)
                if not chunk:
                    return
                if len(self._buffer) + len(chunk) > OBSERVER_MAX_BYTES:
                    self._error = EvidenceError(
                        f"renderer observer exceeded {OBSERVER_MAX_BYTES} bytes"
                    )
                    continue
                self._buffer.extend(chunk)
        except BaseException as error:
            self._error = error

    def close_parent_writer(self) -> None:
        if not self._writer_closed:
            os.close(self.write_descriptor)
            self._writer_closed = True

    def finish(self) -> bytes:
        self.close_parent_writer()
        self._thread.join(timeout=10.0)
        if self._thread.is_alive():
            raise EvidenceError("renderer observer reader did not reach EOF")
        os.close(self.read_descriptor)
        self.read_descriptor = -1
        if self._error is not None:
            raise EvidenceError(f"renderer observer reader failed: {self._error}")
        return bytes(self._buffer)

    def close(self) -> None:
        if not self._writer_closed:
            with contextlib.suppress(OSError):
                os.close(self.write_descriptor)
            self._writer_closed = True
        if self.read_descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(self.read_descriptor)
            self.read_descriptor = -1


def validate_observer_events(
    value: bytes,
    *,
    scenario: str,
    expected_mode: str,
    expected_backend: str,
    expected_capabilities: Mapping[str, bool],
    source_sha256: str,
    build_sha256: str,
    session: str,
) -> list[dict[str, Any]]:
    if not value or len(value) > OBSERVER_MAX_BYTES or not value.endswith(b"\n"):
        raise EvidenceError("renderer observer stream is empty, oversized, or unterminated")
    raw_lines = value.splitlines()
    expected_components = EXPECTED_COMPONENTS[scenario]
    if len(raw_lines) != len(expected_components):
        raise EvidenceError(
            f"{scenario}: renderer observer event count changed; "
            f"expected {len(expected_components)}, got {len(raw_lines)}"
        )
    events: list[dict[str, Any]] = []
    sequences: set[int] = set()
    components: set[str] = set()
    for index, line in enumerate(raw_lines):
        try:
            event = RENDERER_VERIFIER.require_mapping(
                RENDERER_VERIFIER.strict_json_bytes(line, label=f"observer event {index}"),
                f"observer event {index}",
            )
            RENDERER_VERIFIER.require_exact_keys(
                event,
                {
                    "schema",
                    "sequence",
                    "component",
                    "requested_mode",
                    "requested_backend",
                    "resolved_backend",
                    "host_capabilities",
                    "source_sha256",
                    "build_sha256",
                    "session",
                },
                f"observer event {index}",
            )
            sequence = RENDERER_VERIFIER.require_int(
                event["sequence"], f"observer event {index}.sequence", positive=True
            )
            component = RENDERER_VERIFIER.require_string(
                event["component"], f"observer event {index}.component"
            )
            capabilities = RENDERER_VERIFIER.require_mapping(
                event["host_capabilities"], f"observer event {index}.host_capabilities"
            )
            RENDERER_VERIFIER.require_exact_keys(
                capabilities,
                {"avx2", "fma", "avx512f"},
                f"observer event {index}.host_capabilities",
            )
            actual_capabilities = {
                name: RENDERER_VERIFIER.require_bool(
                    capabilities[name], f"observer event {index}.host_capabilities.{name}"
                )
                for name in ("avx2", "fma", "avx512f")
            }
        except RENDERER_VERIFIER.RunnerError as error:
            raise EvidenceError(f"{scenario}: invalid renderer observer event: {error}") from error
        if event["schema"] != OBSERVER_SCHEMA:
            raise EvidenceError(f"{scenario}: renderer observer schema changed")
        if sequence != index + 1:
            raise EvidenceError(f"{scenario}: renderer observer sequence is out of order")
        if sequence in sequences or component in components:
            raise EvidenceError(f"{scenario}: duplicate observer sequence or component")
        if component not in expected_components:
            raise EvidenceError(f"{scenario}: forged or unexpected observer component {component}")
        if (
            event["requested_mode"] != expected_mode
            or event["requested_backend"] != expected_backend
            or event["resolved_backend"] != expected_backend
        ):
            raise EvidenceError(f"{scenario}: actual renderer backend did not match {expected_backend}")
        if actual_capabilities != dict(expected_capabilities):
            raise EvidenceError(f"{scenario}: observer host feature bits changed")
        if event["source_sha256"] != source_sha256 or event["build_sha256"] != build_sha256:
            raise EvidenceError(f"{scenario}: observer source/build identity changed")
        if event["session"] != session:
            raise EvidenceError(f"{scenario}: observer session capability changed")
        sequences.add(sequence)
        components.add(component)
        events.append(dict(event))
    if sequences != set(range(1, len(events) + 1)) or components != expected_components:
        raise EvidenceError(f"{scenario}: observer stream is partial, duplicated, or reordered")
    return events


@contextlib.contextmanager
def candidate_process_with_fds(
    runtime_module: Any,
    observer: ObserverPipe,
    binary_descriptor: int,
) -> Any:
    original = runtime_module.ManagedProcess
    observer_descriptor = observer.write_descriptor

    class FdManagedProcess(original):
        def start(self) -> None:
            if self.name != "rust-candidate":
                return super().start()
            if self._process is not None:
                raise RuntimeError(f"{self.name} already started")
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log = self.log_path.open("wb")
            process_env = os.environ.copy() if self.inherit_env else {}
            if self.env:
                process_env.update(self.env)
            try:
                self._process = subprocess.Popen(  # noqa: S603
                    list(self.argv),
                    cwd=self.cwd,
                    env=process_env,
                    stdin=subprocess.DEVNULL,
                    stdout=self._log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    pass_fds=(observer_descriptor, binary_descriptor),
                )
                observer.close_parent_writer()
            except BaseException:
                self._log.close()
                self._log = None
                raise

    runtime_module.ManagedProcess = FdManagedProcess
    try:
        yield
    finally:
        runtime_module.ManagedProcess = original


def collect_render_digests(value: Any, path: str = "$") -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if set(("length", "sha256")).issubset(value) and isinstance(value.get("sha256"), str):
            collected.append(
                {"path": path, "length": value["length"], "sha256": value["sha256"]}
            )
        if "palette_counts" in value:
            collected.append({"path": f"{path}.palette_counts", "value": value["palette_counts"]})
        for key, child in value.items():
            collected.extend(collect_render_digests(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            collected.extend(collect_render_digests(child, f"{path}[{index}]"))
    return collected


def _load_blackbox() -> tuple[Any, Any, Any, Any, Any, Any]:
    repository = pathlib.Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repository / "blackbox/src"))
    sys.path.insert(0, str(repository / "blackbox/tools"))
    import test_minecraft_mail_view as mail_view
    import test_minecraft_video as video
    from lmyzmail_blackbox.differential import DifferentialRunner, Scenario
    import lmyzmail_blackbox.runtime as runtime_module
    from lmyzmail_blackbox.runtime import CandidateRuntime

    return mail_view, video, DifferentialRunner, Scenario, CandidateRuntime, runtime_module


def _candidate_runtime(
    scenario: str,
    candidate_binary: Any,
    mode: str,
    candidate_runtime: Any,
    observer: ObserverPipe,
    *,
    source_sha256: str,
    session: str,
) -> Any:
    executable = candidate_binary.proc_path()

    class ObservedCandidateRuntime(candidate_runtime):
        def _verify_inputs(self) -> None:
            self._verify_backend_inputs()
            if not self.command_template or self.command_template[0] != executable:
                raise EvidenceError("candidate did not retain its pinned executable descriptor")
            metadata = os.stat(executable)
            if (metadata.st_dev, metadata.st_ino) != (
                candidate_binary.identity["device"],
                candidate_binary.identity["inode"],
            ):
                raise EvidenceError("candidate executable descriptor identity changed")

        def _application_environment(self) -> dict[str, str]:
            environment = super()._application_environment()
            environment.update(
                {
                    OBSERVER_ENV_FD: str(observer.write_descriptor),
                    OBSERVER_ENV_BINARY_FD: str(candidate_binary.descriptor),
                    OBSERVER_ENV_SESSION: session,
                    OBSERVER_ENV_SOURCE: source_sha256,
                    OBSERVER_ENV_BUILD: candidate_binary.sha256,
                }
            )
            return environment

    common = (
        executable,
        "--config",
        "{config}",
        "--lmyzmail.minecraft.enabled=true",
        "--lmyzmail.minecraft.online-mode=false",
    )
    if scenario == "minecraft-video":
        command = (
            *common,
            "--lmyzmail.minecraft.spawn.x=0.5",
            "--lmyzmail.minecraft.spawn.y=160.0",
            "--lmyzmail.minecraft.spawn.z=0.5",
            "--lmyzmail.minecraft.spawn.yaw=0.0",
            "--lmyzmail.minecraft.spawn.pitch=0.0",
            "--lmyzmail.minecraft.max-concurrent-videos=2",
            "--lmyzmail.minecraft.read-timeout-seconds=120",
            "--lmyzmail.minecraft.video.center-x=0",
            "--lmyzmail.minecraft.video.center-y=161",
            "--lmyzmail.minecraft.video.wall-z=-3",
            "--lmyzmail.minecraft.video.clear-margin=2",
            "--lmyzmail.minecraft.video.spawn-protect-radius=1",
            "--lmyzmail.minecraft.map-video.center-x=0",
            "--lmyzmail.minecraft.map-video.center-y=161",
            "--lmyzmail.minecraft.map-video.center-z=-3",
            "--lmyzmail.minecraft.map-video.facing=SOUTH",
            f"--lmyzmail.mailrender.simd-mode={mode}",
        )
    elif scenario == "minecraft-mail-view":
        command = (
            *common,
            "--lmyzmail.minecraft.spawn.x=-12.75",
            "--lmyzmail.minecraft.spawn.y=70.9",
            "--lmyzmail.minecraft.spawn.z=34.5",
            "--lmyzmail.minecraft.spawn.yaw=45.0",
            "--lmyzmail.minecraft.spawn.pitch=-15.0",
            f"--lmyzmail.mailrender.simd-mode={mode}",
        )
    else:
        raise EvidenceError(f"unknown renderer scenario: {scenario}")
    return ObservedCandidateRuntime(command_template=command)


def atomic_publish(path: pathlib.Path, value: Mapping[str, Any]) -> None:
    try:
        RENDERER_VERIFIER.atomic_publish(path, value)
    except RENDERER_VERIFIER.RunnerError as error:
        raise EvidenceError(str(error)) from error


def _run_locked(arguments: argparse.Namespace, resources: contextlib.ExitStack) -> int:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise EvidenceError("renderer E2E evidence requires Linux x86_64")
    workspace_lock = RENDERER_VERIFIER.EvidenceLock.acquire()
    resources.callback(workspace_lock.close)
    repository = pathlib.Path(__file__).resolve().parents[2]
    renderer_path = arguments.renderer_evidence.absolute()
    output = arguments.output.absolute()
    if output.exists():
        raise EvidenceError(f"refusing to overwrite evidence: {output}")
    if not output.parent.is_dir():
        raise EvidenceError(f"evidence output directory is missing: {output.parent}")
    renderer_pin = RENDERER_VERIFIER.PinnedFile(
        renderer_path, label="renderer formal evidence"
    )
    resources.callback(renderer_pin.close)
    try:
        renderer = RENDERER_VERIFIER.require_mapping(
            RENDERER_VERIFIER.strict_json_bytes(
                renderer_pin.read_bytes(), label="renderer formal evidence"
            ),
            "renderer formal evidence",
        )
        recomputed_renderer = RENDERER_VERIFIER.verify_formal_evidence(renderer)
    except RENDERER_VERIFIER.RunnerError as error:
        raise EvidenceError(f"renderer formal evidence failed recomputation: {error}") from error
    actual_backends = dict(recomputed_renderer["actual_backends"])
    renderer_artifacts = RENDERER_VERIFIER.require_mapping(
        renderer.get("artifacts"), "renderer artifacts"
    )
    renderer_asset = RENDERER_VERIFIER.require_mapping(
        renderer_artifacts.get("asset"), "renderer asset"
    )
    renderer_binary = RENDERER_VERIFIER.require_mapping(
        renderer_artifacts.get("binary"), "renderer benchmark binary"
    )
    asset_pin = RENDERER_VERIFIER.PinnedFile(
        pathlib.Path(
            RENDERER_VERIFIER.require_string(
                renderer_asset.get("path"), "renderer asset path"
            )
        ),
        label="renderer input asset",
    )
    resources.callback(asset_pin.close)
    benchmark_pin = RENDERER_VERIFIER.PinnedFile(
        pathlib.Path(
            RENDERER_VERIFIER.require_string(
                renderer_binary.get("path"), "renderer benchmark path"
            )
        ),
        label="renderer benchmark binary",
        executable=True,
    )
    resources.callback(benchmark_pin.close)
    if asset_pin.sha256 != renderer_asset.get("sha256"):
        raise EvidenceError("renderer input asset differs from formal evidence")
    if benchmark_pin.sha256 != renderer_binary.get("sha256"):
        raise EvidenceError("renderer benchmark binary differs from formal evidence")
    for label, pin, artifact in (
        ("renderer input asset", asset_pin, renderer_asset),
        ("renderer benchmark binary", benchmark_pin, renderer_binary),
    ):
        if artifact.get("identity") != pin.identity:
            raise EvidenceError(f"{label} dev/inode identity differs from formal evidence")
    source_pins = pin_source_snapshot(repository, renderer)
    for pin in source_pins.values():
        resources.callback(pin.close)
    verify_source_snapshot(source_pins, "initial source pin")

    golden_manifest, golden_pins = pin_tree_manifest(repository, GOLDEN_PATHS)
    for pin in golden_pins.values():
        resources.callback(pin.close)
    golden_digest = manifest_sha256(golden_manifest)
    snapshot_identity = current_identity(repository, renderer_pin, None)
    expected_git = RENDERER_VERIFIER.require_mapping(renderer.get("git"), "renderer git identity")
    if snapshot_identity["head"] != expected_git.get("head"):
        raise EvidenceError("Git HEAD differs from renderer evidence")
    if snapshot_identity["status_sha256"] != expected_git.get("status_sha256"):
        raise EvidenceError("Git status differs from renderer evidence")
    cargo_lock_pin = source_pins.get("Cargo.lock")
    if cargo_lock_pin is None:
        raise EvidenceError("renderer source snapshot did not pin Cargo.lock")
    if (
        snapshot_identity["cargo_lock_sha256"]
        != renderer["artifacts"]["cargo_lock"]["sha256"]
        or cargo_lock_pin.sha256 != snapshot_identity["cargo_lock_sha256"]
    ):
        raise EvidenceError("Cargo.lock differs from renderer evidence")

    target = renderer["environment"]["target"]
    rustc_vv = subprocess.check_output(
        ("rustc", "-vV"), cwd=repository, text=True, stderr=subprocess.STDOUT
    ).rstrip()
    cargo_version = subprocess.check_output(
        ("cargo", "-V"), cwd=repository, text=True, stderr=subprocess.STDOUT
    ).rstrip()
    if rustc_vv != renderer["environment"]["rustc_vv"]:
        raise EvidenceError("rustc identity differs from renderer evidence")
    if cargo_version != renderer["environment"]["cargo_version"]:
        raise EvidenceError("Cargo identity differs from renderer evidence")
    if os.environ.get("RUSTFLAGS", "") != renderer["environment"].get("rustflags", ""):
        raise EvidenceError("RUSTFLAGS differs from renderer evidence")
    target_directory = pathlib.Path(renderer["environment"]["cargo_target_directory"])
    build_environment = os.environ.copy()
    build_environment["CARGO_TARGET_DIR"] = str(target_directory)
    build_command = [
        "cargo",
        "build",
        "--locked",
        "--release",
        "--target",
        target,
        "--bin",
        "lmyzmail",
    ]
    subprocess.check_call(build_command, cwd=repository, env=build_environment)
    candidate_binary = target_directory / target / "release" / "lmyzmail"
    if not candidate_binary.is_file() or not os.access(candidate_binary, os.X_OK):
        raise EvidenceError(f"candidate binary was not produced: {candidate_binary}")
    candidate_pin = RENDERER_VERIFIER.PinnedFile(
        candidate_binary, label="candidate binary", executable=True
    )
    resources.callback(candidate_pin.close)

    verify_source_snapshot(source_pins, "post-build source")
    verify_pins(golden_pins, "post-build golden")
    asset_pin.verify("post-build asset")
    benchmark_pin.verify("post-build renderer benchmark")
    built_identity = current_identity(repository, renderer_pin, candidate_pin)
    if {key: built_identity[key] for key in snapshot_identity} != snapshot_identity:
        raise EvidenceError("source/lock/renderer identity changed during candidate build")

    (
        mail_view,
        video,
        differential_runner,
        scenario_type,
        candidate_runtime,
        runtime_module,
    ) = _load_blackbox()
    runs: list[dict[str, Any]] = []
    observations: dict[str, dict[str, Any]] = {test[0]: {} for test in TESTS}
    for mode, resolved_backend in MODES:
        for scenario, golden_profile in TESTS:
            if actual_backends.get(mode) != resolved_backend:
                raise EvidenceError(f"{mode} actual backend attestation changed")
            module = video if scenario == "minecraft-video" else mail_view
            original = module.SCENARIOS[0]
            captured: dict[str, Any] = {}

            def capture(target: Any, *, original_scenario: Any = original) -> Any:
                observation = original_scenario.capture(target)
                captured["observation"] = observation
                return observation

            wrapped = scenario_type(
                original.name,
                capture,
                normalizers=original.normalizers,
                contract=original.contract,
            )
            observer = ObserverPipe()
            session = secrets.token_hex(32)
            runtime = _candidate_runtime(
                scenario,
                candidate_pin,
                mode,
                candidate_runtime,
                observer,
                source_sha256=renderer["artifacts"]["source"]["sha256"],
                session=session,
            )
            lock = (
                mail_view._renderer_capture_lock()
                if scenario == "minecraft-mail-view"
                else contextlib.nullcontext()
            )
            started = time.monotonic()
            try:
                with candidate_process_with_fds(
                    runtime_module, observer, candidate_pin.descriptor
                ):
                    with scenario_deadline(1800):
                        with lock:
                            with runtime as candidate:
                                differential_runner(
                                    repository,
                                    repository / "blackbox/golden/java" / golden_profile,
                                    golden_profile,
                                ).verify_candidate((wrapped,), candidate)
                observer_events = validate_observer_events(
                    observer.finish(),
                    scenario=scenario,
                    expected_mode=mode,
                    expected_backend=resolved_backend,
                    expected_capabilities=recomputed_renderer["capabilities"],
                    source_sha256=renderer["artifacts"]["source"]["sha256"],
                    build_sha256=candidate_pin.sha256,
                    session=session,
                )
            finally:
                observer.close()
            elapsed = time.monotonic() - started
            observation = captured.get("observation")
            if observation is None:
                raise EvidenceError(f"{scenario} {mode} did not produce an observation")
            observation_hash = sha256_bytes(canonical_bytes(observation))
            observations[scenario][mode] = observation
            runs.append(
                {
                    "scenario": scenario,
                    "golden_profile": golden_profile,
                    "requested_mode": mode,
                    "resolved_backend": resolved_backend,
                    "dispatch_observations": observer_events,
                    "elapsed_seconds": elapsed,
                    "observation_sha256": observation_hash,
                    "render_digests": collect_render_digests(observation),
                }
            )
            verify_source_snapshot(source_pins, f"{scenario} {mode} source")
            verify_pins(golden_pins, f"{scenario} {mode} golden")
            asset_pin.verify(f"{scenario} {mode} asset")
            benchmark_pin.verify(f"{scenario} {mode} renderer benchmark")
            current = current_identity(repository, renderer_pin, candidate_pin)
            if current != built_identity:
                raise EvidenceError(f"attribution changed during {scenario} {mode}")

    cross_backend: dict[str, Any] = {}
    for scenario, by_mode in observations.items():
        hashes = {mode: sha256_bytes(canonical_bytes(value)) for mode, value in by_mode.items()}
        if set(by_mode) != {mode for mode, _ in MODES} or len(set(hashes.values())) != 1:
            raise EvidenceError(f"{scenario} observations differ across SIMD backends: {hashes}")
        cross_backend[scenario] = {
            "status": "passed",
            "observation_sha256": next(iter(hashes.values())),
            "backend_hashes": hashes,
            "scalar_observation": by_mode["SCALAR"],
        }

    verify_source_snapshot(source_pins, "final source")
    verify_pins(golden_pins, "final golden")
    asset_pin.verify("final asset")
    benchmark_pin.verify("final renderer benchmark")
    final_identity = current_identity(repository, renderer_pin, candidate_pin)
    if final_identity != built_identity:
        raise EvidenceError("final source/binary/lock attribution changed")
    evidence = {
        "schema": SCHEMA,
        "status": "passed",
        "generated_utc": dt.datetime.now(dt.UTC).isoformat(),
        "renderer_evidence": {
            "path": str(renderer_path),
            "sha256": renderer_pin.sha256,
            "identity": renderer_pin.identity,
            "schema": renderer["schema"],
            "actual_backends": actual_backends,
            "recomputed_performance_gate": recomputed_renderer["performance"],
            "recomputed_scalar_hashes": recomputed_renderer["scalar_hashes"],
        },
        "candidate_build": {
            "command": build_command,
            "target": target,
            "target_directory": str(target_directory),
            "binary": str(candidate_binary),
            "binary_sha256": final_identity["candidate_binary_sha256"],
            "binary_identity": candidate_pin.identity,
            "rustc_vv": rustc_vv,
            "cargo_version": cargo_version,
            "rustflags": os.environ.get("RUSTFLAGS", ""),
        },
        "attribution": {
            "source_sha256": renderer["artifacts"]["source"]["sha256"],
            "cargo_lock_sha256": final_identity["cargo_lock_sha256"],
            "git_head": final_identity["head"],
            "git_status_sha256": final_identity["status_sha256"],
            "golden_manifest_sha256": golden_digest,
            "golden_files": golden_manifest,
            "renderer_asset_sha256": asset_pin.sha256,
            "renderer_asset_identity": asset_pin.identity,
            "renderer_benchmark_sha256": benchmark_pin.sha256,
            "renderer_benchmark_identity": benchmark_pin.identity,
        },
        "runs": runs,
        "cross_backend_observations": cross_backend,
    }
    atomic_publish(output, evidence)
    print(f"renderer end-to-end SIMD evidence written to {output}")
    return 0


def run() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--renderer-evidence", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    arguments = parser.parse_args()
    try:
        with contextlib.ExitStack() as resources:
            return _run_locked(arguments, resources)
    except RENDERER_VERIFIER.RunnerError as error:
        raise EvidenceError(str(error)) from error


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except (EvidenceError, OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"renderer end-to-end evidence failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
