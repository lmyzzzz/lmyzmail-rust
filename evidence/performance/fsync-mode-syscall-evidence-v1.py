#!/usr/bin/env python3
"""Qualify the application-filesystem fsync switch with external syscall evidence."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPOSITORY = Path(__file__).resolve().parents[2]
BLACKBOX_SOURCE = REPOSITORY / "blackbox/src"
if str(BLACKBOX_SOURCE) not in sys.path:
    sys.path.insert(0, str(BLACKBOX_SOURCE))

import psycopg  # noqa: E402
import redis  # noqa: E402

from lmyzmail_blackbox.runtime import CandidateRuntime, HarnessError  # noqa: E402
from lmyzmail_blackbox.smtp_contract import SMTP_SCENARIOS  # noqa: E402

RUNNER_PATH = REPOSITORY / "evidence/performance/smtp-endpoint-throughput-v1.py"
RUNNER_SPEC = importlib.util.spec_from_file_location(
    "lmyzmail_smtp_endpoint_throughput_v1", RUNNER_PATH
)
if RUNNER_SPEC is None or RUNNER_SPEC.loader is None:
    raise RuntimeError(f"cannot load throughput runner: {RUNNER_PATH}")
runner = importlib.util.module_from_spec(RUNNER_SPEC)
sys.modules[RUNNER_SPEC.name] = runner
RUNNER_SPEC.loader.exec_module(runner)

TRACE_SYSCALLS = (
    "clone,clone3,execve,fsync,fdatasync,pwrite64,linkat,rename,renameat2,"
    "openat,openat2,write"
)
SYNC_START = re.compile(r"(?P<name>f(?:data)?sync)\((?P<arguments>.*)")
SYNC_RESUME = re.compile(r"<\.\.\. (?P<name>f(?:data)?sync) resumed>(?P<tail>.*)")
ATOMIC_START = re.compile(r"(?P<name>linkat|rename|renameat2)\((?P<arguments>.*)")
ATOMIC_RESUME = re.compile(
    r"<\.\.\. (?P<name>linkat|rename|renameat2) resumed>(?P<tail>.*)"
)
PID_PREFIX = re.compile(r"^\s*(?P<pid>[0-9]+)\s+")
TIMESTAMP_PREFIX = re.compile(r"^[0-9]+(?:\.[0-9]+)?\s+")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _write_exclusive(path: Path, payload: bytes, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        mode,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("exclusive evidence write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        with contextlib.suppress(OSError):
            path.unlink()
        raise
    else:
        os.close(descriptor)


def _copy_exclusive(source: Path, destination: Path, mode: int = 0o444) -> None:
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        mode,
    )
    try:
        with source.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                view = memoryview(chunk)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("exclusive trace copy made no progress")
                    view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        with contextlib.suppress(OSError):
            destination.unlink()
        raise
    else:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@dataclasses.dataclass(slots=True)
class FsyncProbeRuntime(runner.DurablePostgresRuntimeMixin, CandidateRuntime):
    filesystem_fsync_mode: str = "on"

    @property
    def requires_smtp_readiness(self) -> bool:
        return True

    def _candidate_configuration(self) -> Path:
        if self.filesystem_fsync_mode not in {"on", "off"}:
            raise HarnessError(
                f"invalid filesystem fsync mode: {self.filesystem_fsync_mode!r}"
            )
        path = CandidateRuntime._candidate_configuration(self)
        value = json.loads(path.read_text(encoding="utf-8"))
        storage = value.setdefault("storage", {})
        if not isinstance(storage, dict):
            raise HarnessError("candidate storage configuration is not an object")
        storage["fsync_enabled"] = self.filesystem_fsync_mode == "on"
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return path


def _postgres_snapshot(runtime: FsyncProbeRuntime) -> dict[str, Any]:
    assert runtime.ports is not None
    with psycopg.connect(
        host="127.0.0.1",
        port=runtime.ports.postgres,
        user="lmyzmail_test",
        dbname="lmyzmail",
        connect_timeout=5,
        autocommit=True,
    ) as connection:
        settings = {
            name: connection.execute(f"SHOW {name}").fetchone()[0]
            for name in ("fsync", "synchronous_commit", "full_page_writes")
        }
        wal = connection.execute(
            "SELECT wal_records::bigint, wal_fpi::bigint, wal_bytes::bigint "
            "FROM pg_stat_wal"
        ).fetchone()
    if wal is None:
        raise RuntimeError("PostgreSQL WAL statistics were unavailable")
    return {
        "settings": settings,
        "wal_records": int(wal[0]),
        "wal_fpi": int(wal[1]),
        "wal_bytes": int(wal[2]),
    }


def _redis_snapshot(client: redis.Redis) -> dict[str, Any]:
    persistence = client.info("persistence")
    return {
        "configuration": {
            "appendonly": client.config_get("appendonly").get("appendonly"),
            "appendfsync": client.config_get("appendfsync").get("appendfsync"),
            "save": client.config_get("save").get("save"),
        },
        "aof_enabled": int(persistence.get("aof_enabled", 0)),
        "aof_rewrite_in_progress": int(
            persistence.get("aof_rewrite_in_progress", 0)
        ),
        "aof_pending_bio_fsync": int(
            persistence.get("aof_pending_bio_fsync", 0)
        ),
        "aof_current_size": int(persistence.get("aof_current_size", 0)),
        "aof_last_write_status": str(
            persistence.get("aof_last_write_status", "")
        ),
    }


def _redis_client(runtime: FsyncProbeRuntime) -> redis.Redis:
    assert runtime.ports is not None
    return redis.Redis(
        host="127.0.0.1",
        port=runtime.ports.redis,
        db=0,
        socket_connect_timeout=2.0,
        socket_timeout=2.0,
        decode_responses=True,
    )


def _enable_and_snapshot_redis_aof(
    runtime: FsyncProbeRuntime, *, timeout_seconds: float = 30.0
) -> dict[str, Any]:
    client = _redis_client(runtime)
    try:
        if client.config_set("appendfsync", "always") is not True:
            raise RuntimeError("Redis rejected appendfsync=always")
        if client.config_set("appendonly", "yes") is not True:
            raise RuntimeError("Redis rejected appendonly=yes")
        deadline = time.monotonic() + timeout_seconds
        while True:
            persistence = client.info("persistence")
            if (
                int(persistence.get("aof_enabled", 0)) == 1
                and int(persistence.get("aof_rewrite_in_progress", 0)) == 0
                and str(persistence.get("aof_last_bgrewrite_status", "")) == "ok"
            ):
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("Redis AOF did not become ready")
            time.sleep(0.05)
        return _redis_snapshot(client)
    finally:
        client.close()


def _final_redis_snapshot(runtime: FsyncProbeRuntime) -> dict[str, Any]:
    client = _redis_client(runtime)
    try:
        deadline = time.monotonic() + 10.0
        while True:
            snapshot = _redis_snapshot(client)
            if snapshot["aof_pending_bio_fsync"] == 0:
                return snapshot
            if time.monotonic() >= deadline:
                raise TimeoutError("Redis retained pending AOF fsync work")
            time.sleep(0.02)
    finally:
        client.close()


def _run_probe(mode: str, result_path: Path) -> None:
    candidate = REPOSITORY / "target/x86_64-unknown-linux-gnu/release/lmyzmail"
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise FileNotFoundError(f"release candidate is unavailable: {candidate}")
    runtime = FsyncProbeRuntime(
        command_template=(str(candidate), "--config", "{config}"),
        filesystem_fsync_mode=mode,
        startup_timeout=180.0,
        shutdown_timeout=60.0,
        shutdown_kill_timeout=5.0,
    )
    workspace: Path | None = None
    started_at = _utc_now()
    with runtime:
        assert runtime.workspace is not None and runtime.ports is not None
        workspace = runtime.workspace.resolve()
        redis_before = _enable_and_snapshot_redis_aof(runtime)
        postgres_before = _postgres_snapshot(runtime)
        scenario_names: list[str] = []
        for scenario in SMTP_SCENARIOS:
            observation = scenario.capture(runtime)
            if not isinstance(observation, dict):
                raise RuntimeError(f"SMTP scenario {scenario.name} returned no mapping")
            scenario_names.append(scenario.name)
        postgres_after = _postgres_snapshot(runtime)
        redis_after = _final_redis_snapshot(runtime)
        process_ids = {
            name: process.pid
            for name, process in {
                "candidate": runtime._application,
                "postgres": runtime._postgres,
                "redis": runtime._redis,
            }.items()
            if process is not None
        }
    if workspace is None:
        raise RuntimeError("probe workspace identity was not captured")
    wal_delta = {
        key: postgres_after[key] - postgres_before[key]
        for key in ("wal_records", "wal_fpi", "wal_bytes")
    }
    result = {
        "schema_version": 1,
        "profile": "lmyzmail-fsync-mode-runtime-probe-v1",
        "mode": mode,
        "started_at": started_at,
        "completed_at": _utc_now(),
        "candidate": {
            "path": candidate.relative_to(REPOSITORY).as_posix(),
            "sha256": _sha256(candidate),
            "size_bytes": candidate.stat().st_size,
        },
        "workspace": str(workspace),
        "process_ids": process_ids,
        "smtp_scenarios": scenario_names,
        "smtp_scenario_count": len(scenario_names),
        "postgres_before": postgres_before,
        "postgres_after": postgres_after,
        "postgres_wal_delta": wal_delta,
        "redis_before": redis_before,
        "redis_after": redis_after,
        "runtime_cleanup_completed": True,
    }
    _write_exclusive(result_path, _canonical_bytes(result), 0o600)


def _pid(line: str) -> str:
    match = PID_PREFIX.match(line)
    return match.group("pid") if match is not None else "single"


def _syscall_body(line: str) -> str:
    without_pid = PID_PREFIX.sub("", line, count=1)
    return TIMESTAMP_PREFIX.sub("", without_pid, count=1)


def _completed_success(line: str) -> bool:
    return re.search(r"\)\s+=\s+0(?:\s|$)", line) is not None


def _trace_summary(trace_path: Path, workspace: str) -> dict[str, Any]:
    pending_sync: dict[str, tuple[str, str]] = {}
    pending_atomic: dict[str, tuple[str, str]] = {}
    sync_calls: list[dict[str, Any]] = []
    atomic_calls: list[dict[str, Any]] = []
    line_count = 0
    with trace_path.open("r", encoding="utf-8", errors="strict") as stream:
        for line in stream:
            line_count += 1
            pid = _pid(line)
            body = _syscall_body(line)
            resumed_sync = SYNC_RESUME.match(body)
            if resumed_sync is not None:
                pending = pending_sync.pop(pid, None)
                if pending is None or pending[0] != resumed_sync.group("name"):
                    raise RuntimeError("strace contained an unmatched sync resume")
                sync_calls.append(
                    {
                        "name": pending[0],
                        "arguments": pending[1],
                        "success": _completed_success(resumed_sync.group("tail")),
                    }
                )
                continue
            resumed_atomic = ATOMIC_RESUME.match(body)
            if resumed_atomic is not None:
                pending = pending_atomic.pop(pid, None)
                if pending is None or pending[0] != resumed_atomic.group("name"):
                    raise RuntimeError("strace contained an unmatched atomic resume")
                atomic_calls.append(
                    {
                        "name": pending[0],
                        "arguments": pending[1],
                        "success": _completed_success(resumed_atomic.group("tail")),
                    }
                )
                continue
            sync = SYNC_START.match(body)
            if sync is not None:
                arguments = sync.group("arguments")
                if "<unfinished ...>" in arguments:
                    if pid in pending_sync:
                        raise RuntimeError("strace contained overlapping sync calls")
                    pending_sync[pid] = (sync.group("name"), arguments)
                else:
                    sync_calls.append(
                        {
                            "name": sync.group("name"),
                            "arguments": arguments,
                            "success": _completed_success(line),
                        }
                    )
            atomic = ATOMIC_START.match(body)
            if atomic is not None:
                arguments = atomic.group("arguments")
                if "<unfinished ...>" in arguments:
                    if pid in pending_atomic:
                        raise RuntimeError("strace contained overlapping atomic calls")
                    pending_atomic[pid] = (atomic.group("name"), arguments)
                else:
                    atomic_calls.append(
                        {
                            "name": atomic.group("name"),
                            "arguments": arguments,
                            "success": _completed_success(line),
                        }
                    )
    if pending_sync:
        raise RuntimeError("strace ended with unfinished sync calls")

    postgres_marker = f"{workspace}/postgres-data"
    redis_marker = f"{workspace}/redis-data"
    maildir_marker = f"{workspace}/maildir"
    workspace_syncs = [call for call in sync_calls if workspace in call["arguments"]]
    application = [
        call
        for call in workspace_syncs
        if postgres_marker not in call["arguments"]
        and redis_marker not in call["arguments"]
    ]
    postgres = [
        call
        for call in sync_calls
        if f"{postgres_marker}/pg_wal" in call["arguments"]
    ]
    redis_aof = [
        call
        for call in sync_calls
        if redis_marker in call["arguments"]
        and ("appendonly" in call["arguments"] or ".aof" in call["arguments"])
    ]
    atomic_maildir = [
        call for call in atomic_calls if maildir_marker in call["arguments"]
    ]

    def counts(calls: list[dict[str, Any]]) -> dict[str, int]:
        return {
            "invocations": len(calls),
            "successful": sum(call["success"] is True for call in calls),
            "failed": sum(call["success"] is False for call in calls),
        }

    return {
        "path": trace_path.name,
        "sha256": _sha256(trace_path),
        "size_bytes": trace_path.stat().st_size,
        "line_count": line_count,
        "unfinished_sync_calls": len(pending_sync),
        "unfinished_atomic_calls": len(pending_atomic),
        "all_sync": counts(sync_calls),
        "application_owned_sync": counts(application),
        "postgres_wal_sync": counts(postgres),
        "redis_aof_sync": counts(redis_aof),
        "application_maildir_atomic_publication": counts(atomic_maildir),
    }


def _load_probe(path: Path, expected_mode: str) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise RuntimeError("runtime probe result has an invalid schema")
    if value.get("mode") != expected_mode:
        raise RuntimeError("runtime probe mode does not match its arm")
    return value


def _qualified(off: dict[str, Any], on: dict[str, Any]) -> tuple[bool, dict[str, bool]]:
    off_probe = off["probe"]
    on_probe = on["probe"]
    off_trace = off["trace"]
    on_trace = on["trace"]
    postgres_settings = {
        "fsync": "on",
        "synchronous_commit": "on",
        "full_page_writes": "on",
    }
    redis_configuration = {
        "appendonly": "yes",
        "appendfsync": "always",
        "save": "",
    }
    checks = {
        "same_candidate": off_probe["candidate"] == on_probe["candidate"],
        "three_smtp_modes_each": off_probe["smtp_scenario_count"]
        == on_probe["smtp_scenario_count"]
        == 3,
        "runtime_cleanup": off_probe["runtime_cleanup_completed"] is True
        and on_probe["runtime_cleanup_completed"] is True,
        "off_application_sync_zero": off_trace["application_owned_sync"][
            "invocations"
        ]
        == 0,
        "on_application_sync_present": on_trace["application_owned_sync"][
            "successful"
        ]
        > 0
        and on_trace["application_owned_sync"]["failed"] == 0,
        "atomic_publication_retained": off_trace[
            "application_maildir_atomic_publication"
        ]["successful"]
        > 0
        and on_trace["application_maildir_atomic_publication"]["successful"] > 0,
        "postgres_configuration_durable_and_equal": all(
            probe["postgres_before"]["settings"]
            == probe["postgres_after"]["settings"]
            == postgres_settings
            for probe in (off_probe, on_probe)
        ),
        "postgres_wal_activity": all(
            probe["postgres_wal_delta"]["wal_records"] > 0
            and probe["postgres_wal_delta"]["wal_bytes"] > 0
            for probe in (off_probe, on_probe)
        ),
        "postgres_wal_sync_present": off_trace["postgres_wal_sync"]["successful"]
        > 0
        and on_trace["postgres_wal_sync"]["successful"] > 0,
        "redis_configuration_durable_and_equal": all(
            probe["redis_before"]["configuration"]
            == probe["redis_after"]["configuration"]
            == redis_configuration
            and probe["redis_after"]["aof_enabled"] == 1
            and probe["redis_after"]["aof_pending_bio_fsync"] == 0
            and probe["redis_after"]["aof_current_size"] > 0
            and probe["redis_after"]["aof_last_write_status"] == "ok"
            for probe in (off_probe, on_probe)
        ),
        "redis_aof_sync_present": off_trace["redis_aof_sync"]["successful"] > 0
        and on_trace["redis_aof_sync"]["successful"] > 0,
        "complete_trace_syncs": off_trace["unfinished_sync_calls"] == 0
        and on_trace["unfinished_sync_calls"] == 0,
    }
    return all(checks.values()), checks


def _git_state() -> dict[str, Any]:
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPOSITORY,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=REPOSITORY,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout
    )
    return {"head": head, "dirty": dirty}


def _run_traced_probe(mode: str, root: Path) -> tuple[Path, Path]:
    trace = root / f"{mode}.trace.txt"
    result = root / f"{mode}.result.json"
    command = [
        shutil.which("strace") or "strace",
        "-f",
        "-qq",
        "-ttt",
        "-T",
        "-yy",
        "-s",
        "4096",
        "-e",
        f"trace={TRACE_SYSCALLS}",
        "-o",
        str(trace),
        sys.executable,
        str(Path(__file__).resolve()),
        "--probe-mode",
        mode,
        "--probe-result",
        str(result),
    ]
    completed = subprocess.run(
        command,
        cwd=REPOSITORY,
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"{mode} syscall probe failed with exit {completed.returncode}: "
            f"{completed.stderr[-4000:]}"
        )
    if not trace.is_file() or not result.is_file():
        raise RuntimeError(f"{mode} syscall probe did not create both artifacts")
    return trace, result


def _orchestrate(output: Path) -> None:
    output = output.resolve()
    evidence_root = (REPOSITORY / "evidence/performance").resolve()
    if output.parent != evidence_root or output.suffix != ".json":
        raise ValueError("output must be a JSON file directly under evidence/performance")
    off_destination = output.with_name(f"{output.stem}-off.trace.txt")
    on_destination = output.with_name(f"{output.stem}-on.trace.txt")
    for path in (output, off_destination, on_destination):
        if os.path.lexists(path):
            raise FileExistsError(f"evidence artifact already exists: {path}")

    with tempfile.TemporaryDirectory(prefix="lmyzmail-fsync-syscall-") as raw_root:
        root = Path(raw_root)
        off_trace_raw, off_result = _run_traced_probe("off", root)
        on_trace_raw, on_result = _run_traced_probe("on", root)
        off_probe = _load_probe(off_result, "off")
        on_probe = _load_probe(on_result, "on")
        off_trace = _trace_summary(off_trace_raw, off_probe["workspace"])
        on_trace = _trace_summary(on_trace_raw, on_probe["workspace"])
        off_trace["path"] = off_destination.relative_to(REPOSITORY).as_posix()
        on_trace["path"] = on_destination.relative_to(REPOSITORY).as_posix()
        off = {"mode": "off", "probe": off_probe, "trace": off_trace}
        on = {"mode": "on", "probe": on_probe, "trace": on_trace}
        qualification, checks = _qualified(off, on)
        if not qualification:
            failed = sorted(name for name, passed in checks.items() if not passed)
            raise RuntimeError(f"fsync syscall qualification failed: {failed}")

        _copy_exclusive(off_trace_raw, off_destination)
        try:
            _copy_exclusive(on_trace_raw, on_destination)
            evidence = {
                "schema_version": 1,
                "profile": "lmyzmail-fsync-mode-syscall-evidence-v1",
                "captured_at": _utc_now(),
                "qualification": qualification,
                "qualification_checks": checks,
                "throughput_claim_allowed": False,
                "git": _git_state(),
                "tooling": {
                    "python": sys.version.split()[0],
                    "strace": subprocess.run(
                        [shutil.which("strace") or "strace", "--version"],
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    ).stdout.splitlines()[0],
                    "trace_options": [
                        "-f",
                        "-qq",
                        "-ttt",
                        "-T",
                        "-yy",
                        "-s 4096",
                    ],
                    "trace_syscalls": TRACE_SYSCALLS.split(","),
                },
                "methodology": {
                    "external_process_tree_trace": True,
                    "smtp_modes": ["DATA", "PIPELINING", "BDAT"],
                    "application_scope": (
                        "workspace paths excluding PostgreSQL and Redis service data"
                    ),
                    "service_scope": ["PostgreSQL pg_wal", "Redis AOF"],
                    "filesystem_fsync_off_scope": (
                        "lmyzmail-owned filesystem barriers only"
                    ),
                    "atomic_publication_retained": True,
                    "database_and_cache_durability_unchanged": True,
                    "trace_is_invasive": True,
                    "not_a_throughput_measurement": True,
                },
                "arms": [off, on],
            }
            _write_exclusive(output, _canonical_bytes(evidence), 0o444)
            _fsync_directory(output.parent)
        except BaseException:
            with contextlib.suppress(OSError):
                on_destination.unlink()
            with contextlib.suppress(OSError):
                off_destination.unlink()
            raise


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--probe-mode", choices=("off", "on"), help=argparse.SUPPRESS)
    parser.add_argument("--probe-result", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    probe = args.probe_mode is not None or args.probe_result is not None
    if probe:
        if args.probe_mode is None or args.probe_result is None or args.output is not None:
            parser.error("internal probe mode requires exactly mode and result")
    elif args.output is None:
        parser.error("--output is required")
    return args


def main() -> int:
    args = _parse_args()
    if args.probe_mode is not None:
        _run_probe(args.probe_mode, args.probe_result.resolve())
    else:
        _orchestrate(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
