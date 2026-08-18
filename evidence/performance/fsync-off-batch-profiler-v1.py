#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import redis


REPOSITORY = Path(__file__).resolve().parents[2]
SUPPORT_PATH = REPOSITORY / "evidence/performance/test_fsync_off_batch_persistence_v1.py"
CANDIDATE = REPOSITORY / "target/x86_64-unknown-linux-gnu/release/lmyzmail"
STRESS_PREFIX = "LMYZMAIL_STRESS_ENQUEUE_OBSERVER "
BATCH_PREFIX = "LMYZMAIL_OUTBOUND_BATCH_OBSERVER "
STRESS_SCHEMA = "lmyzmail.stress-enqueue-observation.v1"
BATCH_SCHEMA = "lmyzmail.outbound-batch-observation.v1"
SOURCE_PATHS = (
    Path("Cargo.lock"),
    Path("crates/lmyzmail/src/outbound.rs"),
    Path("crates/lmyzmail/src/outbound_batch.rs"),
    Path("crates/lmyzmail/src/stress.rs"),
    Path("crates/lmyzmail/src/stress_observer.rs"),
    Path("evidence/performance/fsync-off-batch-profiler-v1.py"),
    Path("evidence/performance/test_fsync_off_batch_persistence_v1.py"),
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _load_support() -> ModuleType:
    sys.path.insert(0, str(REPOSITORY / "blackbox/src"))
    spec = importlib.util.spec_from_file_location(
        "lmyzmail_fsync_off_batch_test_support", SUPPORT_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load benchmark support: {SUPPORT_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _bounded_multiple_of_256(value: str) -> int:
    parsed = int(value)
    if not 256 <= parsed <= 100_000 or parsed % 256 != 0:
        raise argparse.ArgumentTypeError(
            "count must be a multiple of 256 between 256 and 100000"
        )
    return parsed


def _bounded_size_kib(value: str) -> int:
    parsed = int(value)
    if not 1 <= parsed <= 10 * 1024:
        raise argparse.ArgumentTypeError("email size must be between 1 and 10240 KiB")
    return parsed


def _observations(runtime: Any, prefix: str, schema: str) -> list[dict[str, Any]]:
    application = runtime._application
    if application is None:
        raise RuntimeError("candidate application is not running")
    records: list[dict[str, Any]] = []
    for line in application.log_tail(max_bytes=8 * 1024 * 1024).splitlines():
        if prefix not in line:
            continue
        record = json.loads(line.split(prefix, maxsplit=1)[1])
        if record.get("schema") != schema:
            raise RuntimeError(f"unexpected observer schema: {record!r}")
        records.append(record)
    if not records:
        return []
    sequences = [int(record["sequence"]) for record in records]
    if sequences != sorted(set(sequences)):
        raise RuntimeError(f"non-monotonic {schema} sequence: {sequences!r}")
    return records


def _postgres_counts(support: ModuleType, runtime: Any, sender: str) -> tuple[int, ...]:
    with support._postgres(runtime) as connection:
        row = connection.execute(
            "SELECT "
            "(SELECT count(*) FROM outbound_mail_queue WHERE sender_address=%s),"
            "(SELECT count(*) FROM lmyzmail_outbound_spool s JOIN outbound_mail_queue q "
            " ON q.id=s.task_id WHERE q.sender_address=%s "
            " AND s.spool_kind='RUST' AND s.cleanup_state='OWNED'),"
            "(SELECT count(*) FROM lmyzmail_outbound_content c JOIN outbound_mail_queue q "
            " ON q.id=c.task_id WHERE q.sender_address=%s AND c.source_root='SPOOL'),"
            "(SELECT count(*) FROM email_index WHERE mailbox_address=%s AND folder='sent')",
            (sender, sender, sender, sender),
        ).fetchone()
    if row is None:
        raise RuntimeError("PostgreSQL authority count query returned no row")
    return tuple(int(value) for value in row)


def _queue_count(support: ModuleType, runtime: Any, sender: str) -> int:
    with support._postgres(runtime) as connection:
        row = connection.execute(
            "SELECT count(*) FROM outbound_mail_queue WHERE sender_address=%s",
            (sender,),
        ).fetchone()
    return 0 if row is None else int(row[0])


def _redis_pending_count(runtime: Any) -> int:
    if runtime.ports is None:
        raise RuntimeError("candidate ports are unavailable")
    client: redis.Redis = redis.Redis(
        host="127.0.0.1",
        port=runtime.ports.redis,
        db=0,
        socket_connect_timeout=1.0,
        socket_timeout=1.0,
    )
    try:
        return cast(int, client.llen("botmail:mail:queue:pending"))
    finally:
        client.close()


def _process_snapshot(pid: int) -> dict[str, int | str]:
    values: dict[str, int | str] = {}
    for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
        name, separator, raw = line.partition(":")
        if separator and name in {"VmRSS", "VmHWM", "Threads"}:
            values[name] = int(raw.strip().split()[0])
        elif separator and name == "Cpus_allowed_list":
            values[name] = raw.strip()
    values["fd_count"] = sum(1 for _ in Path(f"/proc/{pid}/fd").iterdir())
    return values


def _write_create_only(path: Path, payload: dict[str, Any]) -> str:
    path = path.resolve(strict=False)
    evidence_root = (REPOSITORY / "evidence/performance").resolve()
    if path.parent != evidence_root or path.suffix != ".json":
        raise ValueError("output must be a JSON file directly under evidence/performance")
    data = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while publishing profiler evidence")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return hashlib.sha256(data).hexdigest()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Measure the fsync-off stress foreground enqueue path with production "
            "observers. This diagnostic is not throughput qualification evidence."
        )
    )
    parser.add_argument("--count", type=_bounded_multiple_of_256, default=4096)
    parser.add_argument("--email-size-kib", type=_bounded_size_kib, default=10)
    parser.add_argument("--timeout-seconds", type=float, default=180.0)
    parser.add_argument("--candidate-cpu", type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not 30.0 <= args.timeout_seconds <= 900.0:
        parser.error("--timeout-seconds must be between 30 and 900")
    if args.candidate_cpu is not None:
        if args.candidate_cpu not in os.sched_getaffinity(0):
            parser.error("--candidate-cpu is outside this process affinity mask")
        if shutil.which("taskset") is None:
            parser.error("--candidate-cpu requires taskset")
    return args


def main() -> int:
    args = _parse_args()
    if not CANDIDATE.is_file():
        raise FileNotFoundError(f"release candidate is missing: {CANDIDATE}")
    support = _load_support()
    started_at = datetime.now(UTC)
    run_id = str(uuid.uuid4())
    workspace: Path | None = None
    if args.candidate_cpu is None:
        runtime_factory = support._runtime(
            REPOSITORY, count=args.count, email_size_kb=args.email_size_kib
        )
    else:
        runtime_factory = support._FsyncOffStressRuntime(
            command_template=(
                cast(str, shutil.which("taskset")),
                "--cpu-list",
                str(args.candidate_cpu),
                str(CANDIDATE),
                "--config",
                "{config}",
            ),
            count=args.count,
            email_size_kb=args.email_size_kib,
            shutdown_timeout=30.0,
        )
    with runtime_factory as runtime:
        workspace = runtime.workspace
        if runtime._application is None:
            raise RuntimeError("candidate process did not start")
        pid = int(runtime._application.pid)
        started_ns = time.monotonic_ns()
        support._start(runtime)
        support._wait_for(
            lambda: _queue_count(support, runtime, "stress-sender@example.test")
            == args.count,
            "all PostgreSQL queue rows",
            timeout=args.timeout_seconds,
        )
        support._wait_for(
            lambda: _redis_pending_count(runtime) == args.count,
            "all Redis pending rows",
            timeout=args.timeout_seconds,
        )
        completed_ns = time.monotonic_ns()
        stress_records = support._wait_for(
            lambda: _observations(runtime, STRESS_PREFIX, STRESS_SCHEMA),
            "stress stage observer",
            timeout=5.0,
        )
        batch_records = support._wait_for(
            lambda: _observations(runtime, BATCH_PREFIX, BATCH_SCHEMA),
            "outbound batch observer",
            timeout=5.0,
        )
        stress_last = stress_records[-1]
        batch_last = batch_records[-1]
        counts = _postgres_counts(support, runtime, "stress-sender@example.test")
        pending_ids = support._pending_ids(runtime)
        process = _process_snapshot(pid)

        if counts != (args.count,) * 4:
            raise RuntimeError(f"PostgreSQL authorities diverged: {counts!r}")
        if len(pending_ids) != args.count or len(set(pending_ids)) != args.count:
            raise RuntimeError("Redis pending identities are missing or duplicated")
        if int(stress_last["stages"]["total"]["count"]) != args.count:
            raise RuntimeError(f"incomplete stress observation: {stress_last!r}")
        if (
            int(batch_last["rows"]) != args.count
            or not 1 < int(batch_last["max_rows"]) <= 64
            or int(batch_last["batches"]) >= args.count
            or int(batch_last["uncertain_batches"]) != 0
        ):
            raise RuntimeError(f"invalid batch observation: {batch_last!r}")

        elapsed_seconds = (completed_ns - started_ns) / 1_000_000_000
        measurement = {
            "elapsed_seconds": elapsed_seconds,
            "messages_per_second": args.count / elapsed_seconds,
            "process_at_completion": process,
            "postgres_authority_counts": {
                name: value
                for name, value in zip(
                    ("queue", "spool", "content", "sent_index"), counts, strict=True
                )
            },
            "redis_pending_ids": len(pending_ids),
            "stress_observer_record_count": len(stress_records),
            "stress_observer_last": stress_last,
            "batch_observer_record_count": len(batch_records),
            "batch_observer_last": batch_last,
        }

    workspace_removed = workspace is not None and not workspace.exists()
    if not workspace_removed:
        raise RuntimeError(f"managed runtime workspace was not removed: {workspace}")
    finished_at = datetime.now(UTC)
    payload = {
        "schema": "lmyzmail.fsync-off-batch-profiler.v1",
        "run_id": run_id,
        "status": "passed",
        "qualified": False,
        "qualification_reason": (
            "enqueue-only diagnostic: delivery workers are intentionally parked and "
            "the result is not an end-to-end SMTP or Java comparison"
        ),
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "count": args.count,
        "email_size_kib": args.email_size_kib,
        "candidate_cpu": args.candidate_cpu,
        "one_original_stress_endpoint_invocation": True,
        "harness_batching": False,
        "filesystem_fsync": "off",
        "production_default_filesystem_fsync": "on",
        "workspace_removed": workspace_removed,
        "measurement": measurement,
        "attestation": {
            "candidate": {
                "path": CANDIDATE.relative_to(REPOSITORY).as_posix(),
                "sha256": _sha256(CANDIDATE),
            },
            "sources": [
                {
                    "path": relative.as_posix(),
                    "sha256": _sha256(REPOSITORY / relative),
                }
                for relative in SOURCE_PATHS
            ],
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
    }
    output_sha256 = _write_create_only(args.output, payload)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "output_sha256": output_sha256,
                "messages_per_second": measurement["messages_per_second"],
                "batch_observer_last": measurement["batch_observer_last"],
                "stress_observer_last": measurement["stress_observer_last"],
                "qualified": False,
                "status": "passed",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
