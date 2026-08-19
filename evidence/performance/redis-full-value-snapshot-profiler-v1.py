from __future__ import annotations

import argparse
import gc
import hashlib
import importlib.util
import json
import os
import resource
import socket
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
V2_SOURCE = REPOSITORY / "evidence/compatibility/smtp-self-stress-v2.py"
REDIS_ROOT = REPOSITORY / ".blackbox/runtime/redis-root"
REDIS_SERVER = REDIS_ROOT / "usr/bin/redis-server"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _current_rss_bytes() -> int:
    fields = Path("/proc/self/statm").read_text(encoding="ascii").split()
    if len(fields) < 2:
        raise RuntimeError("could not read profiler RSS from /proc/self/statm")
    return int(fields[1]) * os.sysconf("SC_PAGE_SIZE")


def _load_v2() -> Any:
    specification = importlib.util.spec_from_file_location(
        "redis_snapshot_profiler_v1_support", V2_SOURCE
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("could not load the Redis snapshot implementation")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_for_redis(client: Any, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Redis exited during startup: {process.returncode}")
        try:
            if client.ping() is True:
                return
        except Exception:
            pass
        time.sleep(0.02)
    raise TimeoutError("Redis did not become ready")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keys", type=int, default=32_768)
    parser.add_argument("--value-bytes", type=int, default=128)
    parser.add_argument("--maximum-rss-growth-mib", type=int, default=192)
    parser.add_argument(
        "--output",
        type=Path,
        default=REPOSITORY
        / "evidence/performance/redis-full-value-snapshot-profiler-v1.json",
    )
    arguments = parser.parse_args()
    if not 1 <= arguments.keys <= 1_000_000:
        parser.error("--keys must be between 1 and 1000000")
    if not 1 <= arguments.value_bytes <= 1024 * 1024:
        parser.error("--value-bytes must be between 1 and 1048576")
    if not 16 <= arguments.maximum_rss_growth_mib <= 4096:
        parser.error("--maximum-rss-growth-mib must be between 16 and 4096")
    return arguments


def main() -> int:
    arguments = _parse_args()
    output = arguments.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    v2 = _load_v2()
    if not REDIS_SERVER.exists():
        raise RuntimeError(f"bundled black-box Redis is missing: {REDIS_SERVER}")
    port = _free_port()
    started_at = _utc_now()
    with tempfile.TemporaryDirectory(prefix="lmyzmail-redis-snapshot-") as temporary:
        root = Path(temporary)
        process = subprocess.Popen(
            [
                str(REDIS_SERVER),
                "--bind",
                "127.0.0.1",
                "--port",
                str(port),
                "--save",
                "",
                "--appendonly",
                "no",
                "--dir",
                str(root),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={
                **os.environ,
                "LD_LIBRARY_PATH": str(REDIS_ROOT / "usr/lib/x86_64-linux-gnu"),
            },
        )
        client = v2.base.redis.Redis(
            host="127.0.0.1",
            port=port,
            db=0,
            socket_connect_timeout=1.0,
            socket_timeout=30.0,
        )
        try:
            _wait_for_redis(client, process)
            value = b"x" * arguments.value_bytes
            for offset in range(0, arguments.keys, 1024):
                pipeline = client.pipeline(transaction=False)
                for index in range(offset, min(arguments.keys, offset + 1024)):
                    pipeline.set(f"botmail:mail:queue:task:{index}", value)
                pipeline.execute()
            gc.collect()
            rss_before_snapshot_bytes = _current_rss_bytes()
            snapshot_started = time.monotonic()
            snapshot = v2._redis_snapshot(
                SimpleNamespace(ports=SimpleNamespace(redis=port))
            )
            elapsed_seconds = time.monotonic() - snapshot_started
            gc.collect()
            rss_after_snapshot_bytes = _current_rss_bytes()
            peak_rss_bytes = int(
                resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
            )
        finally:
            try:
                client.shutdown(nosave=True)
            except Exception:
                pass
            client.close()
            try:
                process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=5.0)

    expected_value_bytes = arguments.keys * arguments.value_bytes
    actual_value_bytes = sum(record["value_bytes"] for record in snapshot["keys"])
    maximum_rss_growth_bytes = arguments.maximum_rss_growth_mib * 1024 * 1024
    observed_rss_growth_bytes = max(
        0, peak_rss_bytes - rss_before_snapshot_bytes
    )
    passed = bool(
        snapshot["scan_complete_and_stable"] is True
        and snapshot["key_count"] == arguments.keys
        and actual_value_bytes == expected_value_bytes
        and all(record["cardinality"] == 1 for record in snapshot["keys"])
        and observed_rss_growth_bytes <= maximum_rss_growth_bytes
    )
    evidence = {
        "schema": "lmyzmail.redis-full-value-snapshot-profiler.v1",
        "status": "passed" if passed else "failed",
        "qualified": False,
        "qualification_reason": (
            "focused harness diagnostic; not an SMTP throughput qualification"
        ),
        "started_at": started_at,
        "finished_at": _utc_now(),
        "keys": arguments.keys,
        "value_bytes_per_key": arguments.value_bytes,
        "expected_value_bytes": expected_value_bytes,
        "actual_value_bytes": actual_value_bytes,
        "rss_before_snapshot_bytes": rss_before_snapshot_bytes,
        "rss_after_snapshot_bytes": rss_after_snapshot_bytes,
        "peak_rss_bytes": peak_rss_bytes,
        "observed_rss_growth_bytes": observed_rss_growth_bytes,
        "maximum_rss_growth_bytes": maximum_rss_growth_bytes,
        "rss_growth_is_bounded_independently_of_cumulative_value_bytes": (
            observed_rss_growth_bytes <= maximum_rss_growth_bytes
        ),
        "elapsed_seconds": round(elapsed_seconds, 6),
        "keys_per_second": round(arguments.keys / elapsed_seconds, 6),
        "pipeline_key_limit": v2.REDIS_SNAPSHOT_PIPELINE_KEY_LIMIT,
        "scan_complete_and_stable": snapshot["scan_complete_and_stable"],
        "snapshot_sha256": snapshot["snapshot_sha256"],
        "sources": {
            str(V2_SOURCE.relative_to(REPOSITORY)): _sha256_file(V2_SOURCE),
            str(Path(__file__).resolve().relative_to(REPOSITORY)): _sha256_file(
                Path(__file__).resolve()
            ),
            str(REDIS_SERVER.relative_to(REPOSITORY)): _sha256_file(REDIS_SERVER),
        },
        "temporary_workspace_removed": True,
    }
    encoded = json.dumps(evidence, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    try:
        with output.open("xb") as stream:
            stream.write(encoded)
    except FileExistsError as error:
        raise RuntimeError(f"refusing to overwrite existing evidence: {output}") from error
    print(
        json.dumps(
            {
                "status": evidence["status"],
                "keys": evidence["keys"],
                "keys_per_second": evidence["keys_per_second"],
                "output": str(output.relative_to(REPOSITORY)),
                "output_sha256": hashlib.sha256(encoded).hexdigest(),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
