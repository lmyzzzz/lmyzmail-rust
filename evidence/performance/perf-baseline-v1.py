from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY / "blackbox/src"))

import httpx  # noqa: E402

from lmyzmail_blackbox.runtime import CandidateRuntime, JavaOracleRuntime  # noqa: E402


_ACTIVE_RUNTIME: Any | None = None


def _on_term(_signum: int, _frame: Any) -> None:
    if _ACTIVE_RUNTIME is not None:
        try:
            _ACTIVE_RUNTIME.stop()
        finally:
            raise SystemExit(143)
    raise SystemExit(143)


signal.signal(signal.SIGTERM, _on_term)
signal.signal(signal.SIGINT, _on_term)


def _proc_sample(pid: int) -> dict[str, int]:
    status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
    rss = next(
        int(line.split()[1])
        for line in status.splitlines()
        if line.startswith("VmRSS:")
    )
    fds = len(list(Path(f"/proc/{pid}/fd").iterdir()))
    return {"rss_kib": rss, "fd_count": fds}


def _http(port: int) -> bool:
    with httpx.Client(trust_env=False, timeout=3.0) as client:
        return client.get(f"http://127.0.0.1:{port}/api/health").status_code == 200


def _smtp(port: int) -> bool:
    with socket.create_connection(("127.0.0.1", port), timeout=3.0) as stream:
        deadline = time.monotonic() + 3.0
        greeting = b""
        while b"\r\n" not in greeting:
            if time.monotonic() >= deadline:
                return False
            chunk = stream.recv(4096)
            if not chunk:
                return False
            greeting += chunk
            if len(greeting) > 64 * 1024:
                return False
        stream.sendall(b"QUIT\r\n")
        reply = b""
        while b"\r\n" not in reply:
            if time.monotonic() >= deadline:
                return False
            chunk = stream.recv(4096)
            if not chunk:
                break
            reply += chunk
            if len(reply) > 64 * 1024:
                return False
    # The frozen Java oracle closes after QUIT without a final 221; EOF is a
    # valid completion for this bounded health probe, while Rust emits 221.
    return greeting.startswith(b"220") and (b"221" in reply or not reply)


def _terminate_process_group(pid: int) -> None:
    """Best-effort cleanup for a watchdog-triggered runtime teardown."""
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            os.killpg(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.02)
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def _run_one(
    name: str, runtime_factory: Callable[[], Any], duration: float = 20.0
) -> dict[str, Any]:
    global _ACTIVE_RUNTIME
    runtime = runtime_factory()
    _ACTIVE_RUNTIME = runtime
    started = time.monotonic()
    process_pids: tuple[int, ...] = ()
    http_ok = smtp_ok = failures = 0
    smtp_probed = False
    samples: list[dict[str, int]] = []
    try:
        runtime.start()
        startup = time.monotonic() - started
        assert runtime.ports is not None and runtime._application is not None
        pid = runtime._application.pid
        process_pids = tuple(
            process.pid
            for process in (runtime._application, runtime._redis, runtime._postgres)
            if process is not None
        )
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            for _ in range(2):
                try:
                    if _http(runtime.ports.http):
                        http_ok += 1
                    else:
                        failures += 1
                except (OSError, httpx.HTTPError):
                    failures += 1
                if not smtp_probed:
                    try:
                        if _smtp(runtime.ports.smtp):
                            smtp_ok += 1
                        else:
                            failures += 1
                    except OSError:
                        failures += 1
                    smtp_probed = True
            samples.append(_proc_sample(pid))
            time.sleep(1.0)
        return {
            "name": name,
            "status": "passed" if failures == 0 else "failed",
            "startup_seconds": round(startup, 3),
            "duration_seconds": round(time.monotonic() - started - startup, 3),
            "http_successes": http_ok,
            "smtp_successes": smtp_ok,
            "failures": failures,
            "resource": {
                "rss_min_kib": min(item["rss_kib"] for item in samples),
                "rss_max_kib": max(item["rss_kib"] for item in samples),
                "fd_min": min(item["fd_count"] for item in samples),
                "fd_max": max(item["fd_count"] for item in samples),
                "samples": len(samples),
            },
        }
    finally:
        try:
            runtime.stop()
        except (OSError, subprocess.TimeoutExpired):
            if runtime._application is not None:
                _terminate_process_group(runtime._application.pid)
            raise
        finally:
            residual = tuple(
                pid for pid in process_pids if Path(f"/proc/{pid}").exists()
            )
            if residual:
                for residual_pid in residual:
                    _terminate_process_group(residual_pid)
                raise RuntimeError(f"runtime left process groups alive: {residual}")
            _ACTIVE_RUNTIME = None


def run() -> dict[str, Any]:
    repository = REPOSITORY
    candidate = repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"
    rows = []
    rows.append(
        _run_one(
            "rust-candidate",
            lambda: CandidateRuntime(
                command_template=(str(candidate), "--config", "{config}"),
                startup_timeout=45.0,
                shutdown_timeout=5.0,
                shutdown_kill_timeout=3.0,
            ),
        )
    )
    rows.append(
        _run_one(
            "java-oracle",
            lambda: JavaOracleRuntime(
                startup_timeout=60.0,
                shutdown_timeout=5.0,
                shutdown_kill_timeout=3.0,
            ),
        )
    )
    return {
        "schema_version": 1,
        "profile": "same-host-java-rust-performance-memory-baseline-v1",
        "workload": {
            "duration_seconds": 20,
            "http_workers": 2,
            "probe_interval_seconds": 1.0,
            "http_route": "GET /api/health",
            "smtp_exchange": "greeting then QUIT",
            "smtp_probe_once": True,
            "isolated_runtime": True,
        },
        "rows": rows,
        "release_sha256": "ebc91b78f14a00b3059240f28410926918ff6e7683ee0fcbbf37d383fe741d82",
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", choices=("rust", "java", "both"), default="both")
    parser.add_argument("--duration", type=float, default=20.0)
    args = parser.parse_args()
    if args.runtime == "rust":
        result = {
            "schema_version": 1,
            "profile": "rust-candidate-performance-memory-baseline-v1",
            "rows": [
                _run_one(
                    "rust-candidate",
                    lambda: CandidateRuntime(
                        command_template=(
                            str(
                                REPOSITORY
                                / "target/x86_64-unknown-linux-gnu/release/lmyzmail"
                            ),
                            "--config",
                            "{config}",
                        ),
                        startup_timeout=45.0,
                        shutdown_timeout=5.0,
                        shutdown_kill_timeout=3.0,
                    ),
                    args.duration,
                )
            ],
        }
    elif args.runtime == "java":
        result = {
            "schema_version": 1,
            "profile": "java-oracle-performance-memory-baseline-v1",
            "rows": [
                _run_one(
                    "java-oracle",
                    lambda: JavaOracleRuntime(
                        startup_timeout=60.0,
                        shutdown_timeout=5.0,
                        shutdown_kill_timeout=3.0,
                    ),
                    args.duration,
                )
            ],
        }
    else:
        result = run()
    print(json.dumps(result, sort_keys=True, indent=2))
