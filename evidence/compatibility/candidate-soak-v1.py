from __future__ import annotations

import concurrent.futures
import json
import socket
import time
from pathlib import Path
from typing import Any

import httpx

from lmyzmail_blackbox.runtime import CandidateRuntime


def _probe_http(port: int) -> tuple[str, int | str]:
    with httpx.Client(trust_env=False, timeout=3.0) as client:
        response = client.get(f"http://127.0.0.1:{port}/api/health")
        return ("status", response.status_code)


def _probe_smtp(port: int) -> tuple[str, int]:
    with socket.create_connection(("127.0.0.1", port), timeout=3.0) as stream:
        stream.settimeout(3.0)
        greeting = b""
        while b"\r\n" not in greeting:
            greeting += stream.recv(4096)
        stream.sendall(b"QUIT\r\n")
        farewell = b""
        while b"\r\n" not in farewell:
            farewell += stream.recv(4096)
        return ("ok", 1) if greeting.startswith(b"220") and b"221" in farewell else ("smtp", 0)


def _resource_sample(pid: int) -> dict[str, int]:
    status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
    rss = next(int(line.split()[1]) for line in status.splitlines() if line.startswith("VmRSS:"))
    return {"rss_kib": rss, "fd_count": len(list(Path(f"/proc/{pid}/fd").iterdir()))}


def run(duration_seconds: float = 45.0, workers: int = 8) -> dict[str, Any]:
    repository = Path(__file__).resolve().parents[2]
    candidate = repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"
    runtime = CandidateRuntime(command_template=(str(candidate), "--config", "{config}"))
    http_count = smtp_count = failures = 0
    failure_kinds: dict[str, int] = {}
    samples: list[dict[str, int]] = []
    started = time.monotonic()
    try:
        runtime.start()
        assert runtime.ports is not None and runtime._application is not None
        pid = runtime._application.pid
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            while time.monotonic() - started < duration_seconds:
                futures = [pool.submit(_probe_http, runtime.ports.http) for _ in range(workers)]
                for future in futures:
                    try:
                        kind, value = future.result()
                        if kind == "status" and value == 200:
                            http_count += 1
                        else:
                            failures += 1
                            key = f"http-{kind}-{value}"
                            failure_kinds[key] = failure_kinds.get(key, 0) + 1
                    except (OSError, httpx.HTTPError, concurrent.futures.TimeoutError) as error:
                        failures += 1
                        key = f"http-exception-{type(error).__name__}"
                        failure_kinds[key] = failure_kinds.get(key, 0) + 1
                try:
                    smtp_result = _probe_smtp(runtime.ports.smtp)
                    if smtp_result[0] == "ok":
                        smtp_count += 1
                    else:
                        failures += 1
                        failure_kinds["smtp-invalid"] = failure_kinds.get("smtp-invalid", 0) + 1
                except OSError as error:
                    failures += 1
                    key = f"smtp-exception-{type(error).__name__}"
                    failure_kinds[key] = failure_kinds.get(key, 0) + 1
                samples.append(_resource_sample(pid))
        return {
            "status": "passed" if failures == 0 else "failed",
            "duration_seconds": round(time.monotonic() - started, 3),
            "workers": workers,
            "http_successes": http_count,
            "smtp_successes": smtp_count,
            "failures": failures,
            "failure_kinds": failure_kinds,
            "resource": {
                "samples": len(samples),
                "rss_min_kib": min(sample["rss_kib"] for sample in samples),
                "rss_max_kib": max(sample["rss_kib"] for sample in samples),
                "fd_min": min(sample["fd_count"] for sample in samples),
                "fd_max": max(sample["fd_count"] for sample in samples),
            },
        }
    finally:
        runtime.stop()


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True, indent=2))
