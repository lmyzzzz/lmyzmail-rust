from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import socket
import statistics
import sys
import time
from pathlib import Path
from typing import Any

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY / "blackbox/src"))

import httpx  # noqa: E402

from lmyzmail_blackbox.protocols import (  # noqa: E402
    build_http_request,
    connect_bounded,
    minecraft_status,
    read_http_response,
)
from lmyzmail_blackbox.runtime import API_KEY, CandidateRuntime  # noqa: E402


def _read_line(stream: socket.socket, limit: int = 64 * 1024) -> bytes:
    value = bytearray()
    while not value.endswith(b"\r\n"):
        chunk = stream.recv(4096)
        if not chunk:
            break
        value.extend(chunk)
        if len(value) > limit:
            raise RuntimeError("line exceeded probe limit")
    return bytes(value)


def _smtp_probe(port: int) -> float:
    started = time.perf_counter()
    with socket.create_connection(("127.0.0.1", port), timeout=3.0) as stream:
        stream.settimeout(3.0)
        greeting = _read_line(stream)
        stream.sendall(b"EHLO soak.example.test\r\nQUIT\r\n")
        reply = bytearray()
        while b"221" not in reply:
            chunk = stream.recv(4096)
            if not chunk:
                break
            reply.extend(chunk)
            if len(reply) > 128 * 1024:
                raise RuntimeError("SMTP probe response exceeded limit")
        if not greeting.startswith(b"220") or b"221" not in reply:
            raise RuntimeError(f"SMTP probe failed: {greeting!r} {bytes(reply)!r}")
    return (time.perf_counter() - started) * 1000.0


def _http_probe(port: int, path: str = "/api/health") -> float:
    started = time.perf_counter()
    with httpx.Client(trust_env=False, timeout=3.0) as client:
        response = client.get(
            f"http://127.0.0.1:{port}{path}",
            headers={"X-API-Key": API_KEY} if path.startswith("/api/") else {},
        )
        if response.status_code != 200:
            raise RuntimeError(f"HTTP {path} returned {response.status_code}")
    return (time.perf_counter() - started) * 1000.0


def _http_api_status_probe(port: int) -> float:
    started = time.perf_counter()
    with httpx.Client(trust_env=False, timeout=3.0) as client:
        response = client.post(
            f"http://127.0.0.1:{port}/api/status",
            headers={"X-API-Key": API_KEY},
            json={},
        )
        if response.status_code != 200:
            raise RuntimeError(f"HTTP /api/status returned {response.status_code}")
    return (time.perf_counter() - started) * 1000.0


def _htcpcp_probe(port: int) -> float:
    started = time.perf_counter()
    stream = connect_bounded("127.0.0.1", port, timeout=3.0, max_received=128 * 1024)
    try:
        stream.sendall(build_http_request("OPTIONS", "/", host=f"127.0.0.1:{port}"))
        response = read_http_response(stream, request_method="OPTIONS")
        if response.status_code != 200:
            raise RuntimeError(f"HTCPCP OPTIONS returned {response.status_code}")
    finally:
        stream.sock.close()
    return (time.perf_counter() - started) * 1000.0


def _minecraft_status_probe(port: int) -> float:
    started = time.perf_counter()
    status = minecraft_status("127.0.0.1", port, protocol_version=47, timeout=3.0)
    version = status.get("version")
    players = status.get("players")
    if not isinstance(version, dict) or not isinstance(players, dict):
        raise RuntimeError(f"Minecraft status shape was invalid: {status!r}")
    return (time.perf_counter() - started) * 1000.0


def _allocated_bytes(root: Path) -> tuple[int, dict[str, int]]:
    total = 0
    components: dict[str, int] = {}
    for path in root.rglob("*"):
        try:
            stat = path.lstat()
        except FileNotFoundError:
            continue
        if not path.is_symlink() and path.is_file():
            allocated = stat.st_blocks * 512
            total += allocated
            relative = path.relative_to(root)
            component = relative.parts[0] if relative.parts else "."
            components[component] = components.get(component, 0) + allocated
    return total, components


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _resource_sample(
    pid: int,
    workspace: Path,
    redis_port: int,
    postgres_port: int,
    disk_baseline_bytes: int,
    workspace_baseline_bytes: int,
) -> dict[str, Any]:
    status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
    rss = next(
        int(line.split()[1])
        for line in status.splitlines()
        if line.startswith("VmRSS:")
    )
    tasks = len(list(Path(f"/proc/{pid}/task").iterdir()))
    fds = len(list(Path(f"/proc/{pid}/fd").iterdir()))
    filesystem = os.statvfs(workspace)
    disk_used_bytes = int(
        (filesystem.f_blocks - filesystem.f_bfree) * filesystem.f_frsize
    )
    workspace_bytes, workspace_components = _allocated_bytes(workspace)
    queue = 0
    try:
        import redis

        client = redis.Redis(
            host="127.0.0.1", port=redis_port, db=0, socket_timeout=1.0
        )
        try:
            queue = int(client.llen("botmail:mail:queue:pending"))
        finally:
            client.close()
    except Exception:
        queue = -1
    return {
        "rss_kib": rss,
        "fd_count": fds,
        "task_count": tasks,
        "disk_used_bytes": disk_used_bytes,
        "disk_delta_bytes": disk_used_bytes - disk_baseline_bytes,
        "workspace_bytes": workspace_bytes,
        "workspace_delta_bytes": workspace_bytes - workspace_baseline_bytes,
        "workspace_components_bytes": workspace_components,
        "queue_pending": queue,
        "postgres_port": postgres_port,
    }


def _summary(values: list[float]) -> dict[str, float]:
    if not values:
        return {"count": 0, "p50_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0}
    ordered = sorted(values)
    return {
        "count": len(values),
        "p50_ms": round(statistics.median(ordered), 3),
        "p95_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 3),
        "max_ms": round(max(ordered), 3),
    }


def run(duration_seconds: float = 1800.0, workers: int = 16) -> dict[str, Any]:
    candidate = REPOSITORY / "target/x86_64-unknown-linux-gnu/release/lmyzmail"
    runtime = CandidateRuntime(
        command_template=(str(candidate), "--config", "{config}")
    )
    successes = {"http": 0, "smtp": 0, "htcpcp": 0, "minecraft": 0}
    failures = 0
    failure_kinds: dict[str, int] = {}
    latencies: dict[str, list[float]] = {key: [] for key in successes}
    samples: list[dict[str, Any]] = []
    started = time.monotonic()
    result: dict[str, Any] | None = None
    workspace_path: Path | None = None
    managed_pids: dict[str, int] = {}
    release_sha256 = _sha256(candidate)
    try:
        runtime.start()
        assert (
            runtime.ports is not None
            and runtime.workspace is not None
            and runtime._application is not None
        )
        pid = runtime._application.pid
        ports = runtime.ports
        workspace_path = runtime.workspace
        managed_pids = {
            name: process.pid
            for name, process in {
                "candidate": runtime._application,
                "postgres": runtime._postgres,
                "redis": runtime._redis,
            }.items()
            if process is not None
        }
        filesystem = os.statvfs(runtime.workspace)
        disk_baseline_bytes = int(
            (filesystem.f_blocks - filesystem.f_bfree) * filesystem.f_frsize
        )
        workspace_baseline_bytes, _ = _allocated_bytes(runtime.workspace)

        def capture_sample() -> dict[str, Any]:
            sample = _resource_sample(
                pid,
                runtime.workspace,
                ports.redis,
                ports.postgres,
                disk_baseline_bytes,
                workspace_baseline_bytes,
            )
            sample["elapsed_millis"] = int((time.monotonic() - started) * 1000)
            return sample

        samples.append(capture_sample())
        probes = (
            ("http", lambda: _http_probe(ports.http)),
            ("http", lambda: _http_api_status_probe(ports.http)),
            ("smtp", lambda: _smtp_probe(ports.smtp)),
            ("htcpcp", lambda: _htcpcp_probe(ports.htcpcp)),
            ("minecraft", lambda: _minecraft_status_probe(ports.minecraft)),
        )
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            next_sample = time.monotonic() + 5.0
            while time.monotonic() - started < duration_seconds:
                work = [probes[index % len(probes)] for index in range(workers)]
                futures = [pool.submit(kind_probe) for _, kind_probe in work]
                for (kind, _), future in zip(work, futures, strict=True):
                    try:
                        latency = future.result(timeout=8.0)
                        successes[kind] += 1
                        latencies[kind].append(latency)
                    except Exception as error:  # noqa: BLE001
                        failures += 1
                        name = f"{kind}-{type(error).__name__}"
                        failure_kinds[name] = failure_kinds.get(name, 0) + 1
                if time.monotonic() >= next_sample:
                    samples.append(capture_sample())
                    next_sample = time.monotonic() + 5.0
        samples.append(capture_sample())
        duration = time.monotonic() - started
        steady_samples = [item for item in samples if item["elapsed_millis"] >= 60_000]
        if not steady_samples:
            steady_samples = samples[-1:]
        steady_first = steady_samples[0]
        steady_duration = max(
            (samples[-1]["elapsed_millis"] - steady_first["elapsed_millis"]) / 1000.0,
            0.001,
        )
        component_names = sorted(
            {
                name
                for sample in samples
                for name in sample["workspace_components_bytes"]
            }
        )
        result = {
            "schema_version": 1,
            "profile": "candidate-multi-module-half-hour-soak-v4",
            "duration_seconds": round(duration, 3),
            "workers": workers,
            "release_sha256": release_sha256,
            "successes": successes,
            "failures": failures,
            "failure_kinds": failure_kinds,
            "latency": {kind: _summary(values) for kind, values in latencies.items()},
            "resource": {
                "samples": len(samples),
                "rss_first_kib": samples[0]["rss_kib"],
                "rss_final_kib": samples[-1]["rss_kib"],
                "rss_delta_kib": samples[-1]["rss_kib"] - samples[0]["rss_kib"],
                "rss_min_kib": min(item["rss_kib"] for item in samples),
                "rss_max_kib": max(item["rss_kib"] for item in samples),
                "fd_first": samples[0]["fd_count"],
                "fd_final": samples[-1]["fd_count"],
                "fd_min": min(item["fd_count"] for item in samples),
                "fd_max": max(item["fd_count"] for item in samples),
                "task_first": samples[0]["task_count"],
                "task_final": samples[-1]["task_count"],
                "task_min": min(item["task_count"] for item in samples),
                "task_max": max(item["task_count"] for item in samples),
                "queue_first": samples[0]["queue_pending"],
                "queue_final": samples[-1]["queue_pending"],
                "queue_min": min(item["queue_pending"] for item in samples),
                "queue_max": max(item["queue_pending"] for item in samples),
                "disk_baseline_bytes": disk_baseline_bytes,
                "disk_used_min_bytes": min(item["disk_used_bytes"] for item in samples),
                "disk_used_max_bytes": max(item["disk_used_bytes"] for item in samples),
                "disk_delta_peak_bytes": max(
                    item["disk_delta_bytes"] for item in samples
                ),
                "disk_delta_final_bytes": samples[-1]["disk_delta_bytes"],
                "workspace_baseline_bytes": workspace_baseline_bytes,
                "workspace_used_min_bytes": min(
                    item["workspace_bytes"] for item in samples
                ),
                "workspace_used_max_bytes": max(
                    item["workspace_bytes"] for item in samples
                ),
                "workspace_delta_peak_bytes": max(
                    item["workspace_delta_bytes"] for item in samples
                ),
                "workspace_delta_final_bytes": samples[-1]["workspace_delta_bytes"],
                "steady_state_baseline_elapsed_seconds": round(
                    steady_first["elapsed_millis"] / 1000.0, 3
                ),
                "growth_per_hour": {
                    metric: round(
                        (samples[-1][field] - steady_first[field])
                        * 3600.0
                        / steady_duration,
                        3,
                    )
                    for metric, field in (
                        ("rss_kib", "rss_kib"),
                        ("fd_count", "fd_count"),
                        ("task_count", "task_count"),
                        ("workspace_bytes", "workspace_bytes"),
                    )
                },
                "workspace_components": {
                    name: {
                        "first_bytes": samples[0]["workspace_components_bytes"].get(
                            name, 0
                        ),
                        "final_bytes": samples[-1]["workspace_components_bytes"].get(
                            name, 0
                        ),
                        "min_bytes": min(
                            sample["workspace_components_bytes"].get(name, 0)
                            for sample in samples
                        ),
                        "max_bytes": max(
                            sample["workspace_components_bytes"].get(name, 0)
                            for sample in samples
                        ),
                        "steady_growth_per_hour_bytes": round(
                            (
                                samples[-1]["workspace_components_bytes"].get(name, 0)
                                - steady_first["workspace_components_bytes"].get(name, 0)
                            )
                            * 3600.0
                            / steady_duration,
                            3,
                        ),
                    }
                    for name in component_names
                },
                "samples_all": samples,
                "samples_tail": samples[-3:],
            },
        }
    finally:
        runtime.stop()
    if result is None:
        raise RuntimeError("soak completed without a result")
    residual_pids = {
        name: pid for name, pid in managed_pids.items() if Path(f"/proc/{pid}").exists()
    }
    result["cleanup"] = {
        "managed_pids": managed_pids,
        "residual_pids": residual_pids,
        "workspace_removed": workspace_path is not None and not workspace_path.exists(),
    }
    release_sha256_after = _sha256(candidate)
    result["release_sha256_after"] = release_sha256_after
    result["release_binary_unchanged"] = release_sha256_after == release_sha256
    result["status"] = (
        "passed"
        if failures == 0
        and result["resource"]["queue_min"] == 0
        and result["resource"]["queue_max"] == 0
        and not residual_pids
        and result["cleanup"]["workspace_removed"]
        and result["release_binary_unchanged"]
        else "failed"
    )
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=float, default=1800.0)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run(args.duration, args.workers)
    encoded = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
