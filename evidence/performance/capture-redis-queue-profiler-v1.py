#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
REDIS_ROOT = REPOSITORY / ".blackbox/runtime/redis-root"
REDIS_CLI = REDIS_ROOT / "usr/bin/redis-cli"
REDIS_LIBRARY_PATH = REDIS_ROOT / "usr/lib/x86_64-linux-gnu"
NSENTER = Path("/usr/bin/nsenter")
RUN_CGROUP = re.compile(
    r"^/lmyzmail-benchmark-root/run-"
    r"(?P<run_id>[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})"
    r"/services$"
)
QUEUE_KEYS = {
    "pending": ("LLEN", "botmail:mail:queue:pending"),
    "processing": ("SCARD", "botmail:mail:queue:processing"),
    "retry": ("ZCARD", "botmail:mail:queue:retry"),
}


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def process_start_time(pid: int) -> int:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    fields = raw[raw.rfind(")") + 2 :].split()
    if len(fields) <= 19:
        raise RuntimeError("process stat is truncated")
    return int(fields[19])


def process_cgroup(pid: int) -> str:
    for line in Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii").splitlines():
        if line.startswith("0::"):
            return line[3:]
    raise RuntimeError("process has no unified cgroup")


def process_arguments(pid: int) -> list[str]:
    raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    return [part.decode("utf-8", errors="surrogateescape") for part in raw.split(b"\0") if part]


def redis_port(arguments: list[str]) -> int:
    try:
        index = arguments.index("--port")
        port = int(arguments[index + 1])
    except (ValueError, IndexError):
        rewritten = re.fullmatch(r".+:(?P<port>[0-9]+)", arguments[-1])
        if rewritten is None:
            raise RuntimeError("Redis command line omitted a listening port")
        port = int(rewritten.group("port"))
    if not 1 <= port <= 65_535:
        raise RuntimeError("Redis command line contains an invalid port")
    return port


def discover_redis(deadline: float) -> tuple[int, int, str, int]:
    while time.monotonic() < deadline:
        matches: list[tuple[int, int, str, int]] = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            try:
                arguments = process_arguments(pid)
                cgroup = process_cgroup(pid)
                cgroup_match = RUN_CGROUP.fullmatch(cgroup)
                if (
                    not arguments
                    or "redis-server" not in Path(arguments[0]).name
                    or cgroup_match is None
                ):
                    continue
                matches.append(
                    (
                        pid,
                        process_start_time(pid),
                        cgroup_match.group("run_id"),
                        redis_port(arguments),
                    )
                )
            except (FileNotFoundError, PermissionError, ProcessLookupError, RuntimeError):
                continue
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise RuntimeError(f"multiple benchmark Redis processes are active: {matches!r}")
        time.sleep(0.1)
    raise RuntimeError("timed out waiting for the benchmark Redis process")


def redis_json(pid: int, port: int, *command: str) -> Any:
    return json.loads(redis_cli(pid, port, "--json", *command))


def redis_cli(pid: int, port: int, output_mode: str, *command: str) -> str:
    completed = subprocess.run(
        [
            str(NSENTER),
            "-t",
            str(pid),
            "-n",
            "/usr/bin/env",
            f"LD_LIBRARY_PATH={REDIS_LIBRARY_PATH}",
            str(REDIS_CLI),
            "-h",
            "127.0.0.1",
            "-p",
            str(port),
            output_mode,
            *command,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=2.0,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"redis-cli exited with {completed.returncode}: {completed.stderr.strip()}"
        )
    return completed.stdout


def parse_info(raw: str) -> dict[str, Any]:
    selected: dict[str, Any] = {}
    commands: dict[str, dict[str, int | float]] = {}
    latency: dict[str, dict[str, int | float]] = {}
    for line in raw.splitlines():
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.startswith("cmdstat_") or key.startswith("latency_percentiles_usec_"):
            fields: dict[str, int | float] = {}
            for part in value.split(","):
                name, raw_value = part.split("=", 1)
                fields[name] = float(raw_value) if "." in raw_value else int(raw_value)
            destination = commands if key.startswith("cmdstat_") else latency
            destination[key] = fields
        elif key in {
            "redis_version",
            "instantaneous_ops_per_sec",
            "total_commands_processed",
            "rejected_connections",
            "expired_keys",
            "evicted_keys",
            "used_memory",
            "used_memory_peak",
            "connected_clients",
            "blocked_clients",
            "total_error_replies",
            "used_cpu_sys",
            "used_cpu_user",
        }:
            if value.replace(".", "", 1).isdigit():
                selected[key] = float(value) if "." in value else int(value)
            else:
                selected[key] = value
    selected["commandstats"] = commands
    selected["latencystats"] = latency
    return selected


def sample(pid: int, start_time: int, port: int, started: float) -> dict[str, Any]:
    if process_start_time(pid) != start_time:
        raise ProcessLookupError("Redis PID identity changed")
    record: dict[str, Any] = {
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "captured_at": utc_now(),
    }
    errors: list[str] = []
    try:
        info = redis_cli(pid, port, "--raw", "INFO", "ALL")
        record["info"] = parse_info(info)
    except (json.JSONDecodeError, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        errors.append(f"info:{type(error).__name__}:{error}")
    depths: dict[str, int] = {}
    for name, command in QUEUE_KEYS.items():
        try:
            value = redis_json(pid, port, *command)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise RuntimeError(f"invalid {name} depth: {value!r}")
            depths[name] = value
        except (json.JSONDecodeError, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            errors.append(f"{name}:{type(error).__name__}:{error}")
    record["queue_depth"] = depths
    try:
        record["latency_latest"] = redis_json(pid, port, "LATENCY", "LATEST")
    except (json.JSONDecodeError, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        errors.append(f"latency:{type(error).__name__}:{error}")
    if errors:
        record["errors"] = errors
    return record


def write_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--discovery-timeout", type=float, default=180.0)
    parser.add_argument("--duration", type=float, default=180.0)
    parser.add_argument("--interval", type=float, default=1.0)
    arguments = parser.parse_args()
    if arguments.discovery_timeout <= 0 or arguments.duration <= 0:
        parser.error("timeouts must be positive")
    if not 0.1 <= arguments.interval <= 60.0:
        parser.error("interval must be between 0.1 and 60 seconds")
    output = arguments.output.resolve()
    evidence_root = (REPOSITORY / "evidence/performance").resolve()
    if output.parent != evidence_root or output.suffix != ".json" or output.exists():
        parser.error("output must be a new JSON file directly under evidence/performance")
    arguments.output = output
    return arguments


def main() -> int:
    arguments = parse_arguments()
    if os.geteuid() != 0:
        raise SystemExit("capture must run as root for network namespace access")
    if not REDIS_CLI.is_file() or not NSENTER.is_file():
        raise SystemExit("pinned redis-cli or nsenter is unavailable")

    capture_started = time.monotonic()
    pid, start_time, run_id, port = discover_redis(
        capture_started + arguments.discovery_timeout
    )
    started_at = utc_now()
    metadata: dict[str, Any] = {}
    for name in ("slowlog-log-slower-than", "slowlog-max-len", "latency-monitor-threshold"):
        try:
            metadata[name] = redis_json(pid, port, "CONFIG", "GET", name)
        except (json.JSONDecodeError, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            metadata[name] = {"error": f"{type(error).__name__}:{error}"}

    samples: list[dict[str, Any]] = []
    slowlog: dict[int, Any] = {}
    status = "duration-complete"
    sampling_started = time.monotonic()
    deadline = sampling_started + arguments.duration
    while time.monotonic() < deadline:
        try:
            samples.append(sample(pid, start_time, port, sampling_started))
            entries = redis_json(pid, port, "SLOWLOG", "GET", "128")
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, list) and entry and isinstance(entry[0], int):
                        slowlog[entry[0]] = entry
        except (FileNotFoundError, ProcessLookupError):
            status = "redis-exited"
            break
        except (json.JSONDecodeError, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            samples.append(
                {
                    "elapsed_seconds": round(time.monotonic() - sampling_started, 6),
                    "captured_at": utc_now(),
                    "errors": [f"sample:{type(error).__name__}:{error}"],
                }
            )
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(arguments.interval, remaining))

    value = {
        "schema_version": 1,
        "profile": "lmyzmail-redis-queue-profiler-v1",
        "run_id": run_id,
        "redis_pid": pid,
        "redis_start_time_ticks": start_time,
        "redis_port": port,
        "started_at": started_at,
        "completed_at": utc_now(),
        "status": status,
        "read_only_capture": True,
        "sampling_interval_seconds": arguments.interval,
        "redis_configuration": metadata,
        "samples": samples,
        "slowlog_entries": [slowlog[key] for key in sorted(slowlog, reverse=True)],
    }
    write_atomic(arguments.output, value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
