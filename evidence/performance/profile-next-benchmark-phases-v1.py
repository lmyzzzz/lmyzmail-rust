#!/usr/bin/env python3
"""Capture progress-aligned CPU, wait, I/O, and inode benchmark evidence."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


REPOSITORY = Path(__file__).resolve().parents[2]
DEFAULT_CANDIDATE = (
    REPOSITORY
    / "target/profiling/x86_64-unknown-linux-gnu/release-with-debug/lmyzmail"
)
DEFAULT_RUNTIME_ROOT = Path("/run/lmyzmail-benchmark-root/mounts")
MAX_CONTROL_BYTES = 64 * 1024
MAX_TREE_DIRECTORIES = 200_000
MAX_WCHAN_NAMES = 128
PERF_EXIT_SECONDS = 20.0


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    start_time_ticks: int
    executable_device: int
    executable_inode: int


@dataclass(frozen=True)
class ProgressWindow:
    name: str
    start_fraction: float
    end_fraction: float

    def thresholds(self, expected: int) -> tuple[int, int]:
        if expected <= 0:
            raise ValueError("expected message count must be positive")
        if not 0 <= self.start_fraction < self.end_fraction <= 1:
            raise ValueError("progress window fractions are invalid")
        start = math.ceil(expected * self.start_fraction)
        end = math.ceil(expected * self.end_fraction)
        if start >= end:
            raise ValueError("progress window is empty at this message count")
        return start, end


WINDOWS = (
    ProgressWindow("early", 0.05, 0.25),
    ProgressWindow("late", 0.75, 0.95),
)


def _read(path: Path, maximum: int = 1024 * 1024) -> str:
    with path.open("rb") as stream:
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise RuntimeError(f"bounded read exceeded for {path}")
    return value.decode("utf-8", errors="replace")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _identity(pid: int) -> ProcessIdentity:
    fields = _read(Path(f"/proc/{pid}/stat"), 64 * 1024).split()
    if len(fields) < 22:
        raise RuntimeError(f"process stat is truncated for PID {pid}")
    executable = Path(f"/proc/{pid}/exe").stat()
    return ProcessIdentity(pid, int(fields[21]), executable.st_dev, executable.st_ino)


def _alive(value: ProcessIdentity) -> bool:
    try:
        return _identity(value.pid) == value
    except (FileNotFoundError, PermissionError, ProcessLookupError, RuntimeError):
        return False


def _candidate_matches(candidate: Path) -> list[ProcessIdentity]:
    metadata = candidate.stat()
    matches = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            executable = (entry / "exe").stat()
            if (executable.st_dev, executable.st_ino) == (
                metadata.st_dev,
                metadata.st_ino,
            ):
                matches.append(_identity(int(entry.name)))
        except (FileNotFoundError, PermissionError, ProcessLookupError, RuntimeError):
            continue
    return sorted(matches, key=lambda item: (item.start_time_ticks, item.pid))


def _wait_candidate(candidate: Path, deadline: float) -> ProcessIdentity:
    while time.monotonic() < deadline:
        matches = _candidate_matches(candidate)
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise RuntimeError("more than one profiling candidate is running")
        time.sleep(0.1)
    raise TimeoutError("profiling candidate did not start before the deadline")


def _proxy_command(path: Path) -> dict[str, Any]:
    payload = b'{"command":"summary"}\n'
    metadata = path.lstat()
    original_uid = os.geteuid()
    original_gid = os.getegid()
    switch_identity = original_uid == 0 and metadata.st_uid != 0
    if switch_identity:
        os.setegid(metadata.st_gid)
        os.seteuid(metadata.st_uid)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2.0)
            connection.connect(str(path))
            connection.sendall(payload)
            response = bytearray()
            while b"\n" not in response:
                chunk = connection.recv(MAX_CONTROL_BYTES + 1 - len(response))
                if not chunk:
                    raise RuntimeError("proxy control closed without a response")
                response.extend(chunk)
                if len(response) > MAX_CONTROL_BYTES:
                    raise RuntimeError("proxy control response exceeded its bound")
    finally:
        if switch_identity:
            os.seteuid(original_uid)
            os.setegid(original_gid)
    value = json.loads(bytes(response).split(b"\n", 1)[0])
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise RuntimeError("proxy control returned an invalid summary")
    return value


def _progress(control: Path) -> dict[str, int]:
    round_value = _proxy_command(control).get("round")
    if not isinstance(round_value, dict):
        raise RuntimeError("proxy summary omitted active round evidence")
    value = {
        "expected": int(round_value["expected"]),
        "verified": int(round_value["verified"]),
        "duration_ns": int(round_value.get("progress_duration_ns") or 0),
        "observer_failures": int(round_value.get("observer_failure_count", 0)),
    }
    if not 0 <= value["verified"] <= value["expected"]:
        raise RuntimeError("proxy progress escaped its expected range")
    return value


def _wait_proxy(runtime_root: Path, deadline: float) -> tuple[Path, dict[str, int]]:
    while time.monotonic() < deadline:
        active = []
        if runtime_root.is_dir():
            for mount in runtime_root.iterdir():
                control = mount / "p.sock"
                try:
                    if stat.S_ISSOCK(control.lstat().st_mode):
                        value = _progress(control)
                        if value["expected"] > 0:
                            active.append((control, value))
                except (FileNotFoundError, OSError, ValueError, RuntimeError):
                    continue
        if len(active) == 1:
            return active[0]
        if len(active) > 1:
            raise RuntimeError("more than one active benchmark proxy was found")
        time.sleep(0.1)
    raise TimeoutError("active benchmark proxy did not appear before the deadline")


def _key_values(value: str) -> dict[str, int]:
    output = {}
    for line in value.splitlines():
        fields = line.replace(":", " ", 1).split()
        if len(fields) >= 2 and fields[1].lstrip("-").isdecimal():
            output[fields[0]] = int(fields[1])
    return output


def _pressure(value: str) -> dict[str, dict[str, float | int]]:
    output = {}
    for line in value.splitlines():
        fields = line.split()
        row: dict[str, float | int] = {}
        for field in fields[1:]:
            key, separator, raw = field.partition("=")
            if separator:
                row[key] = int(raw) if key == "total" else float(raw)
        if fields:
            output[fields[0]] = row
    return output


def _process_io(pid: int) -> dict[str, int]:
    try:
        return _key_values(_read(Path(f"/proc/{pid}/io"), 64 * 1024))
    except (FileNotFoundError, PermissionError):
        return {}


def _thread_waits(pid: int) -> dict[str, Any]:
    waits: collections.Counter[str] = collections.Counter()
    run_ns = wait_ns = slices = tasks = 0
    try:
        entries = list(Path(f"/proc/{pid}/task").iterdir())
    except (FileNotFoundError, PermissionError):
        entries = []
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        try:
            waits[_read(entry / "wchan", 4096).strip() or "running"] += 1
            fields = _read(entry / "schedstat", 4096).split()
            tasks += 1
            if len(fields) >= 3:
                run_ns += int(fields[0])
                wait_ns += int(fields[1])
                slices += int(fields[2])
        except (FileNotFoundError, PermissionError, ValueError):
            continue
    return {
        "tasks": tasks,
        "wchan": dict(waits.most_common(MAX_WCHAN_NAMES)),
        "schedstat_run_ns": run_ns,
        "schedstat_wait_ns": wait_ns,
        "schedstat_slices": slices,
    }


def _postgres_process_table() -> dict[int, dict[str, Any]]:
    table: dict[int, dict[str, Any]] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            pid = int(entry.name)
            command = (entry / "cmdline").read_bytes().replace(b"\0", b" ").strip()
            status = _key_values(_read(entry / "status", 64 * 1024))
            table[pid] = {
                "command": command.decode("utf-8", errors="replace"),
                "ppid": status.get("PPid", 0),
                "rss_kib": status.get("VmRSS", 0),
            }
        except (FileNotFoundError, PermissionError):
            continue
    return table


def _postgres_masters(table: dict[int, dict[str, Any]]) -> list[int]:
    return sorted(
        pid
        for pid, value in table.items()
        if "postgres-data" in value["command"]
        and re.search(r"(?:^|/)postgres(?:\s|$)", value["command"])
    )


def _postgres_processes() -> dict[str, Any]:
    waits: collections.Counter[str] = collections.Counter()
    io: collections.Counter[str] = collections.Counter()
    rss_kib = processes = 0
    table = _postgres_process_table()
    masters = set(_postgres_masters(table))
    commands: collections.Counter[str] = collections.Counter()
    for pid, value in table.items():
        if pid not in masters and value["ppid"] not in masters:
            continue
        try:
            processes += 1
            command = value["command"]
            role = command.split(":", 1)[1].strip().split(maxsplit=1)[0] if ":" in command else "master"
            commands[role] += 1
            waits[_read(Path(f"/proc/{pid}/wchan"), 4096).strip() or "running"] += 1
            rss_kib += value["rss_kib"]
            io.update(_process_io(pid))
        except (FileNotFoundError, PermissionError):
            continue
    return {
        "masters": sorted(masters),
        "processes": processes,
        "rss_kib": rss_kib,
        "roles": dict(commands),
        "wchan": dict(waits.most_common(MAX_WCHAN_NAMES)),
        "io": dict(io),
    }


def _postgres_sql_snapshot() -> dict[str, Any]:
    table = _postgres_process_table()
    masters = _postgres_masters(table)
    if len(masters) != 1:
        return {"available": False, "reason": f"postgres_masters={masters}"}
    command = table[masters[0]]["command"].split()
    try:
        port = int(command[command.index("-p") + 1])
    except (ValueError, IndexError):
        return {"available": False, "reason": "postgres_port_unavailable"}
    try:
        import psycopg

        connection = psycopg.connect(
            host="127.0.0.1",
            port=port,
            user="lmyzmail_test",
            dbname="lmyzmail",
            connect_timeout=2,
            options="-c default_transaction_read_only=on -c statement_timeout=1000",
        )
        connection.autocommit = True
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT backend_type,COALESCE(state,''),"
                "COALESCE(wait_event_type,''),COALESCE(wait_event,''),count(*) "
                "FROM pg_stat_activity GROUP BY 1,2,3,4 ORDER BY 1,2,3,4"
            )
            activity = [
                {
                    "backend_type": row[0],
                    "state": row[1],
                    "wait_event_type": row[2],
                    "wait_event": row[3],
                    "count": row[4],
                }
                for row in cursor.fetchall()
            ]
            snapshots: dict[str, Any] = {}
            for name, query in (
                (
                    "database",
                    "SELECT row_to_json(s)::text FROM (SELECT numbackends,xact_commit,"
                    "xact_rollback,blks_read,blks_hit,temp_files,temp_bytes,deadlocks,"
                    "blk_read_time,blk_write_time,session_time,active_time,idle_in_transaction_time,"
                    "sessions,sessions_abandoned,sessions_fatal,sessions_killed,stats_reset "
                    "FROM pg_stat_database WHERE datname=current_database()) s",
                ),
                ("wal", "SELECT row_to_json(s)::text FROM pg_stat_wal s"),
                ("bgwriter", "SELECT row_to_json(s)::text FROM pg_stat_bgwriter s"),
            ):
                cursor.execute(query)
                row = cursor.fetchone()
                snapshots[name] = json.loads(row[0]) if row and row[0] else None
        connection.close()
        return {
            "available": True,
            "master_pid": masters[0],
            "port": port,
            "activity": activity,
            **snapshots,
        }
    except BaseException as error:
        return {
            "available": False,
            "master_pid": masters[0],
            "port": port,
            "reason": f"{type(error).__name__}: {error}",
        }


def _cgroup(identity: ProcessIdentity) -> Path | None:
    for line in _read(Path(f"/proc/{identity.pid}/cgroup"), 64 * 1024).splitlines():
        hierarchy, controllers, relative = line.split(":", 2)
        if hierarchy == "0" and not controllers:
            value = Path("/sys/fs/cgroup") / relative.lstrip("/")
            return value if value.is_dir() else None
    return None


def _filesystem(workspace: Path) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for name, path in {
        "maildir": workspace / "maildir",
        "outbound_spool": workspace / "maildir/.lmyzmail-outbound",
        "stress_temp": workspace / "maildir/.lmyzmail-stress",
    }.items():
        started = time.monotonic_ns()
        try:
            entries = sum(1 for _ in os.scandir(path))
            metadata = path.stat()
            output[name] = {
                "exists": True,
                "direct_entries": entries,
                "enumeration_ns": time.monotonic_ns() - started,
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
            }
        except FileNotFoundError:
            output[name] = {
                "exists": False,
                "direct_entries": 0,
                "enumeration_ns": time.monotonic_ns() - started,
            }
    values = os.statvfs(workspace)
    output["statvfs"] = {
        "block_size": values.f_frsize,
        "blocks_free": values.f_bfree,
        "inodes": values.f_files,
        "inodes_free": values.f_ffree,
    }
    return output


def _tree(root: Path) -> dict[str, Any]:
    started = time.monotonic_ns()
    files = directories = symlinks = vanished = logical = allocated = 0
    maximum_entries = 0
    maximum_path = None
    stack = [root]
    while stack:
        directory = stack.pop()
        directories += 1
        if directories > MAX_TREE_DIRECTORIES:
            raise RuntimeError("tree snapshot exceeded its directory bound")
        try:
            entries = list(os.scandir(directory))
        except FileNotFoundError:
            continue
        if len(entries) > maximum_entries:
            maximum_entries = len(entries)
            maximum_path = str(directory.relative_to(root)) or "."
        for entry in entries:
            try:
                metadata = entry.stat(follow_symlinks=False)
            except FileNotFoundError:
                vanished += 1
                continue
            if stat.S_ISLNK(metadata.st_mode):
                symlinks += 1
            elif stat.S_ISDIR(metadata.st_mode):
                stack.append(Path(entry.path))
            elif stat.S_ISREG(metadata.st_mode):
                files += 1
                logical += metadata.st_size
                allocated += metadata.st_blocks * 512
    return {
        "files": files,
        "directories": directories,
        "symlinks": symlinks,
        "vanished_entries": vanished,
        "logical_bytes": logical,
        "allocated_bytes": allocated,
        "maximum_direct_entries": maximum_entries,
        "maximum_direct_entries_path": maximum_path,
        "duration_ns": time.monotonic_ns() - started,
    }


def _sample(identity: ProcessIdentity, control: Path, workspace: Path) -> dict[str, Any]:
    pid = identity.pid
    value: dict[str, Any] = {
        "monotonic_ns": time.monotonic_ns(),
        "progress": _progress(control),
        "candidate": {
            "status": _key_values(_read(Path(f"/proc/{pid}/status"), 64 * 1024)),
            "io": _process_io(pid),
            "fd_count": sum(1 for _ in Path(f"/proc/{pid}/fd").iterdir()),
            "threads": _thread_waits(pid),
        },
        "postgres": _postgres_processes(),
        "filesystem": _filesystem(workspace),
        "pressure": {
            name: _pressure(_read(Path("/proc/pressure") / name, 64 * 1024))
            for name in ("cpu", "io", "memory")
        },
    }
    cgroup = _cgroup(identity)
    if cgroup is not None:
        cgroup_value: dict[str, Any] = {"path": str(cgroup)}
        for name in ("cpu.pressure", "io.pressure", "memory.pressure"):
            path = cgroup / name
            if path.is_file():
                cgroup_value[name] = _pressure(_read(path, 64 * 1024))
        for name in ("cpu.stat", "io.stat", "memory.events"):
            path = cgroup / name
            if path.is_file():
                cgroup_value[name] = _read(path, 256 * 1024).strip()
        for name in ("memory.current", "memory.peak", "pids.current"):
            path = cgroup / name
            if path.is_file():
                cgroup_value[name] = int(_read(path, 4096).strip())
        value["cgroup"] = cgroup_value
    return value


def _perf(explicit: Path | None) -> Path:
    if explicit is not None:
        value = explicit.resolve(strict=True)
        if not os.access(value, os.X_OK):
            raise RuntimeError("explicit perf binary is not executable")
        return value
    for value in reversed(sorted(Path("/usr/lib/linux-tools").glob("*/perf"))):
        if value.is_file() and os.access(value, os.X_OK):
            return value
    raise RuntimeError("a real perf binary is required")


def _fold(lines: Iterable[str]) -> collections.Counter[str]:
    output: collections.Counter[str] = collections.Counter()
    frames: list[str] = []
    pattern = re.compile(r"^\s*[0-9a-f]+\s+(.+?)(?:\s+\([^)]*\))?\s*$")

    def flush() -> None:
        if frames:
            output[";".join(reversed(frames))] += 1
            frames.clear()

    for raw in lines:
        line = raw.rstrip("\n")
        if not line.strip():
            flush()
            continue
        matched = pattern.match(line)
        if matched:
            frames.append(matched.group(1).strip())
    flush()
    return output


def _perf_views(perf: Path, data: Path, directory: Path) -> dict[str, Any]:
    stacks = directory / "perf.stacks.txt"
    with stacks.open("xb") as output:
        completed = subprocess.run(
            [str(perf), "script", "--header", "-i", str(data)],
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.PIPE,
            check=False,
        )
    if completed.returncode:
        raise RuntimeError(completed.stderr.decode(errors="replace")[-4096:])
    folded = _fold(stacks.read_text(encoding="utf-8", errors="replace").splitlines())
    if not folded:
        raise RuntimeError("perf window produced no callchain samples")
    folded_path = directory / "perf.folded.txt"
    with folded_path.open("x", encoding="utf-8", newline="\n") as output:
        for stack, count in sorted(folded.items(), key=lambda item: (-item[1], item[0])):
            output.write(f"{stack} {count}\n")
    return {
        "perf_data_sha256": _sha256(data),
        "perf_data_bytes": data.stat().st_size,
        "stack_samples": sum(folded.values()),
        "unique_stacks": len(folded),
        "stacks_sha256": _sha256(stacks),
        "folded_sha256": _sha256(folded_path),
    }


def _wait_threshold(
    identity: ProcessIdentity,
    control: Path,
    expected: int,
    threshold: int,
    deadline: float,
) -> dict[str, int]:
    while time.monotonic() < deadline:
        if not _alive(identity):
            raise RuntimeError("candidate identity changed before a profiler window")
        value = _progress(control)
        if value["expected"] != expected or value["observer_failures"]:
            raise RuntimeError("proxy contract changed during profiling")
        if value["verified"] >= threshold:
            return value
        time.sleep(0.1)
    raise TimeoutError(f"message threshold {threshold} was not reached")


def _stop_perf(process: subprocess.Popen[bytes]) -> tuple[int, str]:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    try:
        _, stderr = process.communicate(timeout=PERF_EXIT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=PERF_EXIT_SECONDS)
        raise RuntimeError("perf record did not stop after SIGINT")
    return process.returncode, stderr.decode(errors="replace")[-16 * 1024 :]


def _capture(
    identity: ProcessIdentity,
    control: Path,
    workspace: Path,
    perf: Path,
    output: Path,
    window: ProgressWindow,
    expected: int,
    sample_interval: float,
    deadline: float,
    maximum_window: float,
    frequency: int,
) -> dict[str, Any]:
    start_threshold, end_threshold = window.thresholds(expected)
    reached = _wait_threshold(identity, control, expected, start_threshold, deadline)
    if reached["verified"] >= end_threshold:
        raise RuntimeError(f"{window.name} profiler window was already passed")
    directory = output / window.name
    directory.mkdir(mode=0o755)
    data = directory / "perf.data"
    samples_path = directory / "samples.jsonl"
    before = _sample(identity, control, workspace)
    postgres_sql_before = _postgres_sql_snapshot()
    tree_before = _tree(workspace / "maildir")
    command = [
        str(perf), "record", "-e", "cpu-clock", "-F", str(frequency),
        "--call-graph", "fp", "--inherit", "-p", str(identity.pid),
        "-o", str(data),
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    started = time.monotonic()
    count = 0
    last = reached
    primary_error: BaseException | None = None
    try:
        with samples_path.open("x", encoding="utf-8", newline="\n") as samples:
            while True:
                if time.monotonic() - started > maximum_window:
                    raise TimeoutError(f"{window.name} profiler window exceeded its bound")
                if not _alive(identity):
                    raise RuntimeError("candidate identity changed during profiling")
                sample = _sample(identity, control, workspace)
                last = sample["progress"]
                samples.write(json.dumps(sample, sort_keys=True, separators=(",", ":")) + "\n")
                samples.flush()
                count += 1
                if last["verified"] >= end_threshold:
                    break
                if process.poll() is not None:
                    raise RuntimeError("perf record exited before the message threshold")
                time.sleep(sample_interval)
    except BaseException as error:
        primary_error = error
    returncode, stderr = _stop_perf(process)
    if primary_error is not None:
        raise primary_error
    if returncode not in (0, 130, -signal.SIGINT):
        raise RuntimeError(f"perf record failed with {returncode}: {stderr}")
    after = _sample(identity, control, workspace)
    postgres_sql_after = _postgres_sql_snapshot()
    result = {
        "name": window.name,
        "fractions": [window.start_fraction, window.end_fraction],
        "thresholds": [start_threshold, end_threshold],
        "progress_before": reached,
        "progress_after": last,
        "duration_seconds": round(time.monotonic() - started, 6),
        "sample_interval_seconds": sample_interval,
        "sample_count": count,
        "perf_frequency": frequency,
        "perf_command": command,
        "perf_stderr_tail": stderr,
        "boundary_before": before,
        "boundary_after": after,
        "postgres_sql_before": postgres_sql_before,
        "postgres_sql_after": postgres_sql_after,
        "tree_before": tree_before,
        "tree_after": _tree(workspace / "maildir"),
        "samples_sha256": _sha256(samples_path),
    }
    result.update(_perf_views(perf, data, directory))
    return result


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--candidate", type=Path, default=DEFAULT_CANDIDATE)
    parser.add_argument("--runtime-root", type=Path, default=DEFAULT_RUNTIME_ROOT)
    parser.add_argument("--perf", type=Path)
    parser.add_argument("--wait-seconds", type=float, default=300.0)
    parser.add_argument("--maximum-window-seconds", type=float, default=20 * 60.0)
    parser.add_argument("--sample-interval-seconds", type=float, default=0.25)
    parser.add_argument("--perf-frequency", type=int, default=99)
    args = parser.parse_args(argv)
    if args.wait_seconds <= 0 or args.maximum_window_seconds <= 0:
        parser.error("timeouts must be positive")
    if not 0.05 <= args.sample_interval_seconds <= 5.0:
        parser.error("sample interval must be between 0.05 and 5 seconds")
    if not 1 <= args.perf_frequency <= 999:
        parser.error("perf frequency must be between 1 and 999 Hz")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    if os.geteuid() != 0:
        raise SystemExit("progress-aligned profiler must run as root")
    candidate = args.candidate.resolve(strict=True)
    perf = _perf(args.perf)
    output = args.output_dir.resolve(strict=False)
    output.mkdir(mode=0o755, parents=False, exist_ok=False)
    deadline = time.monotonic() + args.wait_seconds
    identity = _wait_candidate(candidate, deadline)
    control, progress = _wait_proxy(args.runtime_root.resolve(strict=False), deadline)
    workspace = Path(f"/proc/{identity.pid}/cwd").resolve(strict=True)
    if not (workspace / "maildir").is_dir():
        raise RuntimeError("candidate working directory omitted benchmark Maildir")
    metadata = candidate.stat()
    report: dict[str, Any] = {
        "schema": "lmyzmail-progress-aligned-profiler-v1",
        "status": "running",
        "started_unix_seconds": time.time(),
        "candidate": {
            "path": str(candidate),
            "sha256": _sha256(candidate),
            "bytes": metadata.st_size,
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "pid": identity.pid,
            "start_time_ticks": identity.start_time_ticks,
        },
        "perf": {"path": str(perf), "sha256": _sha256(perf)},
        "proxy_control": str(control),
        "expected_messages": progress["expected"],
        "workspace": str(workspace),
        "windows": [],
    }
    running = output / "report.running.json"
    running.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        for window in WINDOWS:
            report["windows"].append(
                _capture(
                    identity, control, workspace, perf, output, window,
                    progress["expected"], args.sample_interval_seconds, deadline,
                    args.maximum_window_seconds, args.perf_frequency,
                )
            )
            running.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        report["status"] = "passed"
        report["completed_unix_seconds"] = time.time()
        report["candidate_identity_still_alive"] = _alive(identity)
        final = output / "report.json"
        final.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        running.unlink()
        print(final)
        return 0
    except BaseException as error:
        report["status"] = "failed"
        report["completed_unix_seconds"] = time.time()
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        running.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        raise


if __name__ == "__main__":
    raise SystemExit(main())
