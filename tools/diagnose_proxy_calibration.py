#!/usr/bin/env python3
"""Record synthetic proxy timing evidence without changing qualification gates."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time


def network_counters() -> dict[str, int]:
    counters = {}
    for filename in ("snmp", "netstat"):
        lines = Path(f"/proc/net/{filename}").read_text().splitlines()
        for header, values in zip(lines[::2], lines[1::2], strict=True):
            names, numbers = header.split(), values.split()
            if names[0] != numbers[0]:
                raise ValueError("mismatched kernel network counters")
            for name, value in zip(names[1:], numbers[1:], strict=True):
                counters[f"{names[0][:-1]}.{name}"] = int(value)
    return counters


def process_sample(pid: int) -> dict:
    tasks = []
    for task in Path(f"/proc/{pid}/task").iterdir():
        try:
            runtime, waiting, slices = map(int, (task / "schedstat").read_text().split())
            tasks.append({
                "tid": int(task.name), "runtime_ns": runtime,
                "runqueue_wait_ns": waiting, "slices": slices,
                "wchan": (task / "wchan").read_text().strip(),
            })
        except FileNotFoundError:
            pass
    return {"tasks": tasks, "status": Path(f"/proc/{pid}/status").read_text()}


def tcp_sample(pid: int) -> dict:
    result = subprocess.run(
        ["ss", "-tinpo"], check=True, capture_output=True, text=True, timeout=10,
    )
    lines = result.stdout.splitlines()
    sockets = [(line, lines[index + 1]) for index, line in enumerate(lines[:-1])
               if f"pid={pid}," in line and not line.startswith("\t")]
    pending = [(state, info) for state, info in sockets
               if re.search(r"\b(?:unacked|notsent):[1-9]", info)]
    # Preserve bounded witnesses, including small unsent writes and retransmission
    # timers; these belong to this process, unlike the global MIB deltas.
    pending.sort(key=lambda pair: int(
        (re.search(r"\blastsend:(\d+)", pair[1]) or
         re.search(r"\blastsnd:(\d+)", pair[1]) or ["", "0"])[1]
    ), reverse=True)
    return {"sockets": len(sockets), "pending": len(pending),
            "pending_examples": pending[:8]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--messages", type=int, default=25_000)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--worker-threads", type=int)
    parser.add_argument("--initialize-isolated-network", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.messages <= 250_000:
        parser.error("messages must be 1..250000")
    if args.worker_threads is not None and not 1 <= args.worker_threads <= 8:
        parser.error("worker threads must be 1..8")
    repository = Path(__file__).resolve().parents[1]
    if args.initialize_isolated_network:
        if os.geteuid() != 0 or os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
            parser.error("network initialization requires root in a new network namespace")
        subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
        owner = repository.stat()
        if owner.st_uid == 0:
            parser.error("repository owner must be unprivileged")
        os.setgroups([])
        os.setgid(owner.st_gid)
        os.setuid(owner.st_uid)
    binary = (args.binary or repository /
              "target/x86_64-unknown-linux-gnu/release/lmyzmail-benchmark-proxy").resolve()
    output = args.output.resolve()
    output.mkdir(exist_ok=False)
    report_path = output / "calibration.json"
    command = [
        "taskset", "-c", "0-7", "prlimit", "--nofile=8192:8192", "--", str(binary),
        "calibrate", "--messages", str(args.messages), "--message-bytes", "10240",
        "--concurrency", "1000", "--rounds", "4", "--minimum-ratio", "0.90",
        "--maximum-spread", "0.20", "--output", str(report_path),
    ]
    with binary.open("rb") as stream:
        binary_sha = hashlib.file_digest(stream, "sha256").hexdigest()
    before = network_counters()
    topology = {
        "network_namespace": os.readlink("/proc/self/ns/net"),
        "loopback_route": subprocess.check_output(
            ["ip", "route", "get", "127.0.0.1"], text=True,
        ),
        "loopback_interface": subprocess.check_output(
            ["ip", "link", "show", "lo"], text=True,
        ),
    }
    started = time.monotonic()
    timed_out = False
    environment = dict(os.environ)
    if args.worker_threads is not None:
        environment["TOKIO_WORKER_THREADS"] = str(args.worker_threads)
    with (output / "console.log").open("x") as console, (
        output / "samples.jsonl"
    ).open("x") as samples:
        process = subprocess.Popen(
            command, cwd=repository, stdout=console, stderr=subprocess.STDOUT,
            start_new_session=True, env=environment,
        )
        try:
            while process.poll() is None:
                elapsed = time.monotonic() - started
                if elapsed >= 900:
                    timed_out = True
                    break
                try:
                    sample = process_sample(process.pid)
                except FileNotFoundError:
                    continue
                sample.update(elapsed_seconds=elapsed, network=network_counters())
                sample["tcp"] = tcp_sample(process.pid)
                samples.write(json.dumps(sample, sort_keys=True) + "\n")
                samples.flush()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
    after = network_counters()
    summary = {
        "diagnostic_only": True,
        "formal_qualification": False,
        "candidate_started": False,
        "global_tcp_counters_may_include_unrelated_traffic": True,
        "command": command, "binary_sha256": binary_sha,
        "network_topology": topology,
        "tokio_worker_threads_override": args.worker_threads,
        "exit_code": process.returncode, "timed_out": timed_out,
        "elapsed_seconds": time.monotonic() - started,
        "network_counter_deltas": {key: after[key] - value for key, value in before.items()
                                   if after[key] != value},
    }
    with (output / "diagnostic.json").open("x") as stream:
        json.dump(summary, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps(summary, indent=2, sort_keys=True), flush=True)
    return process.returncode or int(timed_out)


if __name__ == "__main__":
    raise SystemExit(main())
