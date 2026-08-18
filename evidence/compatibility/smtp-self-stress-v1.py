from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY / "blackbox/src"))

import psycopg  # noqa: E402
import redis  # noqa: E402

from lmyzmail_blackbox.protocols import http_exchange  # noqa: E402
from lmyzmail_blackbox.ports import PortSet  # noqa: E402
from lmyzmail_blackbox.runtime import API_KEY, CandidateRuntime  # noqa: E402


ENDPOINT_SENDER = "stress-sender@lmyz.net"
RECEIVER = "stress-receiver@lmyz.net"
QUEUE_PREFIX = "botmail:mail:queue:"
MAILBOX_ROOTS = (ENDPOINT_SENDER, RECEIVER)
PUBLIC_MX_ADDRESS = "1.1.1.1"
PUBLIC_MX_HOST = "mx.lmyz.net"
NAMESPACE_ENV = "LMYZMAIL_SMTP_STRESS_NAMESPACE"


def _sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


@dataclass(frozen=True)
class StressPlan:
    label: str
    message_bytes: int
    total_messages: int
    batch_size: int


class StressCandidateRuntime(CandidateRuntime):
    stress_enabled = True
    production_count = 1
    warmup_count = 0
    email_size_kb = 1
    spf_dns_port = 0

    @property
    def requires_qa_account(self) -> bool:
        return False

    def _start_application(self) -> None:
        if self.ports is None or self._port_allocator is None:
            raise RuntimeError("stress runtime ports were not allocated")
        if self.ports.smtp != 25:
            old = self.ports
            self._port_allocator.release_port(old.smtp)
            self._port_allocator.reserve_port(25)
            self.ports = PortSet(
                old.postgres,
                old.redis,
                old.http,
                25,
                old.htcpcp,
                old.minecraft,
                old.honeypots,
            )
        CandidateRuntime._start_application(self)

    def _candidate_configuration(self) -> Path:
        path = CandidateRuntime._candidate_configuration(self)
        value = json.loads(path.read_text(encoding="utf-8"))
        value["stress"] = {
            "enabled": True,
            "sender_prefix": "stress-sender",
            "receiver_prefix": "stress-receiver",
            "password": "StressBlackboxPass123!",
            "production_count": self.production_count,
            "warmup_count": self.warmup_count,
            "warmup_rounds": 0,
            "email_size_kb": self.email_size_kb,
        }
        # The frozen SMTP workload uses a routable external envelope sender so
        # the candidate's reserved-TLD and local-SPF defenses remain active;
        # disable content scoring so the measured self-receive path lands in
        # inbox rather than spam.
        value["content_filter"] = {"enabled": False}
        value["listen"]["host"] = "0.0.0.0"
        value["domain"] = "lmyz.net"
        value["domains"] = [
            {
                "domain": "lmyz.net",
                "receive_enabled": True,
                "send_enabled": True,
                "require_existing_mailbox": True,
            }
        ]
        if not self.spf_dns_port:
            raise RuntimeError("stress SPF DNS server was not started")
        value["features"]["smtp_spf_dns_server"] = f"127.0.0.1:{self.spf_dns_port}"
        # The pressure driver is the SMTP client; do not add a second queue
        # worker that could race with batch cleanup.
        # Let the setup round drain promptly; the measured workload below is
        # raw SMTP, while this endpoint is retained as the original mailbox and
        # queue lifecycle exercise.
        value["limits"]["outbound_poll_interval_ms"] = 100
        path.write_text(
            json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        return path


class StressDnsServer:
    """Isolated MX/A/TXT fixture for self-delivery without public traffic."""

    def __init__(self, txt: bytes = b"v=spf1 +all"):
        self.txt = txt
        self.stop_event = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 53))
        self.sock.settimeout(0.2)
        self.thread = threading.Thread(
            target=self._serve, name="stress-spf-dns", daemon=True
        )
        self.thread.start()

    @property
    def port(self) -> int:
        return int(self.sock.getsockname()[1])

    @staticmethod
    def _decode_question(query: bytes) -> tuple[str, int, bytes] | None:
        cursor = 12
        labels: list[str] = []
        while cursor < len(query) and query[cursor] != 0:
            length = query[cursor]
            cursor += 1
            if length == 0 or cursor + length > len(query):
                return None
            try:
                labels.append(query[cursor : cursor + length].decode("ascii"))
            except UnicodeDecodeError:
                return None
            cursor += length
        if cursor + 5 > len(query):
            return None
        question_end = cursor + 5
        qtype = int.from_bytes(query[cursor + 1 : cursor + 3], "big")
        return ".".join(labels).lower(), qtype, query[12:question_end]

    @staticmethod
    def _encode_name(value: str) -> bytes:
        return (
            b"".join(
                bytes([len(label)]) + label.encode("ascii")
                for label in value.split(".")
            )
            + b"\x00"
        )

    def _answer(self, query: bytes) -> bytes | None:
        decoded = self._decode_question(query)
        if decoded is None:
            return None
        qname, qtype, question = decoded
        record_type = 0
        rdata = b""
        if qname == "lmyz.net" and qtype == 15:
            record_type = 15
            rdata = b"\x00\x00" + self._encode_name(PUBLIC_MX_HOST)
        elif qname == PUBLIC_MX_HOST and qtype == 1:
            record_type = 1
            rdata = socket.inet_aton(PUBLIC_MX_ADDRESS)
        elif qname == "lmyz.net" and qtype == 16:
            record_type = 16
            rdata = bytes([len(self.txt)]) + self.txt
        answer_count = 1 if record_type else 0
        response = (
            query[:2]
            + b"\x81\x80"
            + b"\x00\x01"
            + answer_count.to_bytes(2, "big")
            + b"\x00\x00\x00\x00"
            + question
        )
        if record_type:
            response += (
                b"\xc0\x0c"
                + record_type.to_bytes(2, "big")
                + b"\x00\x01\x00\x00\x00\x3c"
                + len(rdata).to_bytes(2, "big")
                + rdata
            )
        return response

    def _serve(self) -> None:
        while not self.stop_event.is_set():
            try:
                query, address = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if len(query) < 12:
                continue
            answer = self._answer(query)
            if answer is None:
                continue
            try:
                self.sock.sendto(answer, address)
            except OSError:
                return

    def close(self) -> None:
        self.stop_event.set()
        self.sock.close()
        self.thread.join(timeout=1.0)


def _required_command(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(f"required SMTP stress command is missing: {name}")
    return str(Path(path).resolve())


def _enter_isolated_namespace() -> None:
    if os.environ.get(NAMESPACE_ENV) == "1":
        return
    environment = dict(os.environ)
    environment[NAMESPACE_ENV] = "1"
    unshare = _required_command("unshare")
    arguments = [
        unshare,
        "--user",
        f"--map-user={os.getuid()}",
        f"--map-group={os.getgid()}",
        "--keep-caps",
        "--net",
        "--mount",
        "--propagation",
        "private",
        str(Path(sys.executable).absolute()),
        str(Path(__file__).resolve()),
        *sys.argv[1:],
    ]
    os.execve(unshare, arguments, environment)


def _configure_isolated_namespace(root: Path) -> None:
    ip = _required_command("ip")
    subprocess.run([ip, "link", "set", "lo", "up"], check=True)
    subprocess.run(
        [ip, "address", "add", f"{PUBLIC_MX_ADDRESS}/32", "dev", "lo"],
        check=True,
    )
    resolver = root / "resolv.conf"
    resolver.write_text(
        "nameserver 127.0.0.1\noptions attempts:1 timeout:1\n",
        encoding="ascii",
    )
    os.chmod(resolver, 0o444)
    subprocess.run(
        [_required_command("mount"), "--bind", str(resolver), "/etc/resolv.conf"],
        check=True,
    )


def _start_endpoint(runtime: StressCandidateRuntime) -> None:
    assert runtime.ports is not None
    response = http_exchange(
        "127.0.0.1",
        runtime.ports.http,
        "POST",
        "/api/stress/start",
        headers=(("X-API-Key", API_KEY),),
    )
    if response.status_code != 200:
        raise RuntimeError(
            f"stress endpoint returned {response.status_code}: {response.body!r}"
        )


def _cleanup_endpoint(runtime: StressCandidateRuntime, timeout: float = 30.0) -> None:
    assert runtime.ports is not None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = http_exchange(
            "127.0.0.1",
            runtime.ports.http,
            "POST",
            "/api/stress/cleanup",
            headers=(("X-API-Key", API_KEY),),
        )
        if response.status_code == 200:
            return
        if response.status_code != 503:
            raise RuntimeError(
                f"stress cleanup returned {response.status_code}: {response.body!r}"
            )
        time.sleep(0.05)
    raise TimeoutError("stress cleanup remained busy before the deadline")


def _filesystem_used(path: Path) -> int:
    stat = os.statvfs(path)
    return (stat.f_blocks - stat.f_bfree) * stat.f_frsize


def _filesystem_free(path: Path) -> int:
    stat = os.statvfs(path)
    return stat.f_bavail * stat.f_frsize


def _allocated_bytes(root: Path) -> int:
    total = 0
    for path in root.rglob("*"):
        try:
            stat = path.lstat()
        except FileNotFoundError:
            continue
        if not path.is_symlink() and path.is_file():
            total += stat.st_blocks * 512
    return total


def _sample(
    runtime: StressCandidateRuntime,
    workspace_baseline: int,
    filesystem_baseline: int,
) -> dict[str, int]:
    assert runtime._application is not None and runtime.workspace is not None
    assert runtime.ports is not None
    pid = runtime._application.pid
    status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
    rss = next(
        int(line.split()[1])
        for line in status.splitlines()
        if line.startswith("VmRSS:")
    )
    workspace_bytes = _allocated_bytes(runtime.workspace)
    filesystem_used_bytes = _filesystem_used(runtime.workspace)
    client = redis.Redis(
        host="127.0.0.1",
        port=runtime.ports.redis,
        db=0,
        socket_timeout=2.0,
    )
    try:
        queue_pending = int(client.llen(QUEUE_PREFIX + "pending"))
    finally:
        client.close()
    return {
        "rss_kib": rss,
        "fd_count": len(list(Path(f"/proc/{pid}/fd").iterdir())),
        "task_count": len(list(Path(f"/proc/{pid}/task").iterdir())),
        "queue_pending": queue_pending,
        "workspace_bytes": workspace_bytes,
        "workspace_delta_bytes": workspace_bytes - workspace_baseline,
        "filesystem_used_bytes": filesystem_used_bytes,
        "filesystem_delta_bytes": filesystem_used_bytes - filesystem_baseline,
        "filesystem_free_bytes": _filesystem_free(runtime.workspace),
    }


def _delivery_rows(runtime: StressCandidateRuntime) -> list[tuple[str, Any]]:
    assert runtime.ports is not None
    with psycopg.connect(
        host="127.0.0.1",
        port=runtime.ports.postgres,
        dbname="lmyzmail",
        user="lmyzmail_test",
        connect_timeout=5,
    ) as connection:
        rows = connection.execute(
            "SELECT subject,received_at FROM email_index "
            "WHERE mailbox_address=%s ORDER BY id",
            (RECEIVER,),
        ).fetchall()
    return [(str(subject), received_at) for subject, received_at in rows]


def _delivery_ledger(runtime: StressCandidateRuntime) -> dict[str, int]:
    assert runtime.ports is not None
    with psycopg.connect(
        host="127.0.0.1",
        port=runtime.ports.postgres,
        dbname="lmyzmail",
        user="lmyzmail_test",
        connect_timeout=5,
    ) as connection:
        row = connection.execute(
            "SELECT "
            "count(*) FILTER (WHERE recipient.state='DELIVERED'),"
            "count(*) FILTER (WHERE recipient.state IN ('PERMANENT','AMBIGUOUS')) ,"
            "count(*) FILTER (WHERE recipient.state IN "
            "('PENDING','RETRYABLE','COMMIT_ARMED')) ,"
            "COALESCE(sum(GREATEST(recipient.attempt_generation-1,0)),0) "
            "FROM outbound_mail_queue queue "
            "JOIN lmyzmail_outbound_delivery_recipient recipient "
            "ON recipient.task_id=queue.id WHERE queue.sender_address=%s",
            (ENDPOINT_SENDER,),
        ).fetchone()
    if row is None:
        raise RuntimeError("stress delivery ledger query returned no row")
    return {
        "delivered": int(row[0]),
        "failed": int(row[1]),
        "active": int(row[2]),
        "retries": int(row[3]),
    }


def _delivery_failure_details(runtime: StressCandidateRuntime) -> list[dict[str, Any]]:
    assert runtime.ports is not None
    with psycopg.connect(
        host="127.0.0.1",
        port=runtime.ports.postgres,
        dbname="lmyzmail",
        user="lmyzmail_test",
        connect_timeout=5,
    ) as connection:
        rows = connection.execute(
            "SELECT recipient.recipient_address,recipient.state,"
            "recipient.attempt_generation,recipient.smtp_code,recipient.detail "
            "FROM outbound_mail_queue queue "
            "JOIN lmyzmail_outbound_delivery_recipient recipient "
            "ON recipient.task_id=queue.id "
            "WHERE queue.sender_address=%s "
            "AND recipient.state IN ('PERMANENT','AMBIGUOUS') "
            "ORDER BY queue.id,recipient.recipient_ordinal LIMIT 20",
            (ENDPOINT_SENDER,),
        ).fetchall()
    return [
        {
            "recipient": str(row[0]),
            "state": str(row[1]),
            "attempt_generation": int(row[2]),
            "smtp_code": int(row[3]) if row[3] is not None else None,
            "detail": str(row[4]) if row[4] is not None else None,
        }
        for row in rows
    ]


def _message_latencies(rows: list[tuple[str, Any]]) -> list[float]:
    values: list[float] = []
    for subject, received_at in rows:
        try:
            generated_millis = int(subject.rsplit(" - ", maxsplit=1)[1])
            received_millis = float(received_at.timestamp()) * 1000.0
        except (AttributeError, IndexError, TypeError, ValueError) as error:
            raise RuntimeError(
                f"stress delivery lost its timestamp contract: {subject!r}"
            ) from error
        latency = received_millis - generated_millis
        if not 0 <= latency <= 60 * 60 * 1000:
            raise RuntimeError(
                f"stress delivery latency is outside its bound: {latency}"
            )
        values.append(latency)
    return values


def _wait_for_deliveries(
    runtime: StressCandidateRuntime,
    expected: int,
    workspace_baseline: int,
    filesystem_baseline: int,
    hard_disk_budget_bytes: int,
    samples: list[dict[str, int]],
    *,
    timeout: float = 55 * 60,
) -> tuple[list[tuple[str, Any]], dict[str, int]]:
    deadline = time.monotonic() + timeout
    next_sample = 0.0
    observed_rows: dict[str, tuple[str, Any]] = {}
    ledger = {"delivered": 0, "failed": 0, "active": 0, "retries": 0}
    while time.monotonic() < deadline:
        current_rows = _delivery_rows(runtime)
        for row in current_rows:
            observed_rows[row[0]] = row
        if len(observed_rows) > expected:
            raise RuntimeError(
                "stress endpoint delivered more messages than configured: "
                f"{len(observed_rows)}>{expected}"
            )
        ledger = _delivery_ledger(runtime)
        if ledger["failed"]:
            log_tail = (
                runtime._application.log_tail()
                if runtime._application is not None
                else "<none>"
            )
            raise RuntimeError(
                "stress delivery ledger recorded failure: "
                f"{ledger!r}; details={_delivery_failure_details(runtime)!r}; "
                f"candidate_tail={log_tail}"
            )
        if ledger["delivered"] == expected:
            rows = list(observed_rows.values())
            if len(rows) != expected:
                raise RuntimeError(
                    "stress mailbox cleanup raced latency capture: "
                    f"captured={len(rows)}, delivered={expected}"
                )
            return rows, ledger
        if ledger["delivered"] > expected:
            raise RuntimeError(
                f"stress delivery ledger exceeded configured count: {ledger!r}"
            )
        now = time.monotonic()
        if now >= next_sample:
            sample = _sample(runtime, workspace_baseline, filesystem_baseline)
            samples.append(sample)
            if sample["workspace_delta_bytes"] > hard_disk_budget_bytes:
                raise RuntimeError("hard workspace disk budget exceeded")
            next_sample = now + 1.0
        time.sleep(0.05)
    raise TimeoutError(
        f"stress endpoint delivered {ledger['delivered']} of {expected} messages before the deadline"
    )


def _state_counts(runtime: StressCandidateRuntime) -> dict[str, int]:
    assert runtime.ports is not None
    with psycopg.connect(
        host="127.0.0.1",
        port=runtime.ports.postgres,
        dbname="lmyzmail",
        user="lmyzmail_test",
        connect_timeout=5,
    ) as connection:
        email_count = connection.execute(
            "SELECT count(*) FROM email_index WHERE mailbox_address IN (%s,%s)",
            MAILBOX_ROOTS,
        ).fetchone()[0]
        queue_count = connection.execute(
            "SELECT count(*) FROM outbound_mail_queue"
        ).fetchone()[0]
    client = redis.Redis(
        host="127.0.0.1", port=runtime.ports.redis, db=0, socket_timeout=2.0
    )
    try:
        pending = int(client.llen(QUEUE_PREFIX + "pending"))
    finally:
        client.close()
    return {
        "email_index": int(email_count),
        "outbound_queue": int(queue_count),
        "redis_pending": pending,
    }


def _purge_isolated_queue(runtime: StressCandidateRuntime) -> None:
    """Remove only stress-owned durable queue state from the isolated fixture."""
    assert runtime.ports is not None and runtime.workspace is not None
    spool_paths: list[Path] = []
    with psycopg.connect(
        host="127.0.0.1",
        port=runtime.ports.postgres,
        dbname="lmyzmail",
        user="lmyzmail_test",
        connect_timeout=5,
    ) as connection:
        task_ids = [
            int(row[0])
            for row in connection.execute(
                "SELECT id FROM outbound_mail_queue WHERE sender_address=%s",
                (ENDPOINT_SENDER,),
            ).fetchall()
        ]
        if task_ids:
            spool_paths = [
                Path(str(row[0]))
                for row in connection.execute(
                    "SELECT spool_path FROM lmyzmail_outbound_spool WHERE task_id=ANY(%s)",
                    (task_ids,),
                ).fetchall()
            ]
            connection.execute(
                "DELETE FROM lmyzmail_outbound_delivery_recipient WHERE task_id=ANY(%s)",
                (task_ids,),
            )
            connection.execute(
                "DELETE FROM lmyzmail_outbound_delivery_attempt WHERE task_id=ANY(%s)",
                (task_ids,),
            )
            connection.execute(
                "DELETE FROM lmyzmail_outbound_dsn WHERE original_task_id=ANY(%s)",
                (task_ids,),
            )
            connection.execute(
                "DELETE FROM lmyzmail_outbound_spool WHERE task_id=ANY(%s)", (task_ids,)
            )
            connection.execute(
                "DELETE FROM outbound_mail_queue WHERE id=ANY(%s)", (task_ids,)
            )

    spool_root = (runtime.workspace / "maildir/.lmyzmail-outbound").resolve()
    for path in spool_paths:
        resolved = path.resolve()
        if not resolved.is_relative_to(spool_root):
            raise RuntimeError(
                f"stress spool path escaped fixture workspace: {resolved}"
            )
        resolved.unlink(missing_ok=True)
    if spool_root.is_dir():
        for path in sorted(
            spool_root.rglob("*"), key=lambda value: len(value.parts), reverse=True
        ):
            if path.is_symlink() or path.is_file():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
        spool_root.rmdir()

    client = redis.Redis(
        host="127.0.0.1", port=runtime.ports.redis, db=0, socket_timeout=2.0
    )
    try:
        client.flushdb()
    finally:
        client.close()


def _distribution(values: list[float]) -> dict[str, float | int]:
    if not values:
        return {"count": 0, "p50": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0}
    ordered = sorted(values)
    return {
        "count": len(ordered),
        "p50": round(ordered[len(ordered) // 2], 3),
        "p95": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 3),
        "p99": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.99))], 3),
        "max": round(ordered[-1], 3),
    }


def run_plan(
    plan: StressPlan,
    hard_disk_budget_bytes: int,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    if plan.total_messages <= 0 or plan.batch_size <= 0:
        raise ValueError("stress counts must be positive")
    if plan.total_messages % plan.batch_size:
        raise ValueError("stress total must be an exact multiple of its cleanup batch")
    if plan.message_bytes % 1024:
        raise ValueError("the original stress endpoint accepts whole-KiB message sizes")
    candidate = REPOSITORY / "target/x86_64-unknown-linux-gnu/release/lmyzmail"
    spf_dns = StressDnsServer()
    runtime = StressCandidateRuntime(
        command_template=(str(candidate), "--config", "{config}")
    )
    runtime.production_count = plan.batch_size
    runtime.email_size_kb = plan.message_bytes // 1024
    runtime.spf_dns_port = spf_dns.port
    runtime.shutdown_timeout = 35.0
    started = time.monotonic()
    latencies: list[float] = []
    batch_latencies: list[float] = []
    samples: list[dict[str, int]] = []
    failures = 0
    retries = 0
    sent = 0
    workspace_baseline = 0
    filesystem_baseline = 0
    workspace_path: Path | None = None
    managed_pids: dict[str, int] = {}
    result: dict[str, Any] | None = None
    try:
        runtime.start()
        assert runtime.ports is not None and runtime.workspace is not None
        workspace_path = runtime.workspace
        processes = {
            "candidate": runtime._application,
            "postgres": runtime._postgres,
            "redis": runtime._redis,
        }
        managed_pids = {
            name: process.pid
            for name, process in processes.items()
            if process is not None
        }
        workspace_baseline = _allocated_bytes(runtime.workspace)
        filesystem_baseline = _filesystem_used(runtime.workspace)
        samples.append(_sample(runtime, workspace_baseline, filesystem_baseline))
        for batch_start in range(0, plan.total_messages, plan.batch_size):
            batch_started = time.monotonic()
            _start_endpoint(runtime)
            rows, ledger = _wait_for_deliveries(
                runtime,
                plan.batch_size,
                workspace_baseline,
                filesystem_baseline,
                hard_disk_budget_bytes,
                samples,
            )
            message_latencies = _message_latencies(rows)
            latencies.extend(message_latencies)
            sent += len(rows)
            failures += ledger["failed"]
            retries += ledger["retries"]
            _cleanup_endpoint(runtime, timeout=120.0)
            _purge_isolated_queue(runtime)
            states = _state_counts(runtime)
            if any(states.values()):
                raise RuntimeError(f"batch cleanup left durable state: {states!r}")
            batch_latency = (time.monotonic() - batch_started) * 1000.0
            batch_latencies.append(batch_latency)
            sample = _sample(runtime, workspace_baseline, filesystem_baseline)
            samples.append(sample)
            if sample["workspace_delta_bytes"] > hard_disk_budget_bytes:
                raise RuntimeError("hard workspace disk budget exceeded after cleanup")
            if progress is not None:
                progress(
                    {
                        "label": plan.label,
                        "batches_completed": len(batch_latencies),
                        "batches_total": plan.total_messages // plan.batch_size,
                        "sent": sent,
                        "requested": plan.total_messages,
                        "failures": failures,
                        "retries": retries,
                        "latest_resource": sample,
                    }
                )
        final_sample = _sample(runtime, workspace_baseline, filesystem_baseline)
        samples.append(final_sample)
        duration = time.monotonic() - started
        log_path = runtime.workspace / f"{runtime.target_kind}.log"
        stress_errors = []
        if log_path.is_file():
            stress_errors = [
                line
                for line in log_path.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
                if "stress round" in line and "failed before completion" in line
            ]
        result = {
            "label": plan.label,
            "message_bytes": plan.message_bytes,
            "requested": plan.total_messages,
            "sent": sent,
            "batch_size": plan.batch_size,
            "batches": len(batch_latencies),
            "failures": failures,
            "retries": retries,
            "duration_seconds": round(duration, 3),
            "throughput_messages_per_second": round(sent / max(0.001, duration), 3),
            "throughput_bytes_per_second": round(
                sent * plan.message_bytes / max(0.001, duration), 3
            ),
            "message_latency_ms": _distribution(latencies),
            "batch_completion_ms": _distribution(batch_latencies),
            "stress_error_lines": stress_errors,
            "resource": {
                "samples": len(samples),
                "rss_first_kib": samples[0]["rss_kib"],
                "rss_final_kib": final_sample["rss_kib"],
                "rss_min_kib": min(item["rss_kib"] for item in samples),
                "rss_max_kib": max(item["rss_kib"] for item in samples),
                "fd_first": samples[0]["fd_count"],
                "fd_final": final_sample["fd_count"],
                "fd_min": min(item["fd_count"] for item in samples),
                "fd_max": max(item["fd_count"] for item in samples),
                "task_first": samples[0]["task_count"],
                "task_final": final_sample["task_count"],
                "task_min": min(item["task_count"] for item in samples),
                "task_max": max(item["task_count"] for item in samples),
                "queue_first": samples[0]["queue_pending"],
                "queue_final": final_sample["queue_pending"],
                "queue_max": max(item["queue_pending"] for item in samples),
                "workspace_baseline_bytes": workspace_baseline,
                "workspace_delta_peak_bytes": max(
                    item["workspace_delta_bytes"] for item in samples
                ),
                "workspace_delta_final_bytes": final_sample["workspace_delta_bytes"],
                "filesystem_delta_peak_bytes": max(
                    item["filesystem_delta_bytes"] for item in samples
                ),
                "filesystem_delta_final_bytes": final_sample["filesystem_delta_bytes"],
                "filesystem_free_min_bytes": min(
                    item["filesystem_free_bytes"] for item in samples
                ),
            },
            "residual_state": _state_counts(runtime),
        }
    finally:
        try:
            if runtime.ports is not None:
                _cleanup_endpoint(runtime)
        except Exception:
            pass
        runtime.stop()
        spf_dns.close()
    if result is None:
        raise RuntimeError("stress plan completed without a result")
    residual_pids = {
        name: pid for name, pid in managed_pids.items() if Path(f"/proc/{pid}").exists()
    }
    result["cleanup"] = {
        "managed_pids": managed_pids,
        "residual_pids": residual_pids,
        "workspace_removed": workspace_path is not None and not workspace_path.exists(),
    }
    result["status"] = (
        "passed"
        if sent == plan.total_messages
        and failures == 0
        and retries == 0
        and not result["stress_error_lines"]
        and all(value == 0 for value in result["residual_state"].values())
        and not residual_pids
        and result["cleanup"]["workspace_removed"]
        else "failed"
    )
    return result


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, sort_keys=True, indent=2) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--disk-budget-gib", type=float, default=20.0)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    _enter_isolated_namespace()
    candidate = REPOSITORY / "target/x86_64-unknown-linux-gnu/release/lmyzmail"
    release_sha256 = _sha256_file(candidate)
    budget = int(args.disk_budget_gib * 1024**3)
    large_target = max(1, budget // (10 * 1024 * 1024) // 2)
    large_batch = min(50, large_target)
    large_count = max(large_batch, (large_target // large_batch) * large_batch)
    plans = (
        (
            StressPlan("1KB-smoke", 1024, 4, 2),
            StressPlan("10KB-smoke", 10 * 1024, 4, 2),
            StressPlan("10MB-smoke", 10 * 1024 * 1024, 2, 2),
        )
        if args.smoke
        else (
            StressPlan("1KB", 1024, 500_000, 1_000),
            StressPlan("10KB", 10 * 1024, 500_000, 1_000),
            StressPlan("10MB-budgeted", 10 * 1024 * 1024, large_count, large_batch),
        )
    )
    result = {
        "schema_version": 2,
        "profile": "candidate-smtp-self-receive-disk-stress-v1",
        "release_sha256": release_sha256,
        "hard_disk_budget_bytes": budget,
        "network_isolation": {
            "user_namespace": True,
            "network_namespace": True,
            "mount_namespace": True,
            "mapped_uid": os.getuid(),
            "kept_namespace_capabilities": True,
            "public_test_mx": PUBLIC_MX_ADDRESS,
            "smtp_port": 25,
        },
        "plans": [],
    }
    with tempfile.TemporaryDirectory(
        prefix="lmyzmail-smtp-stress-namespace-"
    ) as temporary:
        _configure_isolated_namespace(Path(temporary))
        try:
            for plan in plans:

                def checkpoint(current: dict[str, Any]) -> None:
                    result["status"] = "running"
                    result["current"] = current
                    if args.output:
                        _write_json(args.output, result)

                result["plans"].append(run_plan(plan, budget, checkpoint))
                result.pop("current", None)
                if args.output:
                    _write_json(args.output, result)
        except Exception as error:
            result["status"] = "failed"
            result["error"] = {"type": type(error).__name__, "message": str(error)}
            if args.output:
                _write_json(args.output, result)
            print(json.dumps(result, sort_keys=True, indent=2))
            return 1
    release_sha256_after = _sha256_file(candidate)
    result["release_sha256_after"] = release_sha256_after
    result["release_binary_unchanged"] = release_sha256_after == release_sha256
    result["status"] = (
        "passed"
        if all(item["status"] == "passed" for item in result["plans"])
        and result["release_binary_unchanged"]
        else "failed"
    )
    encoded = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if args.output:
        _write_json(args.output, result)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
