from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import httpx
import psycopg
import redis

from .persistent_runtime import PersistentJavaOracleRuntime
from .runtime import API_KEY, QA_ADDRESS, QA_PASSWORD, CandidateRuntime, JavaOracleRuntime
from .scripted_dns import AAnswer, DnsAnswer, ScriptedDnsServer
from .scripted_smtp import (
    RecipientReply,
    ScriptedSmtpServer,
    SmtpMessageAttempt,
    SmtpScenario,
)

_REDIS_PREFIX = "botmail:mail:queue:"
_DOMAIN_STATUS_PREFIX = _REDIS_PREFIX + "domains:"
_SENTINEL = b"-999999999"
_DNS_HOST = "outbound.fixture.test"
_FAKE_IP = "93.184.216.34"
_RECIPIENT = f"recipient@{_DNS_HOST}"
_TASK_TTL_SECONDS = 7 * 24 * 60 * 60
_TASK_TTL_OBSERVATION_WINDOW_SECONDS = 30
_FOURXX_CODES = (400, 421, 450, 451, 452, 499)
_RETRYABLE_FOURXX_CODES = frozenset((421, 450, 451, 452))
_RETRY_DELAYS_SECONDS = (30, 60, 120, 240, 480)
_RETRY_DEADLINE_TOLERANCE_SECONDS = 5.0
_OUTBOUND_TARGET_ENV = "LMYZMAIL_OUTBOUND_TARGET"
_MESSAGE_ID_RE = re.compile(rb"(?im)^(Message-ID:\s*)<[^>\r\n]+>")
_DATE_RE = re.compile(rb"(?im)^Date:\s*[^\r\n]+")
_DKIM_RE = re.compile(rb"(?ims)^DKIM-Signature:.*?(?=^[^ \t\r\n][^\r\n]*:|\Z)")


class OutboundOracleRuntime(PersistentJavaOracleRuntime):
    _hosts_file: Path | None = None

    def __init__(self, workspace_path: Path) -> None:
        super().__init__(workspace_path, index_migration_enabled=False)

    def _application_arguments(self) -> list[str]:
        workspace, _ = self._require_state()
        hosts_file = workspace / "outbound-hosts"
        hosts_file.write_text(f"{_FAKE_IP} {_DNS_HOST}\n", encoding="ascii")
        self._hosts_file = hosts_file
        arguments = super()._application_arguments()
        jar_index = arguments.index("-jar")
        arguments.insert(jar_index, f"-Djdk.net.hosts.file={hosts_file}")
        arguments.extend(
            (
                "--botmail.queue.poll-interval-ms=3000",
                "--botmail.queue.batch-size=2",
                "--botmail.queue.max-concurrent-sends=1",
                "--botmail.queue.persist.interval-ms=50",
                "--botmail.queue.persist.batch-size=10",
                "--botmail.queue.persist.flush-size=1",
                "--botmail.outbound.pool-enabled=false",
                "--botmail.outbound.helo-hostname=blackbox.example",
                "--dns.cache.mx.query-timeout-seconds=1",
            )
        )
        return arguments


class OutboundCandidateRuntime(CandidateRuntime):
    def _application_arguments(self) -> list[str]:
        arguments = CandidateRuntime._application_arguments(self)
        arguments.extend(
            (
                "--lmyzmail.queue.poll-interval-ms=3000",
                "--lmyzmail.queue.batch-size=2",
                "--lmyzmail.queue.max-concurrent-sends=1",
                "--lmyzmail.outbound.pool-enabled=false",
                "--lmyzmail.outbound.helo-hostname=blackbox.example",
                "--lmyzmail.outbound.dns.query-timeout-seconds=1",
                "--lmyzmail.maildir.max-files-per-directory=1",
            )
        )
        return arguments


def _outbound_target() -> str:
    target = os.environ.get(_OUTBOUND_TARGET_ENV, "java").casefold()
    if target not in {"java", "candidate"}:
        raise AssertionError(f"unsupported outbound target: {target}")
    return target


def _candidate_runtime(repository: Path) -> OutboundCandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        return cast(
            OutboundCandidateRuntime,
            OutboundCandidateRuntime.from_environment(),
        )
    return OutboundCandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        )
    )


def _ipv4_nameserver() -> str:
    for line in Path("/etc/resolv.conf").read_text(encoding="ascii").splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[0] != "nameserver":
            continue
        try:
            address = ipaddress.ip_address(fields[1])
        except ValueError:
            continue
        if address.version == 4 and not address.is_unspecified and not address.is_multicast:
            return str(address)
    raise AssertionError("outbound candidate probe requires an IPv4 system nameserver")


def _candidate_dns_server() -> ScriptedDnsServer:
    nameserver = _ipv4_nameserver()
    result = subprocess.run(  # noqa: S603
        ["/usr/sbin/ip", "address", "add", f"{nameserver}/32", "dev", "lo"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 and "File exists" not in result.stderr:
        raise AssertionError(
            f"failed to pin candidate DNS fixture address: {result.stderr.strip()}"
        )
    return ScriptedDnsServer(
        {(_DNS_HOST, 1): DnsAnswer(a=(AAnswer(_FAKE_IP, ttl=0),))},
        bind_host=nameserver,
        bind_port=53,
    )


def _normalize_message(value: bytes) -> bytes:
    value = _DATE_RE.sub(rb"Date: <NORMALIZED>", value)
    value = _MESSAGE_ID_RE.sub(rb"\1<MESSAGE_ID>", value)
    return _DKIM_RE.sub(b"DKIM-Signature: <NORMALIZED>\r\n", value)


def _digest(value: bytes) -> str:
    return hashlib.sha256(_normalize_message(value)).hexdigest()


def _logical_id(task_id: int, ids: dict[int, str]) -> str:
    return ids.get(task_id, f"legacy:{task_id}")


def _redis_type(client: redis.Redis, key: str) -> str:
    value = cast(bytes, client.type(key))
    return value.decode("ascii") if isinstance(value, bytes) else str(value)


def _normalize_task_ttl(ttl_seconds: int) -> int:
    minimum = _TASK_TTL_SECONDS - _TASK_TTL_OBSERVATION_WINDOW_SECONDS
    if not minimum <= ttl_seconds <= _TASK_TTL_SECONDS:
        raise AssertionError(
            "outbound task TTL is outside the seven-day observation window: "
            f"{ttl_seconds} not in [{minimum}, {_TASK_TTL_SECONDS}]"
        )
    return _TASK_TTL_SECONDS


def _redis_snapshot(client: redis.Redis, ids: dict[int, str]) -> dict[str, Any]:
    expected = frozenset(ids.values())
    pending_values = cast(list[bytes], client.lrange(_REDIS_PREFIX + "pending", 0, -1))
    pending = [
        logical
        for value in pending_values
        if value.decode("ascii", errors="ignore").isdigit()
        and (logical := _logical_id(int(value), ids)) in expected
    ]
    processing_values = cast(set[bytes], client.smembers(_REDIS_PREFIX + "processing"))
    processing = sorted(
        logical
        for value in processing_values
        if value.decode("ascii", errors="ignore").isdigit()
        and (logical := _logical_id(int(value), ids)) in expected
    )
    retry_values = cast(list[bytes], client.zrange(_REDIS_PREFIX + "retry", 0, -1))
    retry = [
        logical
        for value in retry_values
        if value.decode("ascii", errors="ignore").isdigit()
        and (logical := _logical_id(int(value), ids)) in expected
    ]
    processing_time_values = cast(list[bytes], client.hkeys(_REDIS_PREFIX + "processing_time"))
    processing_time = sorted(
        logical
        for value in processing_time_values
        if value.decode("ascii", errors="ignore").isdigit()
        and (logical := _logical_id(int(value), ids)) in expected
    )
    archive = client.llen(_REDIS_PREFIX + "archive")
    status_updates = client.llen(_REDIS_PREFIX + "status_updates")
    sent_index_values = cast(dict[bytes, bytes], client.hgetall(_REDIS_PREFIX + "sentfile_index"))
    sent_index: dict[str, str] = {}
    for _filename, value in sent_index_values.items():
        if not value.decode("ascii", errors="ignore").isdigit():
            continue
        logical = _logical_id(int(value), ids)
        if logical not in expected:
            continue
        # Java embeds wall-clock time and a process-local counter in generated
        # sent filenames. The task-to-file relation is stable and is asserted
        # through the normalized key.
        normalized_key = f"generated:{logical}"
        sent_index[normalized_key] = logical
    tasks: dict[str, Any] = {}
    for task_id, logical in ids.items():
        task_key = f"{_REDIS_PREFIX}task:{task_id}"
        raw = cast(bytes | None, client.get(task_key))
        if raw is None:
            tasks[logical] = None
            continue
        detail = json.loads(raw)
        signed = detail.get("signedContentBase64")
        file_path = detail.get("messageFilePath")
        signed_bytes = base64.b64decode(signed) if signed else None
        tasks[logical] = {
            "status": detail.get("status"),
            "retry_count": detail.get("retryCount"),
            "max_retries": detail.get("maxRetries"),
            "message_id_present": bool(detail.get("messageId")),
            "sent_file_present": bool(detail.get("sentFileName")),
            "sent_subdirectory": detail.get("sentSubdirectory"),
            "in_memory": signed_bytes is not None,
            "content_bytes": len(signed_bytes) if signed_bytes is not None else None,
            "content_sha256": _digest(signed_bytes) if signed_bytes is not None else None,
            "file_mode": file_path is not None,
            "file_exists": Path(file_path).is_file() if file_path else False,
            "file_bytes": (
                Path(file_path).stat().st_size if file_path and Path(file_path).is_file() else None
            ),
            "ttl_seconds": _normalize_task_ttl(cast(int, client.ttl(task_key))),
        }
    return {
        "pending": pending,
        "processing": processing,
        "retry": retry,
        "processing_time": processing_time,
        "archive_length": archive,
        "status_updates_length": status_updates,
        "sentfile_index": sent_index,
        "tasks": tasks,
        "key_types": {
            logical: _redis_type(client, f"{_REDIS_PREFIX}task:{task_id}")
            for task_id, logical in ids.items()
        },
    }


def _normalize_response(response: httpx.Response) -> dict[str, Any]:
    body = response.json()
    return {
        "status_code": response.status_code,
        "queued": body.get("queued"),
        "status": body.get("status"),
        "error": body.get("error"),
        "queue_id_present": isinstance(body.get("queueId"), int),
        "message_id_present": isinstance(body.get("messageId"), str),
    }


def _wait_until(
    predicate: Callable[[], bool],
    *,
    timeout: float,
    description: str,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {description}")


def _db_rows(runtime: JavaOracleRuntime) -> list[dict[str, Any]]:
    if runtime.workspace is None or runtime.ports is None:
        raise AssertionError("runtime is not started")
    with psycopg.connect(
        host="127.0.0.1",
        port=runtime.ports.postgres,
        dbname="lmyzmail",
        user="lmyzmail_test",
        password="",
    ) as connection:
        rows = connection.execute(
            """
            SELECT id, status, retry_count, max_retries, sent_file_name,
                   sent_subdirectory, message_id, last_error
            FROM outbound_mail_queue
            ORDER BY id
            """
        ).fetchall()
    output: list[dict[str, Any]] = []
    for row in rows:
        output.append(
            {
                "id": int(row[0]),
                "status": row[1],
                "retry_count": int(row[2]),
                "max_retries": int(row[3]),
                "sent_file_present": row[4] is not None,
                "sent_subdirectory": row[5],
                "message_id_present": row[6] is not None,
                "last_error": row[7],
            }
        )
    return output


def _maildir_snapshot(runtime: JavaOracleRuntime) -> dict[str, Any]:
    if runtime.workspace is None:
        raise AssertionError("runtime is not started")
    sent = runtime.workspace / "maildir" / QA_ADDRESS / "sent"
    files = sorted(path for path in sent.rglob("*") if path.is_file()) if sent.exists() else []
    return {"count": len(files), "bytes": sum(path.stat().st_size for path in files)}


def _attempt_snapshot(attempt: SmtpMessageAttempt) -> dict[str, Any]:
    return {
        "sender": attempt.sender.decode("ascii"),
        "recipients": [value.decode("ascii") for value in attempt.recipients],
        "accepted": attempt.accepted,
        "bytes": len(attempt.data),
        "wire_bytes": len(attempt.wire_data),
        "normalized_sha256": _digest(attempt.data),
    }


def _capture_runtime(
    server: ScriptedSmtpServer,
    runtime: JavaOracleRuntime,
) -> tuple[dict[str, Any], dict[str, Any], dict[int, str], dict[str, int]]:
    if runtime.ports is None:
        raise AssertionError("runtime ports are unavailable")
    if runtime.workspace is None:
        raise AssertionError("runtime workspace is unavailable")
    workspace = runtime.workspace
    bodies = {
        "small": "small outbound body",
        "below_threshold": "m" * 8_191,
        "at_threshold": "f" * 8_192,
        "large": "L" * (12 * 1024),
    }
    redis_client: redis.Redis = redis.Redis(
        host="127.0.0.1",
        port=runtime.ports.redis,
        decode_responses=False,
    )
    try:
        baseline_rows = _db_rows(runtime)
        redis_client.set(
            f"dns:mx:{_DNS_HOST}",
            _DNS_HOST.encode("ascii"),
            ex=300,
        )
        if isinstance(runtime, OutboundOracleRuntime):
            redis_client.rpush(_REDIS_PREFIX + "pending", _SENTINEL)
            _wait_until(
                lambda: _SENTINEL
                not in cast(
                    list[bytes],
                    redis_client.lrange(_REDIS_PREFIX + "pending", 0, -1),
                ),
                timeout=10.0,
                description="scheduler sentinel consumption",
            )
            _wait_until(
                lambda: _SENTINEL
                not in cast(
                    set[bytes],
                    redis_client.smembers(_REDIS_PREFIX + "processing"),
                ),
                timeout=10.0,
                description="scheduler sentinel completion",
            )
        with httpx.Client(
            base_url=f"http://127.0.0.1:{runtime.ports.http}",
            headers={"X-API-Key": API_KEY},
            trust_env=False,
            timeout=5.0,
        ) as client:
            responses = {
                label: client.post(
                    "/api/mail/send",
                    json={
                        "from": QA_ADDRESS,
                        "password": QA_PASSWORD,
                        "to": [_RECIPIENT],
                        "subject": f"blackbox {label} outbound",
                        "text": body,
                        "async": True,
                    },
                )
                for label, body in bodies.items()
            }
        ids = {int(response.json()["queueId"]): label for label, response in responses.items()}
        pre: dict[str, Any] = {
            "responses": {
                label: _normalize_response(response) for label, response in responses.items()
            },
            "redis": _redis_snapshot(redis_client, ids),
            "maildir": _maildir_snapshot(runtime),
        }
        try:
            _wait_until(
                lambda: len(server.messages()) >= len(ids),
                timeout=30.0,
                description="remote SMTP acceptance of all tasks",
            )
        except AssertionError as error:
            log_paths = sorted(workspace.glob("*-application-*.log"))
            log_tail = (
                log_paths[-1].read_text(encoding="utf-8", errors="replace")[-32_768:]
                if log_paths
                else "<application log missing>"
            )
            raise AssertionError(
                f"{error}; smtp_events={server.events()!r}; "
                f"pending={redis_client.lrange(_REDIS_PREFIX + 'pending', 0, -1)!r}; "
                f"processing={redis_client.smembers(_REDIS_PREFIX + 'processing')!r}; "
                f"log_tail={log_tail}"
            ) from error
        _wait_until(
            lambda: len(_db_rows(runtime)) >= len(baseline_rows) + 2
            and all(row["status"] == "SENT" for row in _db_rows(runtime) if row["id"] in ids),
            timeout=30.0,
            description="outbound PostgreSQL archive",
        )
        _wait_until(
            lambda: redis_client.llen(_REDIS_PREFIX + "archive") == 0
            and redis_client.scard(_REDIS_PREFIX + "processing") == 0,
            timeout=10.0,
            description="outbound Redis acknowledgement",
        )
        post: dict[str, Any] = {
            "redis": _redis_snapshot(redis_client, ids),
            "db": _db_rows(runtime),
            "maildir": _maildir_snapshot(runtime),
            "temp_files": len(list((workspace / "java-tmp").rglob("*.eml"))),
        }
        return pre, post, ids, {label: len(body) for label, body in bodies.items()}
    finally:
        redis_client.close()


def _java_domain_is_permanent(error: str | None) -> bool:
    if error is None:
        return False
    lower_error = error.lower()
    return any(
        marker in lower_error
        for marker in (
            "does not support smtputf8",
            "requires smtputf8",
            "smtputf8 recipient",
            "was not sent with smtputf8",
            "session was not initialized",
            "user unknown",
            "mailbox not found",
            "recipient rejected",
            "no such user",
            "address rejected",
            "relay denied",
            "relay not permitted",
            "550 ",
            "551 ",
            "552 ",
            "553 ",
            "554 ",
        )
    )


def _java_aggregate_status(domain_statuses: dict[str, dict[str, Any]]) -> str:
    total = len(domain_statuses)
    if total == 0:
        return "PENDING"
    sent = 0
    failed = 0
    permanent_failed = 0
    pending = 0
    sending = 0
    for status in domain_statuses.values():
        value = status.get("status")
        if value == "SENT":
            sent += 1
        elif value == "FAILED":
            failed += 1
            if _java_domain_is_permanent(cast(str | None, status.get("error"))):
                permanent_failed += 1
        elif value == "SENDING":
            sending += 1
        elif value == "PENDING":
            pending += 1
    if sent == total:
        return "SENT"
    if permanent_failed == total:
        return "FAILED"
    if sent > 0 and permanent_failed > 0 and sent + permanent_failed == total:
        return "PARTIAL_SUCCESS"
    if pending > 0 or sending > 0 or failed > permanent_failed:
        return "PROCESSING"
    return "PENDING"


def _failure_redis_snapshot(
    client: redis.Redis,
    task_id: int,
) -> tuple[dict[str, Any] | None, dict[str, dict[str, Any]]]:
    raw_task = cast(bytes | None, client.get(f"{_REDIS_PREFIX}task:{task_id}"))
    task: dict[str, Any] | None = None
    if raw_task is not None:
        detail = cast(dict[str, Any], json.loads(raw_task))
        task = {
            "status": detail.get("status"),
            "retry_count": detail.get("retryCount"),
            "max_retries": detail.get("maxRetries"),
            "last_error": detail.get("lastError"),
        }

    domain_statuses: dict[str, dict[str, Any]] = {}
    raw_domains = cast(
        dict[bytes, bytes],
        client.hgetall(_DOMAIN_STATUS_PREFIX + str(task_id)),
    )
    for raw_domain, raw_status in raw_domains.items():
        domain = raw_domain.decode("utf-8", errors="replace")
        value = cast(dict[str, Any], json.loads(raw_status))
        domain_statuses[domain] = {
            "status": value.get("status"),
            "error": value.get("error"),
            "recipients": value.get("recipients"),
        }
    return task, dict(sorted(domain_statuses.items()))


def _parse_retry_instant(value: object, *, source: str) -> float:
    if not isinstance(value, str):
        raise AssertionError(f"{source} retry deadline is not a string: {value!r}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AssertionError(f"{source} retry deadline is invalid: {value!r}") from error
    if parsed.tzinfo is None:
        raise AssertionError(f"{source} retry deadline has no timezone: {value!r}")
    return parsed.timestamp()


def _normalize_retry_deadlines(
    failure_observed_at: float,
    expected_delay_seconds: int,
    deadlines: dict[str, float],
) -> int:
    if set(deadlines) != {"redis_task", "redis_zset"}:
        raise AssertionError(f"retry deadline sources are incomplete: {sorted(deadlines)!r}")
    minimum = expected_delay_seconds - _RETRY_DEADLINE_TOLERANCE_SECONDS
    maximum = expected_delay_seconds + _RETRY_DEADLINE_TOLERANCE_SECONDS
    for source, deadline in deadlines.items():
        observed = deadline - failure_observed_at
        if not minimum <= observed <= maximum:
            raise AssertionError(
                f"{source} retry delay is outside the observation window: "
                f"{observed:.3f}s not in [{minimum:.3f}, {maximum:.3f}]"
            )
    spread = max(deadlines.values()) - min(deadlines.values())
    if spread > 1.0:
        raise AssertionError(f"retry deadline sources differ by {spread:.3f}s")
    return expected_delay_seconds


def _retry_database_snapshot(runtime: JavaOracleRuntime, task_id: int) -> dict[str, Any]:
    if runtime.ports is None:
        raise AssertionError("runtime ports are unavailable")
    with psycopg.connect(
        host="127.0.0.1",
        port=runtime.ports.postgres,
        dbname="lmyzmail",
        user="lmyzmail_test",
        password="",
    ) as connection:
        row = connection.execute(
            """
            SELECT status, retry_count, max_retries, next_retry_at, last_error
            FROM outbound_mail_queue
            WHERE id = %s
            """,
            (task_id,),
        ).fetchone()
    if row is None:
        return {"present": False}
    deadline = row[3]
    if not isinstance(deadline, datetime) or deadline.tzinfo is None:
        raise AssertionError(f"outbound retry task {task_id} has an invalid PostgreSQL deadline")
    return {
        "present": True,
        "status": row[0],
        "retry_count": int(row[1]),
        "max_retries": int(row[2]),
        "next_retry_epoch": deadline.timestamp(),
        "last_error": row[4],
    }


def _scheduled_retry_ready(client: redis.Redis, task_id: int, retry_count: int) -> bool:
    raw = cast(bytes | None, client.get(f"{_REDIS_PREFIX}task:{task_id}"))
    if raw is None or client.zscore(_REDIS_PREFIX + "retry", task_id) is None:
        return False
    try:
        detail = cast(dict[str, Any], json.loads(raw))
    except (TypeError, ValueError):
        return False
    return detail.get("status") == "PENDING" and detail.get("retryCount") == retry_count


def _capture_scheduled_retry(
    runtime: JavaOracleRuntime,
    client: redis.Redis,
    task_id: int,
    *,
    retry_count: int,
    expected_delay_seconds: int,
    failure_observed_at: float,
) -> dict[str, Any]:
    _wait_until(
        lambda: _scheduled_retry_ready(client, task_id, retry_count),
        timeout=15.0,
        description=f"retry {retry_count} Redis scheduling",
    )
    raw = cast(bytes | None, client.get(f"{_REDIS_PREFIX}task:{task_id}"))
    if raw is None:
        raise AssertionError(f"retry task {task_id} disappeared after scheduling")
    detail = cast(dict[str, Any], json.loads(raw))
    zset_deadline = cast(
        float | None, client.zscore(_REDIS_PREFIX + "retry", task_id)
    )
    if zset_deadline is None:
        raise AssertionError(f"retry task {task_id} has no retry ZSET deadline")
    task_deadline = _parse_retry_instant(
        detail.get("nextRetryAt"), source="Redis task"
    )
    normalized_delay = _normalize_retry_deadlines(
        failure_observed_at,
        expected_delay_seconds,
        {"redis_task": task_deadline, "redis_zset": float(zset_deadline)},
    )
    task, domains = _failure_redis_snapshot(client, task_id)
    if task is None:
        raise AssertionError(f"retry task {task_id} disappeared before snapshot")
    database = _retry_database_snapshot(runtime, task_id)
    database_deadline_matches: bool | None = None
    if database["present"]:
        database_deadline_matches = (
            abs(float(database["next_retry_epoch"]) - task_deadline) <= 1.0
        )
        del database["next_retry_epoch"]
    database["deadline_matches_retry"] = database_deadline_matches
    return {
        "retry_count": retry_count,
        "scheduled_delay_seconds": normalized_delay,
        "redis": {
            "task": task,
            "retry_zset_member": True,
            "domains": domains,
            "aggregate_status": _java_aggregate_status(domains),
        },
        "db": database,
    }


def _force_retry_due(
    runtime: JavaOracleRuntime,
    client: redis.Redis,
    task_id: int,
    *,
    current_retry_count: int,
    due_retry_count: int,
    database_present: bool,
) -> None:
    task_key = f"{_REDIS_PREFIX}task:{task_id}"
    raw = cast(bytes | None, client.get(task_key))
    if raw is None:
        raise AssertionError(f"retry task {task_id} disappeared before time advancement")
    detail = cast(dict[str, Any], json.loads(raw))
    if detail.get("status") != "PENDING" or detail.get("retryCount") != current_retry_count:
        raise AssertionError(
            f"retry task {task_id} changed before time advancement: {detail!r}"
        )
    max_retries = detail.get("maxRetries")
    if not isinstance(max_retries, int) or not (
        current_retry_count <= due_retry_count <= max_retries
    ):
        raise AssertionError(
            f"retry task {task_id} cannot advance to retry {due_retry_count}: {detail!r}"
        )
    due = datetime.now(UTC)
    due_text = due.isoformat().replace("+00:00", "Z")
    detail["retryCount"] = due_retry_count
    detail["nextRetryAt"] = due_text
    encoded = json.dumps(detail, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if not client.set(task_key, encoded, keepttl=True):
        raise AssertionError(f"retry task {task_id} could not be advanced")

    if runtime.ports is None:
        raise AssertionError("runtime ports are unavailable")
    with psycopg.connect(
        host="127.0.0.1",
        port=runtime.ports.postgres,
        dbname="lmyzmail",
        user="lmyzmail_test",
        password="",
    ) as connection:
        updated = connection.execute(
            """
            UPDATE outbound_mail_queue
            SET status = 'PENDING', retry_count = %s, next_retry_at = %s,
                processor_id = NULL, updated_at = %s
            WHERE id = %s
            """,
            (due_retry_count, due, due, task_id),
        ).rowcount
    expected_updates = 1 if database_present else 0
    if updated != expected_updates:
        raise AssertionError(
            f"retry task {task_id} PostgreSQL presence changed before time advancement: "
            f"expected {expected_updates} row, updated {updated}"
        )
    client.zadd(_REDIS_PREFIX + "retry", {str(task_id): due.timestamp() - 1.0})


def _failure_reply_count(server: ScriptedSmtpServer, code: int) -> int:
    prefix = f"{code} ".encode("ascii")
    return sum(
        event.kind == "reply" and event.payload.startswith(prefix)
        for event in server.events()
    )


def _failure_reply_count_reached(
    server: ScriptedSmtpServer, code: int, expected_count: int
) -> Callable[[], bool]:
    def reached() -> bool:
        return _failure_reply_count(server, code) >= expected_count

    return reached


def _smtp_transcript_snapshot(server: ScriptedSmtpServer) -> dict[str, Any]:
    commands: list[str] = []
    replies: list[str] = []
    data_event_count = 0
    data_bytes = 0
    for event in server.events():
        if event.kind == "command":
            commands.append(event.payload.decode("ascii", errors="replace").rstrip("\r\n"))
        elif event.kind == "reply":
            replies.append(event.payload.decode("ascii", errors="replace").rstrip("\r\n"))
        elif event.kind == "data":
            data_event_count += 1
            data_bytes += len(event.payload)
    return {
        "commands": commands,
        "replies": replies,
        "data_event_count": data_event_count,
        "data_bytes": data_bytes,
        "attempts": [_attempt_snapshot(value) for value in server.messages()],
    }


def _capture_5xx_case(
    server: ScriptedSmtpServer,
    runtime: JavaOracleRuntime,
    *,
    phase: str,
    code: int,
    case_index: int,
) -> dict[str, Any]:
    if runtime.ports is None:
        raise AssertionError("runtime ports are unavailable")
    recipient = f"recipient-{phase.lower()}-{code}-{case_index}@{_DNS_HOST}"
    redis_client: redis.Redis = redis.Redis(
        host="127.0.0.1",
        port=runtime.ports.redis,
        decode_responses=False,
    )
    try:
        redis_client.set(f"dns:mx:{_DNS_HOST}", _DNS_HOST.encode("ascii"), ex=300)
        with httpx.Client(
            base_url=f"http://127.0.0.1:{runtime.ports.http}",
            headers={"X-API-Key": API_KEY},
            trust_env=False,
            timeout=5.0,
        ) as client:
            response = client.post(
                "/api/mail/send",
                json={
                    "from": QA_ADDRESS,
                    "password": QA_PASSWORD,
                    "to": [recipient],
                    "subject": f"blackbox 5xx {phase} {code} {case_index}",
                    "text": f"5xx {phase} body {code} {case_index}",
                    "async": True,
                },
            )
        normalized_response = _normalize_response(response)
        body = response.json()
        task_id = body.get("queueId")
        if not isinstance(task_id, int):
            raise AssertionError(f"5xx case was not queued: {normalized_response!r}")

        _wait_until(
            lambda: any(
                event.kind == "reply"
                and event.payload.startswith(f"{code} ".encode("ascii"))
                for event in server.events()
            ),
            timeout=30.0,
            description=f"5xx {phase} {code} SMTP reply",
        )
        def final_row() -> dict[str, Any] | None:
            return next((row for row in _db_rows(runtime) if row["id"] == task_id), None)

        _wait_until(
            lambda: (row := final_row()) is not None and row["status"] == "FAILED",
            timeout=45.0,
            description=f"5xx {phase} {code} PostgreSQL failure archive",
        )
        _wait_until(
            lambda: redis_client.llen(_REDIS_PREFIX + "archive") == 0
            and redis_client.scard(_REDIS_PREFIX + "processing") == 0,
            timeout=15.0,
            description=f"5xx {phase} {code} Redis acknowledgement",
        )
        row = final_row()
        if row is None:
            raise AssertionError(f"archived 5xx task {task_id} disappeared from PostgreSQL")
        if not isinstance(row.get("id"), int):
            raise AssertionError(f"archived 5xx task has an invalid ID: {row!r}")
        row["id_present"] = True
        del row["id"]
        task, domain_statuses = _failure_redis_snapshot(redis_client, task_id)
        transcript = _smtp_transcript_snapshot(server)
        return {
            "phase": phase,
            "code": code,
            "recipient": recipient,
            "response": normalized_response,
            "wire": {
                "data_observed": transcript["data_event_count"] > 0,
                "data_event_count": transcript["data_event_count"],
                "data_bytes": transcript["data_bytes"],
            },
            "smtp": transcript,
            "redis": {
                "task": task,
                "task_present_after_archive": task is not None,
                "domains": domain_statuses,
                "aggregate_status": _java_aggregate_status(domain_statuses),
            },
            "db": row,
        }
    finally:
        redis_client.close()


def _post_failure_message(
    runtime: JavaOracleRuntime,
    *,
    recipient: str,
    subject: str,
    text: str,
) -> tuple[dict[str, Any], int]:
    if runtime.ports is None:
        raise AssertionError("runtime ports are unavailable")
    with httpx.Client(
        base_url=f"http://127.0.0.1:{runtime.ports.http}",
        headers={"X-API-Key": API_KEY},
        trust_env=False,
        timeout=5.0,
    ) as client:
        response = client.post(
            "/api/mail/send",
            json={
                "from": QA_ADDRESS,
                "password": QA_PASSWORD,
                "to": [recipient],
                "subject": subject,
                "text": text,
                "async": True,
            },
        )
    normalized = _normalize_response(response)
    task_id = response.json().get("queueId")
    if not isinstance(task_id, int):
        raise AssertionError(f"outbound failure case was not queued: {normalized!r}")
    return normalized, task_id


def _capture_terminal_failure(
    runtime: JavaOracleRuntime,
    client: redis.Redis,
    task_id: int,
    *,
    description: str,
) -> dict[str, Any]:
    def final_row() -> dict[str, Any] | None:
        return next((row for row in _db_rows(runtime) if row["id"] == task_id), None)

    _wait_until(
        lambda: (row := final_row()) is not None and row["status"] == "FAILED",
        timeout=45.0,
        description=f"{description} PostgreSQL failure archive",
    )
    _wait_until(
        lambda: client.llen(_REDIS_PREFIX + "archive") == 0
        and client.scard(_REDIS_PREFIX + "processing") == 0
        and client.zscore(_REDIS_PREFIX + "retry", task_id) is None,
        timeout=15.0,
        description=f"{description} Redis acknowledgement",
    )
    row = final_row()
    if row is None:
        raise AssertionError(f"terminal retry task {task_id} disappeared from PostgreSQL")
    row["id_present"] = isinstance(row.get("id"), int)
    del row["id"]
    task, domains = _failure_redis_snapshot(client, task_id)
    return {
        "db": row,
        "redis": {
            "task": task,
            "task_present_after_archive": task is not None,
            "retry_zset_member": client.zscore(_REDIS_PREFIX + "retry", task_id) is not None,
            "domains": domains,
            "aggregate_status": _java_aggregate_status(domains),
        },
    }


def _capture_4xx_case(
    server: ScriptedSmtpServer,
    runtime: JavaOracleRuntime,
    *,
    phase: str,
    code: int,
    case_index: int,
) -> dict[str, Any]:
    if runtime.ports is None:
        raise AssertionError("runtime ports are unavailable")
    recipient = f"recipient-{phase.lower()}-{code}-{case_index}@{_DNS_HOST}"
    client: redis.Redis = redis.Redis(
        host="127.0.0.1",
        port=runtime.ports.redis,
        decode_responses=False,
    )
    try:
        client.set(f"dns:mx:{_DNS_HOST}", _DNS_HOST.encode("ascii"), ex=300)
        response, task_id = _post_failure_message(
            runtime,
            recipient=recipient,
            subject=f"blackbox 4xx {phase} {code} {case_index}",
            text=f"4xx {phase} body {code} {case_index}",
        )
        _wait_until(
            lambda: _failure_reply_count(server, code) >= 1,
            timeout=30.0,
            description=f"4xx {phase} {code} first SMTP reply",
        )
        retryable = code in _RETRYABLE_FOURXX_CODES
        first_retry: dict[str, Any] | None = None
        forced_exhaustion_retry_count: int | None = None
        if retryable:
            failure_observed_at = time.time()
            first_retry = _capture_scheduled_retry(
                runtime,
                client,
                task_id,
                retry_count=1,
                expected_delay_seconds=_RETRY_DELAYS_SECONDS[0],
                failure_observed_at=failure_observed_at,
            )
            forced_exhaustion_retry_count = 5
            _force_retry_due(
                runtime,
                client,
                task_id,
                current_retry_count=1,
                due_retry_count=forced_exhaustion_retry_count,
                database_present=bool(first_retry["db"]["present"]),
            )
            _wait_until(
                lambda: _failure_reply_count(server, code) >= 2,
                timeout=30.0,
                description=f"4xx {phase} {code} exhausted SMTP reply",
            )
        terminal = _capture_terminal_failure(
            runtime,
            client,
            task_id,
            description=f"4xx {phase} {code}",
        )
        transcript = _smtp_transcript_snapshot(server)
        return {
            "phase": phase,
            "code": code,
            "classification": "retryable" if retryable else "terminal",
            "recipient": recipient,
            "response": response,
            "first_retry": first_retry,
            "forced_exhaustion_retry_count": forced_exhaustion_retry_count,
            "terminal": terminal,
            "wire": {
                "failure_reply_count": _failure_reply_count(server, code),
                "data_observed": transcript["data_event_count"] > 0,
                "data_event_count": transcript["data_event_count"],
                "data_bytes": transcript["data_bytes"],
            },
            "smtp": transcript,
        }
    finally:
        client.close()


def _capture_4xx_backoff_sequence(
    server: ScriptedSmtpServer,
    runtime: JavaOracleRuntime,
) -> dict[str, Any]:
    if runtime.ports is None:
        raise AssertionError("runtime ports are unavailable")
    code = 451
    recipient = f"recipient-backoff-{code}@{_DNS_HOST}"
    client: redis.Redis = redis.Redis(
        host="127.0.0.1",
        port=runtime.ports.redis,
        decode_responses=False,
    )
    try:
        client.set(f"dns:mx:{_DNS_HOST}", _DNS_HOST.encode("ascii"), ex=300)
        response, task_id = _post_failure_message(
            runtime,
            recipient=recipient,
            subject="blackbox 4xx full backoff sequence",
            text="4xx full backoff body",
        )
        retries: list[dict[str, Any]] = []
        for retry_count, expected_delay in enumerate(_RETRY_DELAYS_SECONDS, start=1):
            _wait_until(
                _failure_reply_count_reached(server, code, retry_count),
                timeout=30.0,
                description=f"4xx backoff SMTP reply {retry_count}",
            )
            failure_observed_at = time.time()
            retries.append(
                _capture_scheduled_retry(
                    runtime,
                    client,
                    task_id,
                    retry_count=retry_count,
                    expected_delay_seconds=expected_delay,
                    failure_observed_at=failure_observed_at,
                )
            )
            _force_retry_due(
                runtime,
                client,
                task_id,
                current_retry_count=retry_count,
                due_retry_count=retry_count,
                database_present=bool(retries[-1]["db"]["present"]),
            )
        _wait_until(
            lambda: _failure_reply_count(server, code) >= 6,
            timeout=30.0,
            description="4xx backoff exhausted SMTP reply",
        )
        terminal = _capture_terminal_failure(
            runtime,
            client,
            task_id,
            description="4xx full backoff",
        )
        transcript = _smtp_transcript_snapshot(server)
        return {
            "phase": "DATA",
            "code": code,
            "recipient": recipient,
            "response": response,
            "retries": retries,
            "terminal": terminal,
            "wire": {
                "failure_reply_count": _failure_reply_count(server, code),
                "data_event_count": transcript["data_event_count"],
                "data_bytes": transcript["data_bytes"],
            },
            "smtp": transcript,
        }
    finally:
        client.close()


def run_4xx_probe() -> dict[str, Any]:
    if (
        subprocess.run(  # noqa: S603
            ["/usr/sbin/ip", "link", "show", "lo"], capture_output=True
        ).returncode
        != 0
    ):
        raise AssertionError("outbound probe must run inside a network namespace with loopback")

    cases: list[dict[str, Any]] = []
    target = _outbound_target()
    dns_server = _candidate_dns_server() if target == "candidate" else None
    with tempfile.TemporaryDirectory(prefix="lmyzmail-outbound-4xx-oracle-") as workspace:
        runtime: JavaOracleRuntime
        if target == "candidate":
            repository = Path(__file__).resolve().parents[3]
            runtime = _candidate_runtime(repository)
        else:
            runtime = OutboundOracleRuntime(Path(workspace))
        if dns_server is not None:
            dns_server.start()
        try:
            with runtime:
                case_index = 0
                for phase in ("RCPT", "DATA"):
                    for code in _FOURXX_CODES:
                        case_index += 1
                        recipient = (
                            f"recipient-{phase.lower()}-{code}-{case_index}@{_DNS_HOST}"
                        )
                        reply = f"{code} fixture scripted {phase.lower()} retry\r\n".encode(
                            "ascii"
                        )
                        if phase == "RCPT":
                            scenario = SmtpScenario(
                                recipient_replies=(RecipientReply(recipient, reply),),
                                max_connections=4,
                                max_concurrent_connections=2,
                                max_message_bytes=2 * 1024 * 1024,
                            )
                        else:
                            scenario = SmtpScenario(
                                data_result_reply=reply,
                                max_connections=4,
                                max_concurrent_connections=2,
                                max_message_bytes=2 * 1024 * 1024,
                            )
                        server = ScriptedSmtpServer(
                            scenario, bind_host=_FAKE_IP, bind_port=25
                        )
                        with server:
                            cases.append(
                                _capture_4xx_case(
                                    server,
                                    runtime,
                                    phase=phase,
                                    code=code,
                                    case_index=case_index,
                                )
                            )
                backoff_server = ScriptedSmtpServer(
                    SmtpScenario(
                        data_result_reply=b"451 fixture scripted data retry\r\n",
                        max_connections=8,
                        max_concurrent_connections=2,
                        max_message_bytes=2 * 1024 * 1024,
                    ),
                    bind_host=_FAKE_IP,
                    bind_port=25,
                )
                with backoff_server:
                    backoff = _capture_4xx_backoff_sequence(backoff_server, runtime)
        finally:
            if dns_server is not None:
                dns_server.stop()
    return {
        "codes": list(_FOURXX_CODES),
        "retryable_codes": sorted(_RETRYABLE_FOURXX_CODES),
        "terminal_codes": sorted(set(_FOURXX_CODES) - _RETRYABLE_FOURXX_CODES),
        "phases": ["RCPT", "DATA"],
        "case_count": len(cases),
        "cases": cases,
        "backoff": backoff,
        "time_advancement": {
            "storage_contract": "legacy PostgreSQL row plus Redis task and retry ZSET",
            "wall_clock_modified": False,
            "observed_deadline_before_each_advance": True,
        },
    }


def run_5xx_probe() -> dict[str, Any]:
    if (
        subprocess.run(  # noqa: S603
            ["/usr/sbin/ip", "link", "show", "lo"], capture_output=True
        ).returncode
        != 0
    ):
        raise AssertionError("outbound probe must run inside a network namespace with loopback")

    codes = (500, 501, 549, 550, 554)
    cases: list[dict[str, Any]] = []
    target = _outbound_target()
    dns_server = _candidate_dns_server() if target == "candidate" else None
    with tempfile.TemporaryDirectory(prefix="lmyzmail-outbound-5xx-oracle-") as workspace:
        runtime: JavaOracleRuntime
        if target == "candidate":
            repository = Path(__file__).resolve().parents[3]
            runtime = _candidate_runtime(repository)
        else:
            runtime = OutboundOracleRuntime(Path(workspace))
        if dns_server is not None:
            dns_server.start()
        try:
            with runtime:
                case_index = 0
                for phase in ("RCPT", "DATA"):
                    for code in codes:
                        case_index += 1
                        recipient = f"recipient-{phase.lower()}-{code}-{case_index}@{_DNS_HOST}"
                        reply = f"{code} fixture scripted {phase.lower()} failure\r\n".encode(
                            "ascii"
                        )
                        if phase == "RCPT":
                            scenario = SmtpScenario(
                                recipient_replies=(RecipientReply(recipient, reply),),
                                max_connections=8,
                                max_concurrent_connections=2,
                                max_message_bytes=2 * 1024 * 1024,
                            )
                        else:
                            scenario = SmtpScenario(
                                data_result_reply=reply,
                                max_connections=8,
                                max_concurrent_connections=2,
                                max_message_bytes=2 * 1024 * 1024,
                            )
                        server = ScriptedSmtpServer(scenario, bind_host=_FAKE_IP, bind_port=25)
                        with server:
                            cases.append(
                                _capture_5xx_case(
                                    server,
                                    runtime,
                                    phase=phase,
                                    code=code,
                                    case_index=case_index,
                                )
                            )
        finally:
            if dns_server is not None:
                dns_server.stop()
    return {"codes": list(codes), "cases": cases, "case_count": len(cases)}


def run_probe() -> dict[str, Any]:
    if (
        subprocess.run(  # noqa: S603
            ["/usr/sbin/ip", "link", "show", "lo"], capture_output=True
        ).returncode
        != 0
    ):
        raise AssertionError("outbound probe must run inside a network namespace with loopback")
    scenario = SmtpScenario(
        max_connections=8,
        max_concurrent_connections=2,
        max_message_bytes=2 * 1024 * 1024,
    )
    server = ScriptedSmtpServer(scenario, bind_host=_FAKE_IP, bind_port=25)
    target = _outbound_target()
    dns_server = _candidate_dns_server() if target == "candidate" else None
    with tempfile.TemporaryDirectory(prefix="lmyzmail-outbound-oracle-") as workspace:
        runtime: JavaOracleRuntime
        if target == "candidate":
            repository = Path(__file__).resolve().parents[3]
            runtime = _candidate_runtime(repository)
        else:
            runtime = OutboundOracleRuntime(Path(workspace))
        if dns_server is not None:
            dns_server.start()
        try:
            with server:
                with runtime:
                    pre, post, ids, body_lengths = _capture_runtime(server, runtime)
        finally:
            if dns_server is not None:
                dns_server.stop()
    rows = [row for row in post["db"] if row["id"] in ids]
    for row in rows:
        row["id"] = ids[int(row["id"])]
    post["db"] = rows
    return {
        "responses": pre["responses"],
        "pre": pre,
        "post": post,
        "smtp": [_attempt_snapshot(value) for value in server.messages()],
        "smtp_event_kinds": [value.kind for value in server.events()],
        "body_lengths": body_lengths,
        "row_count": len(rows),
    }


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] != "--child":
        raise SystemExit("outbound_oracle_probe must be invoked through run-outbound-probe.sh")
    mode = os.environ.get("LMYZMAIL_OUTBOUND_ORACLE_MODE", "success").lower()
    if mode == "4xx":
        observed = run_4xx_probe()
    elif mode == "5xx":
        observed = run_5xx_probe()
    elif mode == "success":
        observed = run_probe()
    else:
        raise SystemExit(f"unsupported outbound oracle mode: {mode}")
    print(json.dumps(observed, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
