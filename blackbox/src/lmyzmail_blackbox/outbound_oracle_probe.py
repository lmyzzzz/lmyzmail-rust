from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import httpx
import psycopg
import redis

from .persistent_runtime import PersistentJavaOracleRuntime
from .runtime import API_KEY, QA_ADDRESS, QA_PASSWORD
from .scripted_smtp import RecipientReply, ScriptedSmtpServer, SmtpMessageAttempt, SmtpScenario

_REDIS_PREFIX = "botmail:mail:queue:"
_DOMAIN_STATUS_PREFIX = _REDIS_PREFIX + "domains:"
_SENTINEL = b"-999999999"
_DNS_HOST = "outbound.fixture.test"
_FAKE_IP = "93.184.216.34"
_RECIPIENT = f"recipient@{_DNS_HOST}"
_TASK_TTL_SECONDS = 7 * 24 * 60 * 60
_TASK_TTL_OBSERVATION_WINDOW_SECONDS = 30
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
    def decode(value: bytes) -> str:
        return value.decode("utf-8", errors="replace")

    pending_values = cast(list[bytes], client.lrange(_REDIS_PREFIX + "pending", 0, -1))
    pending = [
        _logical_id(int(value), ids)
        for value in pending_values
        if value.decode("ascii", errors="ignore").isdigit()
    ]
    processing_values = cast(set[bytes], client.smembers(_REDIS_PREFIX + "processing"))
    processing = sorted(
        _logical_id(int(value), ids)
        for value in processing_values
        if value.decode("ascii", errors="ignore").isdigit()
    )
    retry_values = cast(list[bytes], client.zrange(_REDIS_PREFIX + "retry", 0, -1))
    retry = [
        _logical_id(int(value), ids)
        for value in retry_values
        if value.decode("ascii", errors="ignore").isdigit()
    ]
    processing_time_values = cast(list[bytes], client.hkeys(_REDIS_PREFIX + "processing_time"))
    processing_time = sorted(
        _logical_id(int(value), ids)
        for value in processing_time_values
        if value.decode("ascii", errors="ignore").isdigit()
    )
    archive = client.llen(_REDIS_PREFIX + "archive")
    status_updates = client.llen(_REDIS_PREFIX + "status_updates")
    sent_index_values = cast(dict[bytes, bytes], client.hgetall(_REDIS_PREFIX + "sentfile_index"))
    sent_index: dict[str, str] = {}
    for filename, value in sent_index_values.items():
        if not value.decode("ascii", errors="ignore").isdigit():
            continue
        logical = _logical_id(int(value), ids)
        # Java embeds wall-clock time and a process-local counter in generated
        # sent filenames. The task-to-file relation is stable and is asserted
        # through the normalized key; legacy filenames remain byte-visible.
        normalized_key = f"generated:{logical}" if logical in ids.values() else decode(filename)
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


def _db_rows(runtime: OutboundOracleRuntime) -> list[dict[str, Any]]:
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


def _maildir_snapshot(runtime: OutboundOracleRuntime) -> dict[str, Any]:
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
    runtime: OutboundOracleRuntime,
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
            log_paths = sorted(workspace.glob("java-application-*.log"))
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
    runtime: OutboundOracleRuntime,
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
        task_before_archive, _ = _failure_redis_snapshot(redis_client, task_id)

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
                "task_before_archive": task_before_archive,
                "task": task,
                "task_present_after_archive": task is not None,
                "domains": domain_statuses,
                "aggregate_status": _java_aggregate_status(domain_statuses),
            },
            "db": row,
        }
    finally:
        redis_client.close()


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
    with tempfile.TemporaryDirectory(prefix="lmyzmail-outbound-5xx-oracle-") as workspace:
        runtime = OutboundOracleRuntime(Path(workspace))
        with runtime:
            case_index = 0
            for phase in ("RCPT", "DATA"):
                for code in codes:
                    case_index += 1
                    recipient = f"recipient-{phase.lower()}-{code}-{case_index}@{_DNS_HOST}"
                    reply = f"{code} fixture scripted {phase.lower()} failure\r\n".encode("ascii")
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
    with tempfile.TemporaryDirectory(prefix="lmyzmail-outbound-oracle-") as workspace:
        runtime = OutboundOracleRuntime(Path(workspace))
        with server:
            with runtime:
                pre, post, ids, body_lengths = _capture_runtime(server, runtime)
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
    if mode == "5xx":
        observed = run_5xx_probe()
    elif mode == "success":
        observed = run_probe()
    else:
        raise SystemExit(f"unsupported outbound oracle mode: {mode}")
    print(json.dumps(observed, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
