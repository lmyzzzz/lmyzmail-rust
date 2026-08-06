from __future__ import annotations

import base64
import hashlib
import json
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
from .scripted_smtp import ScriptedSmtpServer, SmtpMessageAttempt, SmtpScenario

_REDIS_PREFIX = "botmail:mail:queue:"
_SENTINEL = b"-999999999"
_DNS_HOST = "outbound.fixture.test"
_FAKE_IP = "93.184.216.34"
_RECIPIENT = f"recipient@{_DNS_HOST}"
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
    processing_time_values = cast(
        list[bytes], client.hkeys(_REDIS_PREFIX + "processing_time")
    )
    processing_time = sorted(
        _logical_id(int(value), ids)
        for value in processing_time_values
        if value.decode("ascii", errors="ignore").isdigit()
    )
    archive = client.llen(_REDIS_PREFIX + "archive")
    status_updates = client.llen(_REDIS_PREFIX + "status_updates")
    sent_index_values = cast(
        dict[bytes, bytes], client.hgetall(_REDIS_PREFIX + "sentfile_index")
    )
    sent_index: dict[str, str] = {}
    for filename, value in sent_index_values.items():
        if not value.decode("ascii", errors="ignore").isdigit():
            continue
        logical = _logical_id(int(value), ids)
        # Java embeds wall-clock time and a process-local counter in generated
        # sent filenames. The task-to-file relation is stable and is asserted
        # through the normalized key; legacy filenames remain byte-visible.
        normalized_key = (
            f"generated:{logical}" if logical in ids.values() else decode(filename)
        )
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
                Path(file_path).stat().st_size
                if file_path and Path(file_path).is_file()
                else None
            ),
            "ttl_seconds": max(0, cast(int, client.ttl(task_key))),
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
    small_body = "small outbound body"
    large_body = "L" * (12 * 1024)
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
            small_response = client.post(
                "/api/mail/send",
                json={
                    "from": QA_ADDRESS,
                    "password": QA_PASSWORD,
                    "to": [_RECIPIENT],
                    "subject": "blackbox small outbound",
                    "text": small_body,
                    "async": True,
                },
            )
            large_response = client.post(
                "/api/mail/send",
                json={
                    "from": QA_ADDRESS,
                    "password": QA_PASSWORD,
                    "to": [_RECIPIENT],
                    "subject": "blackbox large outbound",
                    "text": large_body,
                    "async": True,
                },
            )
        small_id = int(small_response.json()["queueId"])
        large_id = int(large_response.json()["queueId"])
        ids = {small_id: "small", large_id: "large"}
        pre: dict[str, Any] = {
            "responses": {
                "small": _normalize_response(small_response),
                "large": _normalize_response(large_response),
            },
            "redis": _redis_snapshot(redis_client, ids),
            "maildir": _maildir_snapshot(runtime),
        }
        try:
            _wait_until(
                lambda: len(server.messages()) >= 2,
                timeout=20.0,
                description="remote SMTP acceptance of both tasks",
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
            and all(
                row["status"] == "SENT"
                for row in _db_rows(runtime)
                if row["id"] in ids
            ),
            timeout=20.0,
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
        return pre, post, ids, {"small": len(small_body), "large": len(large_body)}
    finally:
        redis_client.close()


def run_probe() -> dict[str, Any]:
    if subprocess.run(  # noqa: S603
        ["/usr/sbin/ip", "link", "show", "lo"], capture_output=True
    ).returncode != 0:
        raise AssertionError("outbound probe must run inside a network namespace with loopback")
    scenario = SmtpScenario(
        max_connections=4,
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
    print(json.dumps(run_probe(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
