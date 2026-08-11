from __future__ import annotations

import base64
import json
import re
import time
from pathlib import Path
from typing import Any, cast

import psycopg
import redis

from .differential import RuntimeTarget, Scenario
from .normalize import FieldRule, JsonValue
from .protocols import RawHttpResponse, http_exchange
from .runtime import API_KEY, READ_ONLY_API_KEY, WRITE_ONLY_API_KEY
from .snapshots import bytes_snapshot, http_json_snapshot

_QUEUE_PREFIX = "botmail:mail:queue:"
_NORMALIZERS = (
    "header:date:http-date",
    "json-object-order:jdk-map-of",
    "stress:generated-queue-id-and-millis",
)
_DISABLED_NORMALIZERS = (*_NORMALIZERS, "brand:legacy-config-key-to-lmyzmail")
_MILLIS_RE = re.compile(rb"(?<= - )\d{10,19}")
_BODY_MILLIS_RE = re.compile(rb"(?m)^(Timestamp: )\d{10,19}(\r?)$")
_DATE_RE = re.compile(rb"(?im)^Date:[^\r\n]*")
_MESSAGE_ID_RE = re.compile(rb"(?im)^(Message-ID:\s*)<[^>]+>")


def _ports(target: RuntimeTarget) -> tuple[str, int, int, int]:
    if target.ports is None:
        raise AssertionError("stress target is not started")
    return "127.0.0.1", target.ports.http, target.ports.postgres, target.ports.redis


def _request(
    target: RuntimeTarget,
    path: str,
    *,
    key: str | None = API_KEY,
    expected_status: int,
) -> RawHttpResponse:
    host, http_port, _, _ = _ports(target)
    headers = () if key is None else (("X-API-Key", key),)
    response = http_exchange(host, http_port, "POST", path, headers=headers)
    if response.status_code != expected_status:
        raise AssertionError(
            f"stress response changed for POST {path}: "
            f"{response.status_line!r}, body={response.body!r}"
        )
    return response


def _json(
    target: RuntimeTarget,
    path: str,
    *,
    key: str | None = API_KEY,
    expected_status: int,
    rules: tuple[FieldRule, ...] = (),
) -> dict[str, Any]:
    return http_json_snapshot(
        _request(target, path, key=key, expected_status=expected_status),
        rules=rules,
        canonicalize_object_order=True,
    )


def _normalize_stress_enable_key(value: JsonValue) -> JsonValue:
    if not isinstance(value, str):
        raise AssertionError(f"stress disabled message changed type: {value!r}")
    return value.replace(
        "botmail.stress-test-enabled",
        "lmyzmail.stress-test-enabled",
    )


def capture_stress_disabled_and_permissions(target: RuntimeTarget) -> dict[str, Any]:
    return {
        "disabled": {
            route: _json(
                target,
                f"/api/stress/{route}",
                expected_status=403,
                rules=(FieldRule(("message",), _normalize_stress_enable_key),)
                if route == "start"
                else (),
            )
            for route in ("start", "reset", "status", "cleanup")
        },
        "permissions": {
            "missingStatusKey": _json(
                target,
                "/api/stress/status",
                key=None,
                expected_status=401,
            ),
            "writeOnlyStatus": _json(
                target,
                "/api/stress/status",
                key=WRITE_ONLY_API_KEY,
                expected_status=403,
            ),
            "readOnlyStart": _json(
                target,
                "/api/stress/start",
                key=READ_ONLY_API_KEY,
                expected_status=403,
            ),
        },
    }


cast(Any, capture_stress_disabled_and_permissions).__lmyzmail_contract__ = {
    "protocol": "HTTP/1.1 raw sockets",
    "configuration": "stress test disabled",
    "coverage": [
        "all four routes fail closed while disabled",
        "missing API key",
        "read permission on status",
        "write permission on start",
    ],
}


def _normalize_message(value: bytes) -> bytes:
    value = _DATE_RE.sub(b"Date: <DATE>", value)
    value = _MESSAGE_ID_RE.sub(rb"\1<MESSAGE_ID>", value)
    value = _MILLIS_RE.sub(b"<MILLIS>", value)
    return _BODY_MILLIS_RE.sub(rb"\1<MILLIS>\2", value)


def _task_snapshot(target: RuntimeTarget) -> dict[str, Any]:
    host, _, postgres_port, redis_port = _ports(target)
    client: redis.Redis = redis.Redis(
        host=host,
        port=redis_port,
        db=0,
        socket_timeout=1.0,
        socket_connect_timeout=1.0,
    )
    deadline = time.monotonic() + 15.0
    task_id: int | None = None
    detail: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        raw_ids = cast(list[bytes], client.lrange(_QUEUE_PREFIX + "pending", 0, -1))
        for raw_id in raw_ids:
            if not raw_id.isdigit():
                continue
            candidate_id = int(raw_id)
            raw_detail = cast(bytes | None, client.get(f"{_QUEUE_PREFIX}task:{candidate_id}"))
            if raw_detail is None:
                continue
            candidate = json.loads(raw_detail)
            if candidate.get("senderAddress") == "stress-sender@example.test":
                task_id = candidate_id
                detail = cast(dict[str, Any], candidate)
                break
        if detail is not None:
            break
        time.sleep(0.05)
    if task_id is None or detail is None:
        raise AssertionError("stress start did not publish its bounded outbound task")

    signed = detail.get("signedContentBase64")
    message_file = detail.get("messageFilePath")
    if isinstance(signed, str):
        storage_mode = "inline"
        message_bytes = base64.b64decode(signed, validate=True)
    elif isinstance(message_file, str):
        storage_mode = "spool"
        path = Path(message_file)
        stat = path.lstat()
        if not path.is_file() or path.is_symlink() or stat.st_size > 64 * 1024 * 1024:
            raise AssertionError(f"stress spool path is unsafe: {message_file!r}")
        message_bytes = path.read_bytes()
    else:
        raise AssertionError(f"stress task has no durable message source: {detail!r}")
    message = _normalize_message(message_bytes)
    ttl = cast(int, client.ttl(f"{_QUEUE_PREFIX}task:{task_id}"))
    if not 604_790 <= ttl <= 604_800:
        raise AssertionError(f"stress task TTL left the seven-day observation window: {ttl}")

    with psycopg.connect(
        host=host,
        port=postgres_port,
        dbname="lmyzmail",
        user="lmyzmail_test",
        password="",
        connect_timeout=3,
    ) as connection:
        addresses = [
            cast(str, row[0])
            for row in connection.execute(
                "SELECT address FROM mailbox WHERE address LIKE 'stress-%' ORDER BY address"
            ).fetchall()
        ]

    subject = detail.get("subject")
    if (
        not isinstance(subject, str)
        or re.fullmatch(r"Stress Test R1 #0 - \d{10,19}", subject) is None
    ):
        raise AssertionError(f"stress task subject changed: {subject!r}")
    return {
        "mailboxes": addresses,
        "task": {
            "senderAddress": detail.get("senderAddress"),
            "recipientsJson": json.loads(cast(str, detail.get("recipientsJson"))),
            "subject": re.sub(r"\d{10,19}$", "<MILLIS>", subject),
            "status": detail.get("status"),
            "retryCount": detail.get("retryCount"),
            "maxRetries": detail.get("maxRetries"),
            "messageIdPresent": bool(detail.get("messageId")),
            "sentFileNamePresent": bool(detail.get("sentFileName")),
            "sentSubdirectory": detail.get("sentSubdirectory"),
            "storageMode": storage_mode,
            "ttlSeconds": 604_800,
            "message": bytes_snapshot(message),
        },
    }


def capture_stress_enabled_lifecycle(target: RuntimeTarget) -> dict[str, Any]:
    before = _json(target, "/api/stress/status", expected_status=200)
    cleanup = _json(target, "/api/stress/cleanup", expected_status=200)
    started = _json(target, "/api/stress/start", expected_status=200)
    queued = _task_snapshot(target)
    after_start = _json(target, "/api/stress/status", expected_status=200)
    reset = _json(target, "/api/stress/reset", expected_status=200)
    after_reset = _json(target, "/api/stress/status", expected_status=200)
    return {
        "before": before,
        "cleanup": cleanup,
        "started": started,
        "queued": queued,
        "afterStart": after_start,
        "reset": reset,
        "afterReset": after_reset,
    }


cast(Any, capture_stress_enabled_lifecycle).__lmyzmail_contract__ = {
    "protocol": "HTTP/1.1 raw sockets plus isolated PostgreSQL and Redis state",
    "configuration": {
        "enabled": True,
        "warmupRounds": 1,
        "warmupCount": 1,
        "productionCount": 2,
        "emailSizeKB": 1,
    },
    "coverage": [
        "status before and after start",
        "warmup-to-production round transition",
        "one generated outbound task and seven-day TTL",
        "stress mailbox creation",
        "round reset",
        "manual cleanup response",
    ],
}


def capture_stress_streaming_lifecycle(target: RuntimeTarget) -> dict[str, Any]:
    return capture_stress_enabled_lifecycle(target)


cast(Any, capture_stress_streaming_lifecycle).__lmyzmail_contract__ = {
    "protocol": "HTTP/1.1 raw sockets plus isolated PostgreSQL, Redis, and spool state",
    "configuration": {
        "enabled": True,
        "warmupRounds": 1,
        "warmupCount": 1,
        "productionCount": 2,
        "emailSizeKB": 32,
    },
    "coverage": [
        "streaming mode response and status fields",
        "one exact 32 KiB generated body",
        "durable spool-backed outbound task",
        "stress mailbox creation and cleanup",
    ],
}


def capture_stress_concurrent_start_oracle(target: RuntimeTarget) -> dict[str, Any]:
    return {
        "first": _json(target, "/api/stress/start", expected_status=200),
        "second": _json(target, "/api/stress/start", expected_status=200),
    }


cast(Any, capture_stress_concurrent_start_oracle).__lmyzmail_contract__ = {
    "difference_id": "stress-bounded-run-admission",
    "protocol": "HTTP/1.1 raw sockets",
    "oracle_behavior": "two overlapping starts are both accepted and share test mailboxes",
    "candidate_requirement": "admit one run and reject an overlapping start with bounded 503 JSON",
}


def capture_stress_concurrent_start_candidate(target: RuntimeTarget) -> dict[str, Any]:
    return {
        "first": _json(target, "/api/stress/start", expected_status=200),
        "second": _json(target, "/api/stress/start", expected_status=503),
    }


def capture_stress_cleanup_during_run_oracle(target: RuntimeTarget) -> dict[str, Any]:
    return {
        "started": _json(target, "/api/stress/start", expected_status=200),
        "cleanup": _json(target, "/api/stress/cleanup", expected_status=200),
    }


cast(Any, capture_stress_cleanup_during_run_oracle).__lmyzmail_contract__ = {
    "difference_id": "stress-cleanup-run-serialization",
    "protocol": "HTTP/1.1 raw sockets",
    "oracle_behavior": "manual cleanup is accepted while a stress run owns the same mailboxes",
    "candidate_requirement": "reject cleanup while a stress run is active with bounded 503 JSON",
}


def capture_stress_cleanup_during_run_candidate(target: RuntimeTarget) -> dict[str, Any]:
    return {
        "started": _json(target, "/api/stress/start", expected_status=200),
        "cleanup": _json(target, "/api/stress/cleanup", expected_status=503),
    }


STRESS_DISABLED_SCENARIOS = (
    Scenario(
        "http/stress/disabled-and-permissions",
        capture_stress_disabled_and_permissions,
        _DISABLED_NORMALIZERS,
    ),
)

STRESS_ENABLED_SCENARIOS = (
    Scenario(
        "http/stress/enabled-lifecycle",
        capture_stress_enabled_lifecycle,
        _NORMALIZERS,
    ),
)

STRESS_STREAMING_SCENARIOS = (
    Scenario(
        "http/stress/streaming-lifecycle",
        capture_stress_streaming_lifecycle,
        _NORMALIZERS,
    ),
)

STRESS_CONCURRENT_ORACLE_SCENARIOS = (
    Scenario(
        "http/stress/oracle-concurrent-start",
        capture_stress_concurrent_start_oracle,
        _NORMALIZERS,
    ),
)

STRESS_CLEANUP_ORACLE_SCENARIOS = (
    Scenario(
        "http/stress/oracle-cleanup-during-run",
        capture_stress_cleanup_during_run_oracle,
        _NORMALIZERS,
    ),
)
