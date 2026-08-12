from __future__ import annotations

import base64
import email.policy
import hashlib
import ipaddress
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime
from email.parser import BytesParser
from pathlib import Path
from typing import Any, cast

import httpx
import psycopg
import redis

from .persistent_runtime import PersistentJavaOracleRuntime
from .runtime import API_KEY, QA_ADDRESS, QA_PASSWORD, CandidateRuntime, JavaOracleRuntime
from .scripted_dns import AAnswer, DnsAnswer, DnsQuery, ScriptedDnsServer, TxtAnswer
from .scripted_https import HttpsScenario, ScriptedHttpsServer
from .scripted_smtp import (
    RecipientReply,
    ScriptedSmtpServer,
    SmtpMessageAttempt,
    SmtpScenario,
)
from .tls_fixture import (
    EphemeralOutboundTlsMaterial,
    create_server_ssl_context,
    provision_ephemeral_outbound_tls_material,
)

_REDIS_PREFIX = "botmail:mail:queue:"
_DOMAIN_STATUS_PREFIX = _REDIS_PREFIX + "domains:"
_SENTINEL = b"-999999999"
_DNS_HOST = "outbound.fixture.test"
_FAKE_IP = "93.184.216.34"
_RECIPIENT = f"recipient@{_DNS_HOST}"
_TLS_MX_HOST = _DNS_HOST
_MTA_STS_CASE_DOMAINS = {
    "no_txt": "no-txt.sts.fixture.test",
    "malformed_txt": "malformed-txt.sts.fixture.test",
    "multiple_txt": "multiple-txt.sts.fixture.test",
    "a_failure": "a-failure.sts.fixture.test",
    "certificate_failure": "certificate-failure.sts.fixture.test",
    "status_404": "status-404.sts.fixture.test",
    "status_500": "status-500.sts.fixture.test",
    "redirect": "redirect.sts.fixture.test",
    "missing_content_type": "missing-content-type.sts.fixture.test",
    "wrong_content_type": "wrong-content-type.sts.fixture.test",
    "invalid_utf8": "invalid-utf8.sts.fixture.test",
    "malformed_policy": "malformed-policy.sts.fixture.test",
    "oversized_policy": "oversized-policy.sts.fixture.test",
    "timeout": "timeout.sts.fixture.test",
    "testing": "testing.sts.fixture.test",
    "none": "none.sts.fixture.test",
    "enforce": "enforce.sts.fixture.test",
    "zero": "zero.sts.fixture.test",
    "positive": "positive.sts.fixture.test",
}
_MTA_STS_POLICY_HOSTS = tuple(
    f"mta-sts.{domain}" for domain in _MTA_STS_CASE_DOMAINS.values()
)
_MTA_STS_JAVA_HOSTS = tuple(
    host
    for host in _MTA_STS_POLICY_HOSTS
    if host != f"mta-sts.{_MTA_STS_CASE_DOMAINS['a_failure']}"
)
_DSN_RECIPIENT = f"recipient-rcpt-550-1@{_DNS_HOST}"
_QA_DOMAIN = QA_ADDRESS.rsplit("@", 1)[1]
_DSN_ABSENCE_WINDOW_SECONDS = 8
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
_HEADER_BODY_SEPARATOR_RE = re.compile(rb"\r\n\r\n|\n\n|\r\r")


class OutboundOracleRuntime(PersistentJavaOracleRuntime):
    _hosts_file: Path | None = None

    def __init__(
        self,
        workspace_path: Path,
        *,
        outbound_tls_material: EphemeralOutboundTlsMaterial | None = None,
        mta_sts_enabled: bool = False,
    ) -> None:
        super().__init__(workspace_path, index_migration_enabled=False)
        self.outbound_tls_material = outbound_tls_material
        self.mta_sts_enabled = mta_sts_enabled

    def _application_arguments(self) -> list[str]:
        workspace, _ = self._require_state()
        hosts_file = workspace / "outbound-hosts"
        hosts_file.write_text(
            f"{_FAKE_IP} {_DNS_HOST} {' '.join(_MTA_STS_JAVA_HOSTS)}\n",
            encoding="ascii",
        )
        self._hosts_file = hosts_file
        arguments = super()._application_arguments()
        jar_index = arguments.index("-jar")
        arguments.insert(jar_index, f"-Djdk.net.hosts.file={hosts_file}")
        if self.outbound_tls_material is not None:
            arguments[jar_index:jar_index] = (
                f"-Djavax.net.ssl.trustStore={self.outbound_tls_material.java_truststore_path}",
                "-Djavax.net.ssl.trustStoreType=PKCS12",
                "-Djavax.net.ssl.trustStorePassword="
                f"{self.outbound_tls_material.java_truststore_password}",
            )
        if self.mta_sts_enabled:
            disabled = "--botmail.smtp.mta-sts-enabled=false"
            arguments[arguments.index(disabled)] = "--botmail.smtp.mta-sts-enabled=true"
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
                "--botmail.outbound.read-timeout-ms=1000",
                "--dns.cache.mx.query-timeout-seconds=1",
            )
        )
        return arguments


class OutboundCandidateRuntime(CandidateRuntime):
    def __init__(
        self,
        *args: Any,
        outbound_tls_material: EphemeralOutboundTlsMaterial | None = None,
        mta_sts_enabled: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.outbound_tls_material = outbound_tls_material
        self.mta_sts_enabled = mta_sts_enabled

    def _candidate_configuration(self) -> Path:
        path = super()._candidate_configuration()
        if self.mta_sts_enabled:
            value = json.loads(path.read_text(encoding="utf-8"))
            value["features"]["mta_sts"] = True
            path.write_text(
                json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
        return path

    def _application_environment(self) -> dict[str, str]:
        environment = super()._application_environment()
        if self.outbound_tls_material is not None:
            environment["SSL_CERT_FILE"] = str(self.outbound_tls_material.ca_certificate_path)
        return environment

    def _application_arguments(self) -> list[str]:
        arguments = CandidateRuntime._application_arguments(self)
        arguments.extend(
            (
                "--lmyzmail.queue.poll-interval-ms=3000",
                "--lmyzmail.queue.batch-size=2",
                "--lmyzmail.queue.max-concurrent-sends=1",
                "--lmyzmail.outbound.pool-enabled=false",
                "--lmyzmail.outbound.helo-hostname=blackbox.example",
                "--lmyzmail.outbound.read-timeout-ms=1000",
                "--lmyzmail.outbound.dns.query-timeout-seconds=1",
                "--lmyzmail.maildir.max-files-per-directory=1",
            )
        )
        return arguments

    def restart_application(self) -> None:
        if self._application is None or self._port_allocator is None:
            raise RuntimeError("candidate application is not running")
        self._application.stop(
            timeout=self.shutdown_timeout,
            kill_timeout=self.shutdown_kill_timeout,
        )
        self._application = None
        for port in self._application_service_ports():
            self._port_allocator.reserve_port(port)
        self._application_ports_released = False
        self._start_application()


def _outbound_target() -> str:
    target = os.environ.get(_OUTBOUND_TARGET_ENV, "java").casefold()
    if target not in {"java", "candidate"}:
        raise AssertionError(f"unsupported outbound target: {target}")
    return target


def _candidate_runtime(
    repository: Path,
    *,
    outbound_tls_material: EphemeralOutboundTlsMaterial | None = None,
    mta_sts_enabled: bool = False,
) -> OutboundCandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        runtime = cast(
            OutboundCandidateRuntime,
            OutboundCandidateRuntime.from_environment(),
        )
        runtime.outbound_tls_material = outbound_tls_material
        runtime.mta_sts_enabled = mta_sts_enabled
        return runtime
    return OutboundCandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        ),
        outbound_tls_material=outbound_tls_material,
        mta_sts_enabled=mta_sts_enabled,
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


def _outbound_dns_server(
    answers: dict[tuple[str, int], DnsAnswer],
) -> ScriptedDnsServer:
    nameserver = _ipv4_nameserver()
    result = subprocess.run(  # noqa: S603
        ["/usr/sbin/ip", "address", "add", f"{nameserver}/32", "dev", "lo"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 and "File exists" not in result.stderr:
        raise AssertionError(
            f"failed to pin outbound DNS fixture address: {result.stderr.strip()}"
        )
    return ScriptedDnsServer(answers, bind_host=nameserver, bind_port=53)


def _candidate_dsn_dns_server() -> ScriptedDnsServer:
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
        {
            (_DNS_HOST, 1): DnsAnswer(a=(AAnswer(_FAKE_IP, ttl=0),)),
            (_QA_DOMAIN, 1): DnsAnswer(a=(AAnswer(_FAKE_IP, ttl=0),)),
        },
        bind_host=nameserver,
        bind_port=53,
    )


def _normalize_message(value: bytes) -> bytes:
    separator = _HEADER_BODY_SEPARATOR_RE.search(value)
    header_end = separator.start() if separator is not None else len(value)
    headers = value[:header_end]
    body = value[header_end:]
    headers = _DATE_RE.sub(rb"Date: <NORMALIZED>", headers)
    headers = _MESSAGE_ID_RE.sub(rb"\1<MESSAGE_ID>", headers)
    headers = _DKIM_RE.sub(b"DKIM-Signature: <NORMALIZED>\r\n", headers)
    return headers + body


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


def _sent_maildir_owner_counts(runtime: JavaOracleRuntime) -> dict[str, int]:
    if runtime.workspace is None:
        raise AssertionError("runtime workspace is unavailable")
    root = runtime.workspace / "maildir"
    counts: dict[str, int] = {}
    if root.exists():
        for owner in root.iterdir():
            sent = owner / "sent"
            if not owner.is_dir() or not sent.is_dir():
                continue
            count = sum(1 for path in sent.rglob("*.eml") if path.is_file())
            if count:
                counts[owner.name] = count
    return dict(sorted(counts.items()))


def _outbound_worklist_lengths(runtime: JavaOracleRuntime) -> dict[str, int]:
    if runtime.ports is None:
        raise AssertionError("runtime ports are unavailable")
    client: redis.Redis = redis.Redis(
        host="127.0.0.1",
        port=runtime.ports.redis,
        decode_responses=False,
    )
    try:
        return {
            "pending": cast(int, client.llen(_REDIS_PREFIX + "pending")),
            "processing": cast(int, client.scard(_REDIS_PREFIX + "processing")),
            "retry": cast(int, client.zcard(_REDIS_PREFIX + "retry")),
            "archive": cast(int, client.llen(_REDIS_PREFIX + "archive")),
            "status_updates": cast(int, client.llen(_REDIS_PREFIX + "status_updates")),
        }
    finally:
        client.close()


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
    zset_deadline = cast(float | None, client.zscore(_REDIS_PREFIX + "retry", task_id))
    if zset_deadline is None:
        raise AssertionError(f"retry task {task_id} has no retry ZSET deadline")
    task_deadline = _parse_retry_instant(detail.get("nextRetryAt"), source="Redis task")
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
        database_deadline_matches = abs(float(database["next_retry_epoch"]) - task_deadline) <= 1.0
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
        raise AssertionError(f"retry task {task_id} changed before time advancement: {detail!r}")
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
        event.kind == "reply" and event.payload.startswith(prefix) for event in server.events()
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


def _outbound_tls_transcript(server: ScriptedSmtpServer) -> dict[str, Any]:
    commands = [
        {
            "connection": event.connection_id,
            "value": event.payload.decode("ascii", errors="replace").rstrip("\r\n"),
        }
        for event in server.events()
        if event.kind == "command"
    ]
    established = [
        event.connection_id for event in server.events() if event.kind == "tls-established"
    ]
    return {
        "connections": sorted({event.connection_id for event in server.events()}),
        "commands": commands,
        "tls_established_connections": established,
        "attempts": [
            {"connection_id": value.connection_id, **_attempt_snapshot(value)}
            for value in server.messages()
        ],
        "fixture_terminal_events": [
            {
                "connection": event.connection_id,
                "kind": event.kind,
            }
            for event in server.events()
            if event.kind in {"peer-closed", "peer-disconnected", "protocol-error"}
        ],
    }


def _tls_case_terminal(
    runtime: JavaOracleRuntime,
    task_id: int,
    *,
    expected_status: str,
    description: str,
) -> dict[str, Any]:
    def terminal_row() -> dict[str, Any] | None:
        return next((row for row in _db_rows(runtime) if row["id"] == task_id), None)

    try:
        _wait_until(
            lambda: (row := terminal_row()) is not None and row["status"] == expected_status,
            timeout=45.0,
            description=description,
        )
    except AssertionError as error:
        rows = _db_rows(runtime)
        raise AssertionError(f"{error}; outbound_rows={rows!r}") from error
    row = terminal_row()
    if row is None:
        raise AssertionError(f"outbound TLS task {task_id} disappeared")
    return {
        "status": row["status"],
        "retry_count": row["retry_count"],
        "last_error": row["last_error"],
    }


def _run_outbound_tls_case(
    runtime: JavaOracleRuntime,
    server: ScriptedSmtpServer,
    *,
    label: str,
    expected_status: str,
    mta_sts_policy: str | None = None,
) -> dict[str, Any]:
    if runtime.ports is None:
        raise AssertionError("runtime ports are unavailable")
    client: redis.Redis = redis.Redis(
        host="127.0.0.1",
        port=runtime.ports.redis,
        decode_responses=False,
    )
    try:
        client.set(f"dns:mx:{_DNS_HOST}", _DNS_HOST.encode("ascii"), ex=300)
        if mta_sts_policy is not None:
            client.set(f"mta-sts:{_DNS_HOST}", mta_sts_policy.encode("ascii"), ex=300)
        response, task_id = _post_failure_message(
            runtime,
            recipient=_RECIPIENT,
            subject=f"blackbox outbound TLS {label}",
            text=f"outbound TLS body {label}",
        )
        terminal = _tls_case_terminal(
            runtime,
            task_id,
            expected_status=expected_status,
            description=f"outbound TLS {label} {expected_status}",
        )
        return {
            "response": response,
            "terminal": terminal,
            "smtp": _outbound_tls_transcript(server),
        }
    finally:
        client.close()


def _mta_sts_policy_body(*, mode: str, max_age: int, mx: str = _DNS_HOST) -> bytes:
    return (
        f"version: STSv1\r\nmode: {mode}\r\nmx: {mx}\r\nmax_age: {max_age}\r\n"
    ).encode("ascii")


def _mta_sts_dns_answers() -> dict[tuple[str, int], DnsAnswer]:
    answers: dict[tuple[str, int], DnsAnswer] = {
        (_DNS_HOST, 1): DnsAnswer(a=(AAnswer(_FAKE_IP, ttl=0),)),
    }
    for label, domain in _MTA_STS_CASE_DOMAINS.items():
        if label == "no_txt":
            continue
        txt = (
            (
                TxtAnswer(("v=STSv1; id=First1;",), ttl=0),
                TxtAnswer(("v=STSv1; id=Second2;",), ttl=0),
            )
            if label == "multiple_txt"
            else (TxtAnswer(("v=STSv1; id=bad-id;",), ttl=0),)
            if label == "malformed_txt"
            else (
                TxtAnswer(
                    (f"v=STSv1; id={label.title().replace('_', '')}1;",), ttl=0
                ),
            )
        )
        answers[(f"_mta-sts.{domain}", 16)] = DnsAnswer(txt=txt)
        if label != "a_failure":
            answers[(f"mta-sts.{domain}", 1)] = DnsAnswer(
                a=(AAnswer(_FAKE_IP, ttl=0),)
            )
            answers[(f"mta-sts.{domain}", 28)] = DnsAnswer()
    return answers


def _mta_sts_dns_snapshot(queries: tuple[DnsQuery, ...]) -> list[dict[str, Any]]:
    relevant_suffixes = tuple(f".{domain}" for domain in _MTA_STS_CASE_DOMAINS.values())
    return [
        {"name": query.qname, "type": query.qtype, "class": query.qclass}
        for query in queries
        if query.qname == _DNS_HOST
        or any(query.qname.endswith(suffix) for suffix in relevant_suffixes)
    ]


def _mta_sts_https_snapshot(server: ScriptedHttpsServer | None) -> dict[str, Any]:
    if server is None:
        return {"handshake_failures": 0, "requests": []}
    requests: list[dict[str, Any]] = []
    for request in server.requests():
        headers = {name.casefold(): value for name, value in request.headers}
        requests.append(
            {
                "connection": request.connection_id,
                "method": request.method,
                "target": request.target,
                "version": request.version,
                "host": headers.get("host"),
                "user_agent": headers.get("user-agent"),
                "sni": request.sni,
                "tls_protocol": request.tls_protocol,
                "tls_cipher": request.tls_cipher,
                "tls_secret_bits": request.tls_secret_bits,
            }
        )
    return {"handshake_failures": server.handshake_failures(), "requests": requests}


def _mta_sts_scenario_snapshot(scenario: HttpsScenario | None) -> dict[str, Any] | None:
    if scenario is None:
        return None
    content_type = next(
        (value for name, value in scenario.headers if name.casefold() == "content-type"),
        None,
    )
    return {
        "status": scenario.status,
        "content_type": content_type,
        "body_bytes": len(scenario.body),
        "body_sha256": _digest(scenario.body),
        "response_delay_seconds": scenario.response_delay_seconds,
    }


def _mta_sts_cache_snapshot(
    client: redis.Redis,
    domain: str,
    *,
    expected_ttl: int | None,
) -> dict[str, Any]:
    key = f"mta-sts:{domain}"
    value = client.get(key)
    ttl_millis = cast(int, client.pttl(key))
    if expected_ttl is None:
        if value is not None or ttl_millis != -2:
            raise AssertionError(f"unexpected MTA-STS cache entry for {domain}: {value!r}")
        return {"present": False, "ttl_seconds": None, "value": None}
    if not isinstance(value, bytes):
        raise AssertionError(f"MTA-STS cache entry is missing for {domain}")
    if not (expected_ttl * 1000 - 30_000 <= ttl_millis <= expected_ttl * 1000):
        raise AssertionError(
            f"MTA-STS cache TTL for {domain} is outside its observation window: {ttl_millis}"
        )
    fields = value.decode("utf-8", errors="strict").split("|")
    if len(fields) != 6 or not fields[5].isdigit() or int(fields[5]) <= 0:
        raise AssertionError(f"MTA-STS cache serialization is invalid for {domain}: {value!r}")
    return {
        "present": True,
        "ttl_seconds": expected_ttl,
        "value": {
            "version": fields[0],
            "mode": fields[1],
            "mx": fields[2],
            "max_age": fields[3],
            "policy_id": fields[4],
            "fetched_at_present": True,
        },
    }


def _mta_sts_case(
    runtime: JavaOracleRuntime,
    dns: ScriptedDnsServer,
    smtp: ScriptedSmtpServer,
    *,
    label: str,
    expected_status: str,
    expected_ttl: int | None,
    https_server: ScriptedHttpsServer | None,
    https_scenario: HttpsScenario | None = None,
    deliveries: int = 1,
) -> dict[str, Any]:
    if runtime.ports is None:
        raise AssertionError("runtime ports are unavailable")
    domain = _MTA_STS_CASE_DOMAINS[label]
    client: redis.Redis = redis.Redis(
        host="127.0.0.1", port=runtime.ports.redis, decode_responses=False
    )
    dns.drain_queries()
    before_smtp_attempts = len(smtp.messages())
    try:
        client.set(f"dns:mx:{domain}", _DNS_HOST.encode("ascii"), ex=300)
        observations: list[dict[str, Any]] = []
        for index in range(deliveries):
            response, task_id = _post_failure_message(
                runtime,
                recipient=f"recipient-{label}-{index}@{domain}",
                subject=f"blackbox MTA-STS discovery {label} {index}",
                text=f"MTA-STS discovery body {label} {index}",
            )
            observations.append(
                {
                    "response": response,
                    "terminal": _tls_case_terminal(
                        runtime,
                        task_id,
                        expected_status=expected_status,
                        description=f"MTA-STS discovery {label} {index}",
                    ),
                }
            )
        return {
            "deliveries": observations,
            "dns": _mta_sts_dns_snapshot(dns.drain_queries()),
            "https": _mta_sts_https_snapshot(https_server),
            "https_scenario": _mta_sts_scenario_snapshot(https_scenario),
            "redis": _mta_sts_cache_snapshot(client, domain, expected_ttl=expected_ttl),
            "smtp_attempt_count": len(smtp.messages()) - before_smtp_attempts,
        }
    finally:
        client.close()


def _mta_sts_https_server(
    material: EphemeralOutboundTlsMaterial,
    scenario: HttpsScenario,
) -> ScriptedHttpsServer:
    if material.policy_server is None:
        raise AssertionError("MTA-STS policy TLS identity was not provisioned")
    return ScriptedHttpsServer(
        scenario,
        tls_context=create_server_ssl_context(material.policy_server),
        bind_host=_FAKE_IP,
        bind_port=443,
    )


def _mta_sts_scenario(label: str) -> tuple[HttpsScenario, int | None]:
    if label == "certificate_failure":
        return (
            HttpsScenario(body=_mta_sts_policy_body(mode="testing", max_age=600)),
            300,
        )
    if label == "status_404":
        return HttpsScenario(status=404, reason="Not Found"), 300
    if label == "status_500":
        return HttpsScenario(status=500, reason="Internal Server Error"), 300
    if label == "redirect":
        return (
            HttpsScenario(
                status=302,
                reason="Found",
                headers=(
                    ("Content-Type", "text/plain"),
                    ("Location", "https://redirect.invalid/policy"),
                ),
            ),
            300,
        )
    if label == "missing_content_type":
        return (
            HttpsScenario(
                headers=(), body=_mta_sts_policy_body(mode="enforce", max_age=600)
            ),
            300,
        )
    if label == "wrong_content_type":
        return (
            HttpsScenario(
                headers=(("Content-Type", "text/html"),),
                body=_mta_sts_policy_body(mode="enforce", max_age=600),
            ),
            300,
        )
    if label == "invalid_utf8":
        return HttpsScenario(body=b"version: STSv1\r\nmode: testing\r\nmx: \xff\r\n"), 300
    if label == "malformed_policy":
        return (
            HttpsScenario(
                body=b"version: STSv1\r\nmode: enforce\r\nmx: outbound.fixture.test\r\n"
            ),
            300,
        )
    if label == "oversized_policy":
        return (
            HttpsScenario(
                body=_mta_sts_policy_body(mode="testing", max_age=600)
                + b"#"
                + b"x" * (64 * 1024),
                response_chunk_bytes=16 * 1024,
            ),
            300,
        )
    if label == "timeout":
        return (
            HttpsScenario(
                body=_mta_sts_policy_body(mode="testing", max_age=600),
                response_delay_seconds=15.0,
            ),
            300,
        )
    if label == "testing":
        return (
            HttpsScenario(body=_mta_sts_policy_body(mode="testing", max_age=600)),
            600,
        )
    if label == "none":
        return (
            HttpsScenario(body=_mta_sts_policy_body(mode="none", max_age=600)),
            300,
        )
    if label == "enforce":
        return (
            HttpsScenario(body=_mta_sts_policy_body(mode="enforce", max_age=600)),
            600,
        )
    if label == "zero":
        return (
            HttpsScenario(body=_mta_sts_policy_body(mode="testing", max_age=0)),
            None,
        )
    if label == "positive":
        return (
            HttpsScenario(body=_mta_sts_policy_body(mode="testing", max_age=600)),
            600,
        )
    raise AssertionError(f"MTA-STS HTTPS scenario is unsupported: {label}")


def run_mta_sts_discovery_probe() -> dict[str, Any]:
    if (
        subprocess.run(  # noqa: S603
            ["/usr/sbin/ip", "link", "show", "lo"], capture_output=True
        ).returncode
        != 0
    ):
        raise AssertionError("outbound probe must run inside a network namespace with loopback")

    target = _outbound_target()
    repository = Path(__file__).resolve().parents[3]
    dns = _outbound_dns_server(_mta_sts_dns_answers())
    with tempfile.TemporaryDirectory(prefix="lmyzmail-mta-sts-discovery-") as workspace:
        workspace_path = Path(workspace)
        material_workspace = workspace_path / "material"
        material_workspace.mkdir(mode=0o700)
        material = provision_ephemeral_outbound_tls_material(
            material_workspace,
            mx_hostname=_TLS_MX_HOST,
            policy_hostnames=_MTA_STS_POLICY_HOSTS,
        )
        runtime: OutboundOracleRuntime | OutboundCandidateRuntime
        if target == "candidate":
            runtime = _candidate_runtime(
                repository,
                outbound_tls_material=material,
                mta_sts_enabled=True,
            )
        else:
            runtime = OutboundOracleRuntime(
                workspace_path / "runtime",
                outbound_tls_material=material,
                mta_sts_enabled=True,
            )
        smtp = _mta_sts_plaintext_server()
        cases: dict[str, Any] = {}
        with dns, smtp, runtime:
            for label in ("no_txt", "malformed_txt", "multiple_txt", "a_failure"):
                cases[label] = _mta_sts_case(
                    runtime,
                    dns,
                    smtp,
                    label=label,
                    expected_status="SENT",
                    expected_ttl=300,
                    https_server=None,
                )
            for label in (
                "certificate_failure",
                "status_404",
                "status_500",
                "redirect",
                "missing_content_type",
                "wrong_content_type",
                "invalid_utf8",
                "malformed_policy",
                "oversized_policy",
                "timeout",
                "testing",
                "none",
                "enforce",
                "zero",
                "positive",
            ):
                scenario, expected_ttl = _mta_sts_scenario(label)
                if label == "certificate_failure":
                    if material.untrusted_policy_server is None:
                        raise AssertionError("untrusted policy TLS identity was not provisioned")
                    server = ScriptedHttpsServer(
                        HttpsScenario(
                            body=_mta_sts_policy_body(mode="testing", max_age=600)
                        ),
                        tls_context=create_server_ssl_context(
                            material.untrusted_policy_server
                        ),
                        bind_host=_FAKE_IP,
                        bind_port=443,
                    )
                else:
                    server = _mta_sts_https_server(material, scenario)
                with server:
                    cases[label] = _mta_sts_case(
                        runtime,
                        dns,
                        smtp,
                        label=label,
                        expected_status="FAILED" if label == "enforce" else "SENT",
                        expected_ttl=expected_ttl,
                        https_server=server,
                        https_scenario=scenario,
                        deliveries=2 if label in {"zero", "positive"} else 1,
                    )

            runtime.restart_application()
            cases["no_txt_restart"] = _mta_sts_case(
                runtime,
                dns,
                smtp,
                label="no_txt",
                expected_status="SENT",
                expected_ttl=300,
                https_server=None,
            )
            cases["positive_restart"] = _mta_sts_case(
                runtime,
                dns,
                smtp,
                label="positive",
                expected_status="SENT",
                expected_ttl=600,
                https_server=None,
            )
        return {"target": target, "cases": cases}


def _starttls_server(
    material: EphemeralOutboundTlsMaterial,
    identity: str,
    *,
    starttls_reply: bytes = b"220 2.0.0 ready to start TLS\r\n",
    tls_handshake_delay_seconds: float = 0.0,
    minimum_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
    maximum_version: ssl.TLSVersion = ssl.TLSVersion.MAXIMUM_SUPPORTED,
    ciphers: str | None = None,
) -> ScriptedSmtpServer:
    selected = getattr(material, identity)
    return ScriptedSmtpServer(
        SmtpScenario(
            hostname=_TLS_MX_HOST,
            tls_context=create_server_ssl_context(
                selected,
                minimum_version=minimum_version,
                maximum_version=maximum_version,
                ciphers=ciphers,
            ),
            starttls_reply=starttls_reply,
            tls_handshake_delay_seconds=tls_handshake_delay_seconds,
            max_connections=8,
            max_concurrent_connections=2,
            max_message_bytes=2 * 1024 * 1024,
        ),
        bind_host=_FAKE_IP,
        bind_port=25,
    )


def _tls_sessions(server: ScriptedSmtpServer) -> list[dict[str, Any]]:
    sessions: list[dict[str, Any]] = []
    for event in server.events():
        if event.kind != "tls-established":
            continue
        protocol, cipher, secret_bits = event.payload.decode("ascii").split("|")
        sessions.append(
            {
                "connection": event.connection_id,
                "protocol": protocol,
                "cipher": cipher,
                "secret_bits": int(secret_bits),
            }
        )
    return sessions


def _plaintext_server() -> ScriptedSmtpServer:
    return ScriptedSmtpServer(
        SmtpScenario(
            hostname=_TLS_MX_HOST,
            max_connections=8,
            max_concurrent_connections=2,
            max_message_bytes=2 * 1024 * 1024,
        ),
        bind_host=_FAKE_IP,
        bind_port=25,
    )


def _mta_sts_plaintext_server() -> ScriptedSmtpServer:
    return ScriptedSmtpServer(
        SmtpScenario(
            hostname=_TLS_MX_HOST,
            max_connections=32,
            max_concurrent_connections=2,
            max_message_bytes=2 * 1024 * 1024,
        ),
        bind_host=_FAKE_IP,
        bind_port=25,
    )


def run_tls_probe() -> dict[str, Any]:
    if (
        subprocess.run(  # noqa: S603
            ["/usr/sbin/ip", "link", "show", "lo"], capture_output=True
        ).returncode
        != 0
    ):
        raise AssertionError("outbound probe must run inside a network namespace with loopback")

    target = _outbound_target()
    repository = Path(__file__).resolve().parents[3]
    dns_server = _candidate_dns_server() if target == "candidate" else None
    with tempfile.TemporaryDirectory(prefix="lmyzmail-outbound-tls-oracle-") as workspace:
        workspace_path = Path(workspace)
        material_workspace = workspace_path / "material"
        material_workspace.mkdir(mode=0o700)
        material = provision_ephemeral_outbound_tls_material(
            material_workspace,
            mx_hostname=_TLS_MX_HOST,
        )
        if dns_server is not None:
            dns_server.start()
        try:
            cases: dict[str, Any] = {}

            if target == "candidate":
                opportunistic_runtime: JavaOracleRuntime = _candidate_runtime(
                    repository,
                    outbound_tls_material=material,
                )
            else:
                opportunistic_runtime = OutboundOracleRuntime(
                    workspace_path / "opportunistic-runtime",
                    outbound_tls_material=material,
                )
            with opportunistic_runtime as runtime:
                trusted = _starttls_server(material, "matching_server")
                with trusted:
                    cases["opportunistic_trusted"] = _run_outbound_tls_case(
                        runtime,
                        trusted,
                        label="opportunistic trusted",
                        expected_status="SENT",
                    )

                untrusted = _starttls_server(material, "untrusted_server")
                with untrusted:
                    _, task_id = _post_failure_message(
                        runtime,
                        recipient=_RECIPIENT,
                        subject="blackbox outbound TLS untrusted fallback",
                        text="outbound TLS untrusted fallback body",
                    )
                    _wait_until(
                        lambda: len(untrusted.messages()) == 1,
                        timeout=45.0,
                        description="fresh plaintext fallback after TLS handshake failure",
                    )
                    cases["opportunistic_untrusted_fallback"] = {
                        "terminal": _tls_case_terminal(
                            runtime,
                            task_id,
                            expected_status="SENT",
                            description="untrusted TLS plaintext fallback archive",
                        ),
                        "smtp": _outbound_tls_transcript(untrusted),
                    }

                rejected = _starttls_server(
                    material,
                    "matching_server",
                    starttls_reply=b"454 4.7.0 fixture TLS rejection\r\n",
                )
                with rejected:
                    _, task_id = _post_failure_message(
                        runtime,
                        recipient=_RECIPIENT,
                        subject="blackbox outbound TLS rejected fallback",
                        text="outbound TLS rejected fallback body",
                    )
                    _wait_until(
                        lambda: len(rejected.messages()) == 1,
                        timeout=45.0,
                        description="fresh plaintext fallback after STARTTLS rejection",
                    )
                    cases["opportunistic_rejected_fallback"] = {
                        "terminal": _tls_case_terminal(
                            runtime,
                            task_id,
                            expected_status="SENT",
                            description="rejected STARTTLS plaintext fallback archive",
                        ),
                        "smtp": _outbound_tls_transcript(rejected),
                    }

                mismatched = _starttls_server(material, "mismatched_server")
                with mismatched:
                    _, task_id = _post_failure_message(
                        runtime,
                        recipient=_RECIPIENT,
                        subject="blackbox outbound TLS hostname mismatch",
                        text="outbound TLS hostname mismatch body",
                    )
                    if target == "java":
                        _wait_until(
                            lambda: len(mismatched.messages()) == 1,
                            timeout=45.0,
                            description="Java opportunistic hostname mismatch acceptance",
                        )
                        cases["opportunistic_hostname_mismatch"] = {
                            "outcome": "tls-accepted-without-hostname-verification",
                            "terminal": _tls_case_terminal(
                                runtime,
                                task_id,
                                expected_status="SENT",
                                description="Java hostname mismatch archive",
                            ),
                            "smtp": _outbound_tls_transcript(mismatched),
                        }
                    else:
                        _wait_until(
                            lambda: len(mismatched.messages()) == 1,
                            timeout=45.0,
                            description="Rust hostname mismatch plaintext fallback",
                        )
                        cases["opportunistic_hostname_mismatch"] = {
                            "outcome": "hostname-verified-then-plaintext-fallback",
                            "terminal": _tls_case_terminal(
                                runtime,
                                task_id,
                                expected_status="SENT",
                                description="Rust hostname mismatch fallback archive",
                            ),
                            "smtp": _outbound_tls_transcript(mismatched),
                        }

            if target == "candidate":
                enforce_runtime: JavaOracleRuntime = _candidate_runtime(
                    repository,
                    outbound_tls_material=material,
                    mta_sts_enabled=True,
                )
            else:
                enforce_runtime = OutboundOracleRuntime(
                    workspace_path / "enforce-runtime",
                    outbound_tls_material=material,
                    mta_sts_enabled=True,
                )
            with enforce_runtime as runtime:
                policy = f"STSv1|ENFORCE|{_TLS_MX_HOST}|300|Policy1|{int(time.time() * 1000)}"
                enforced = _starttls_server(material, "matching_server")
                with enforced:
                    cases["mta_sts_enforce_trusted"] = _run_outbound_tls_case(
                        runtime,
                        enforced,
                        label="MTA-STS enforce trusted",
                        expected_status="SENT",
                        mta_sts_policy=policy,
                    )

                enforce_plaintext = _plaintext_server()
                with enforce_plaintext:
                    cases["mta_sts_enforce_missing_starttls"] = _run_outbound_tls_case(
                        runtime,
                        enforce_plaintext,
                        label="MTA-STS enforce missing STARTTLS",
                        expected_status="FAILED",
                        mta_sts_policy=policy,
                    )

                enforce_untrusted = _starttls_server(material, "untrusted_server")
                with enforce_untrusted:
                    cases["mta_sts_enforce_untrusted"] = _run_outbound_tls_case(
                        runtime,
                        enforce_untrusted,
                        label="MTA-STS enforce untrusted certificate",
                        expected_status="FAILED",
                        mta_sts_policy=policy,
                    )

                enforce_rejected = _starttls_server(
                    material,
                    "matching_server",
                    starttls_reply=b"454 4.7.0 fixture TLS rejection\r\n",
                )
                with enforce_rejected:
                    cases["mta_sts_enforce_rejected_starttls"] = _run_outbound_tls_case(
                        runtime,
                        enforce_rejected,
                        label="MTA-STS enforce rejected STARTTLS",
                        expected_status="FAILED",
                        mta_sts_policy=policy,
                    )

                enforce_timeout = _starttls_server(
                    material,
                    "matching_server",
                    tls_handshake_delay_seconds=20.0,
                )
                with enforce_timeout:
                    if runtime.ports is None:
                        raise AssertionError("runtime ports are unavailable")
                    client: redis.Redis = redis.Redis(
                        host="127.0.0.1",
                        port=runtime.ports.redis,
                        decode_responses=False,
                    )
                    try:
                        client.set(
                            f"dns:mx:{_DNS_HOST}",
                            _DNS_HOST.encode("ascii"),
                            ex=300,
                        )
                        client.set(
                            f"mta-sts:{_DNS_HOST}",
                            policy.encode("ascii"),
                            ex=300,
                        )
                        response, task_id = _post_failure_message(
                            runtime,
                            recipient=_RECIPIENT,
                            subject="blackbox outbound TLS enforce handshake timeout",
                            text="outbound TLS enforce handshake timeout body",
                        )
                        _wait_until(
                            lambda: _scheduled_retry_ready(client, task_id, 1),
                            timeout=30.0,
                            description="MTA-STS enforce handshake timeout retry scheduling",
                        )
                        retry = _capture_scheduled_retry(
                            runtime,
                            client,
                            task_id,
                            retry_count=1,
                            expected_delay_seconds=_RETRY_DELAYS_SECONDS[0],
                            failure_observed_at=time.time(),
                        )
                        cases["mta_sts_enforce_handshake_timeout"] = {
                            "response": response,
                            "retry": retry,
                            "smtp": _outbound_tls_transcript(enforce_timeout),
                        }
                    finally:
                        client.close()
            return {"target": target, "cases": cases}
        finally:
            if dns_server is not None:
                dns_server.stop()


def _run_opportunistic_certificate_fallback(
    runtime: JavaOracleRuntime,
    material: EphemeralOutboundTlsMaterial,
    *,
    identity: str,
    label: str,
) -> dict[str, Any]:
    server = _starttls_server(material, identity)
    with server:
        response, task_id = _post_failure_message(
            runtime,
            recipient=_RECIPIENT,
            subject=f"blackbox outbound TLS {label}",
            text=f"outbound TLS {label} body",
        )
        _wait_until(
            lambda: len(server.messages()) == 1,
            timeout=45.0,
            description=f"fresh plaintext fallback after {label}",
        )
        return {
            "response": response,
            "terminal": _tls_case_terminal(
                runtime,
                task_id,
                expected_status="SENT",
                description=f"{label} plaintext fallback archive",
            ),
            "smtp": _outbound_tls_transcript(server),
        }


def run_tls_validity_probe() -> dict[str, Any]:
    if (
        subprocess.run(  # noqa: S603
            ["/usr/sbin/ip", "link", "show", "lo"], capture_output=True
        ).returncode
        != 0
    ):
        raise AssertionError("outbound probe must run inside a network namespace with loopback")

    target = _outbound_target()
    repository = Path(__file__).resolve().parents[3]
    dns_server = _candidate_dns_server() if target == "candidate" else None
    with tempfile.TemporaryDirectory(prefix="lmyzmail-outbound-tls-validity-") as workspace:
        workspace_path = Path(workspace)
        material_workspace = workspace_path / "material"
        material_workspace.mkdir(mode=0o700)
        material = provision_ephemeral_outbound_tls_material(
            material_workspace,
            mx_hostname=_TLS_MX_HOST,
        )
        if dns_server is not None:
            dns_server.start()
        try:
            cases: dict[str, Any] = {}
            if target == "candidate":
                opportunistic_runtime: JavaOracleRuntime = _candidate_runtime(
                    repository,
                    outbound_tls_material=material,
                )
            else:
                opportunistic_runtime = OutboundOracleRuntime(
                    workspace_path / "opportunistic-runtime",
                    outbound_tls_material=material,
                )
            with opportunistic_runtime as runtime:
                for label, identity in (
                    ("expired certificate", "expired_server"),
                    ("not-yet-valid certificate", "future_server"),
                ):
                    cases[f"opportunistic_{identity.removesuffix('_server')}"] = (
                        _run_opportunistic_certificate_fallback(
                            runtime,
                            material,
                            identity=identity,
                            label=label,
                        )
                    )

            if target == "candidate":
                enforce_runtime: JavaOracleRuntime = _candidate_runtime(
                    repository,
                    outbound_tls_material=material,
                    mta_sts_enabled=True,
                )
            else:
                enforce_runtime = OutboundOracleRuntime(
                    workspace_path / "enforce-runtime",
                    outbound_tls_material=material,
                    mta_sts_enabled=True,
                )
            with enforce_runtime as runtime:
                policy = f"STSv1|ENFORCE|{_TLS_MX_HOST}|300|Policy1|{int(time.time() * 1000)}"
                for label, identity in (
                    ("expired certificate", "expired_server"),
                    ("not-yet-valid certificate", "future_server"),
                ):
                    server = _starttls_server(material, identity)
                    with server:
                        cases[f"mta_sts_enforce_{identity.removesuffix('_server')}"] = (
                            _run_outbound_tls_case(
                                runtime,
                                server,
                                label=f"MTA-STS enforce {label}",
                                expected_status="FAILED",
                                mta_sts_policy=policy,
                            )
                        )
            return {"target": target, "cases": cases}
        finally:
            if dns_server is not None:
                dns_server.stop()


def _run_tls_negotiation_case(
    runtime: JavaOracleRuntime,
    server: ScriptedSmtpServer,
    *,
    label: str,
    expected_status: str,
    mta_sts_policy: str | None = None,
) -> dict[str, Any]:
    if runtime.ports is None:
        raise AssertionError("runtime ports are unavailable")
    client: redis.Redis = redis.Redis(
        host="127.0.0.1",
        port=runtime.ports.redis,
        decode_responses=False,
    )
    try:
        client.set(f"dns:mx:{_DNS_HOST}", _DNS_HOST.encode("ascii"), ex=300)
        if mta_sts_policy is not None:
            client.set(f"mta-sts:{_DNS_HOST}", mta_sts_policy.encode("ascii"), ex=300)
        response, task_id = _post_failure_message(
            runtime,
            recipient=_RECIPIENT,
            subject=f"blackbox outbound TLS negotiation {label}",
            text=f"outbound TLS negotiation {label} body",
        )
        terminal = _tls_case_terminal(
            runtime,
            task_id,
            expected_status=expected_status,
            description=f"outbound TLS negotiation {label} terminal state",
        )
        if expected_status == "SENT":
            _wait_until(
                lambda: len(server.messages()) == 1,
                timeout=45.0,
                description=f"outbound TLS negotiation {label} delivery",
            )
        return {
            "response": response,
            "terminal": terminal,
            "smtp": _outbound_tls_transcript(server),
            "tls_sessions": _tls_sessions(server),
        }
    finally:
        client.close()


def run_tls_negotiation_probe() -> dict[str, Any]:
    if (
        subprocess.run(  # noqa: S603
            ["/usr/sbin/ip", "link", "show", "lo"], capture_output=True
        ).returncode
        != 0
    ):
        raise AssertionError("outbound probe must run inside a network namespace with loopback")

    target = _outbound_target()
    repository = Path(__file__).resolve().parents[3]
    dns_server = _candidate_dns_server() if target == "candidate" else None
    with tempfile.TemporaryDirectory(prefix="lmyzmail-outbound-tls-negotiation-") as workspace:
        workspace_path = Path(workspace)
        material_workspace = workspace_path / "material"
        material_workspace.mkdir(mode=0o700)
        material = provision_ephemeral_outbound_tls_material(
            material_workspace,
            mx_hostname=_TLS_MX_HOST,
        )
        if dns_server is not None:
            dns_server.start()
        try:
            cases: dict[str, Any] = {}
            if target == "candidate":
                opportunistic_runtime: JavaOracleRuntime = _candidate_runtime(
                    repository,
                    outbound_tls_material=material,
                )
            else:
                opportunistic_runtime = OutboundOracleRuntime(
                    workspace_path / "opportunistic-runtime",
                    outbound_tls_material=material,
                )
            with opportunistic_runtime as runtime:
                opportunistic_servers = {
                    "tls11_only": _starttls_server(
                        material,
                        "matching_server",
                        minimum_version=ssl.TLSVersion.TLSv1_1,
                        maximum_version=ssl.TLSVersion.TLSv1_1,
                        ciphers="DEFAULT:@SECLEVEL=0",
                    ),
                    "no_shared_cipher": _starttls_server(
                        material,
                        "matching_server",
                        minimum_version=ssl.TLSVersion.TLSv1_2,
                        maximum_version=ssl.TLSVersion.TLSv1_2,
                        ciphers="ECDHE-ECDSA-AES128-GCM-SHA256",
                    ),
                    "legacy_rsa_cbc": _starttls_server(
                        material,
                        "matching_server",
                        minimum_version=ssl.TLSVersion.TLSv1_2,
                        maximum_version=ssl.TLSVersion.TLSv1_2,
                        ciphers="AES128-SHA:@SECLEVEL=0",
                    ),
                }
                for label, server in opportunistic_servers.items():
                    with server:
                        cases[f"opportunistic_{label}"] = _run_tls_negotiation_case(
                            runtime,
                            server,
                            label=f"opportunistic {label}",
                            expected_status="SENT",
                        )

            if target == "candidate":
                enforce_runtime: JavaOracleRuntime = _candidate_runtime(
                    repository,
                    outbound_tls_material=material,
                    mta_sts_enabled=True,
                )
            else:
                enforce_runtime = OutboundOracleRuntime(
                    workspace_path / "enforce-runtime",
                    outbound_tls_material=material,
                    mta_sts_enabled=True,
                )
            with enforce_runtime as runtime:
                policy = f"STSv1|ENFORCE|{_TLS_MX_HOST}|300|Policy1|{int(time.time() * 1000)}"
                enforce_servers = {
                    "tls13_only": _starttls_server(
                        material,
                        "matching_server",
                        minimum_version=ssl.TLSVersion.TLSv1_3,
                        maximum_version=ssl.TLSVersion.TLSv1_3,
                    ),
                    "tls12_strong": _starttls_server(
                        material,
                        "matching_server",
                        minimum_version=ssl.TLSVersion.TLSv1_2,
                        maximum_version=ssl.TLSVersion.TLSv1_2,
                        ciphers="ECDHE-RSA-AES128-GCM-SHA256",
                    ),
                    "tls11_only": _starttls_server(
                        material,
                        "matching_server",
                        minimum_version=ssl.TLSVersion.TLSv1_1,
                        maximum_version=ssl.TLSVersion.TLSv1_1,
                        ciphers="DEFAULT:@SECLEVEL=0",
                    ),
                    "no_shared_cipher": _starttls_server(
                        material,
                        "matching_server",
                        minimum_version=ssl.TLSVersion.TLSv1_2,
                        maximum_version=ssl.TLSVersion.TLSv1_2,
                        ciphers="ECDHE-ECDSA-AES128-GCM-SHA256",
                    ),
                    "legacy_rsa_cbc": _starttls_server(
                        material,
                        "matching_server",
                        minimum_version=ssl.TLSVersion.TLSv1_2,
                        maximum_version=ssl.TLSVersion.TLSv1_2,
                        ciphers="AES128-SHA:@SECLEVEL=0",
                    ),
                }
                for label, server in enforce_servers.items():
                    with server:
                        expected_status = (
                            "SENT"
                            if label in {"tls13_only", "tls12_strong"}
                            or (label == "legacy_rsa_cbc" and target == "java")
                            else "FAILED"
                        )
                        cases[f"mta_sts_enforce_{label}"] = _run_tls_negotiation_case(
                            runtime,
                            server,
                            label=f"MTA-STS enforce {label}",
                            expected_status=expected_status,
                            mta_sts_policy=policy,
                        )
            return {"target": target, "cases": cases}
        finally:
            if dns_server is not None:
                dns_server.stop()


def _dsn_wire_snapshot(attempt: SmtpMessageAttempt) -> dict[str, Any]:
    message = BytesParser(policy=email.policy.default).parsebytes(attempt.data)
    parts = list(message.iter_parts())
    delivery_blocks: list[dict[str, str | bool | None]] = []
    if len(parts) >= 2:
        payload = parts[1].get_payload()
        if isinstance(payload, list):
            for block in cast(list[Any], payload):
                delivery_blocks.append(
                    {
                        "reporting_mta": block.get("Reporting-MTA"),
                        "arrival_date_present": block.get("Arrival-Date") is not None,
                        "final_recipient": block.get("Final-Recipient"),
                        "action": block.get("Action"),
                        "status": block.get("Status"),
                        "diagnostic_code": block.get("Diagnostic-Code"),
                    }
                )

    returned_headers: dict[str, str | bool | None] = {
        "message_id_present": False,
        "subject": None,
        "from": None,
    }
    if len(parts) >= 3:
        returned_content = cast(bytes | None, parts[2].get_payload(decode=True))
        if returned_content is not None:
            returned = BytesParser(policy=email.policy.default).parsebytes(returned_content)
            returned_headers = {
                "message_id_present": returned.get("Message-ID") is not None,
                "subject": returned.get("Subject"),
                "from": returned.get("From"),
            }

    return {
        "envelope_from": attempt.sender.decode("ascii"),
        "recipients": [value.decode("ascii") for value in attempt.recipients],
        "accepted": attempt.accepted,
        "crlf_only": b"\n" not in attempt.data.replace(b"\r\n", b""),
        "content_type": message.get_content_type(),
        "report_type": message.get_param("report-type"),
        "headers": {
            "from": str(message.get("From")),
            "to": str(message.get("To")),
            "subject": str(message.get("Subject")),
            "auto_submitted": str(message.get("Auto-Submitted")),
            "message_id_present": message.get("Message-ID") is not None,
        },
        "part_types": [part.get_content_type() for part in parts],
        "delivery_blocks": delivery_blocks,
        "returned_headers": returned_headers,
        "original_body_returned": b"5xx RCPT body 550 1" in attempt.data,
        "bytes": len(attempt.data),
    }


def _candidate_dsn_database_snapshot(
    runtime: JavaOracleRuntime,
    source_task_id: int,
) -> dict[str, Any] | None:
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
            SELECT d.dsn_task_id,d.state,d.payload_json,d.expected_sha256,
                   d.prepared_bytes,d.suppress_reason,
                   q.status,q.sender_address,q.recipients_json,q.subject,
                   q.message_id,q.retry_count,q.last_error
            FROM lmyzmail_outbound_dsn d
            LEFT JOIN outbound_mail_queue q ON q.id=d.dsn_task_id
            WHERE d.original_task_id=%s
            """,
            (source_task_id,),
        ).fetchone()
    if row is None:
        return None
    payload = cast(dict[str, Any], json.loads(row[2]))
    recipients = cast(list[dict[str, Any]], payload["recipients"])
    return {
        "dsn_task_id_present": isinstance(row[0], int),
        "state": row[1],
        "payload": {
            "sender_address": payload.get("sender_address"),
            "subject": payload.get("subject"),
            "message_id_present": isinstance(payload.get("message_id"), str),
            "recipients": [
                {
                    "recipient": recipient.get("recipient"),
                    "state": recipient.get("state"),
                    "smtp_code": recipient.get("smtp_code"),
                    "detail": recipient.get("detail"),
                }
                for recipient in recipients
            ],
        },
        "expected_sha256_present": isinstance(row[3], bytes) and len(row[3]) == 32,
        "prepared_bytes_present": row[4] is not None,
        "suppress_reason": row[5],
        "queue": {
            "status": row[6],
            "sender_address": row[7],
            "recipients_json": row[8],
            "subject": row[9],
            "message_id_present": isinstance(row[10], str),
            "retry_count": row[11],
            "last_error": row[12],
        },
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
                event.kind == "reply" and event.payload.startswith(f"{code} ".encode("ascii"))
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
                        recipient = f"recipient-{phase.lower()}-{code}-{case_index}@{_DNS_HOST}"
                        reply = f"{code} fixture scripted {phase.lower()} retry\r\n".encode("ascii")
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
                        server = ScriptedSmtpServer(scenario, bind_host=_FAKE_IP, bind_port=25)
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


def run_dsn_probe() -> dict[str, Any]:
    if (
        subprocess.run(  # noqa: S603
            ["/usr/sbin/ip", "link", "show", "lo"], capture_output=True
        ).returncode
        != 0
    ):
        raise AssertionError("outbound probe must run inside a network namespace with loopback")

    target = _outbound_target()
    dns_server = _candidate_dsn_dns_server() if target == "candidate" else None
    scenario = SmtpScenario(
        recipient_replies=(
            RecipientReply(
                _DSN_RECIPIENT,
                b"550 5.1.1 fixture scripted recipient failure\r\n",
            ),
        ),
        max_connections=8,
        max_concurrent_connections=2,
        max_message_bytes=2 * 1024 * 1024,
    )
    server = ScriptedSmtpServer(scenario, bind_host=_FAKE_IP, bind_port=25)
    with tempfile.TemporaryDirectory(prefix="lmyzmail-outbound-dsn-oracle-") as workspace:
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
                    if runtime.ports is None:
                        raise AssertionError("runtime ports are unavailable")
                    baseline_worklists = _outbound_worklist_lengths(runtime)
                    redis_client: redis.Redis = redis.Redis(
                        host="127.0.0.1",
                        port=runtime.ports.redis,
                        decode_responses=False,
                    )
                    try:
                        redis_client.set(
                            f"dns:mx:{_QA_DOMAIN}",
                            _QA_DOMAIN.encode("ascii"),
                            ex=300,
                        )
                    finally:
                        redis_client.close()
                    failure = _capture_5xx_case(
                        server,
                        runtime,
                        phase="RCPT",
                        code=550,
                        case_index=1,
                    )
                    source_task_id = cast(
                        int,
                        next(
                            row["id"]
                            for row in _db_rows(runtime)
                            if row["status"] == "FAILED" and "550" in str(row["last_error"])
                        ),
                    )
                    database: dict[str, Any] | None = None
                    if target == "candidate":
                        _wait_until(
                            lambda: any(
                                attempt.sender == b""
                                and attempt.recipients == (QA_ADDRESS.encode("ascii"),)
                                and attempt.accepted
                                for attempt in server.messages()
                            ),
                            timeout=45.0,
                            description="candidate RFC 3464 DSN SMTP acceptance",
                        )

                        def candidate_dsn_sent() -> bool:
                            nonlocal database
                            database = _candidate_dsn_database_snapshot(runtime, source_task_id)
                            return (
                                database is not None
                                and database["state"] == "ADMITTED"
                                and database["queue"]["status"] == "SENT"
                            )

                        _wait_until(
                            candidate_dsn_sent,
                            timeout=30.0,
                            description="candidate durable DSN completion",
                        )
                    else:
                        time.sleep(_DSN_ABSENCE_WINDOW_SECONDS)

                    dsn_attempts = [
                        attempt
                        for attempt in server.messages()
                        if attempt.sender == b"" or QA_ADDRESS.encode("ascii") in attempt.recipients
                    ]
                    null_reverse_path_commands = sum(
                        1
                        for event in server.events()
                        if event.kind == "command"
                        and event.payload.upper().startswith(b"MAIL FROM:<>")
                    )
                    return {
                        "failure": failure,
                        "dsn": {
                            "absence_observation_seconds": (
                                _DSN_ABSENCE_WINDOW_SECONDS if target == "java" else None
                            ),
                            "wire_message_count": len(dsn_attempts),
                            "null_reverse_path_command_count": null_reverse_path_commands,
                            "wire": (
                                _dsn_wire_snapshot(dsn_attempts[0])
                                if len(dsn_attempts) == 1
                                else None
                            ),
                            "database": database,
                            "maildir_owner_counts": _sent_maildir_owner_counts(runtime),
                            "redis_worklists_before": baseline_worklists,
                            "redis_worklists_after": _outbound_worklist_lengths(runtime),
                        },
                    }
        finally:
            if dns_server is not None:
                dns_server.stop()


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
    elif mode == "dsn":
        observed = run_dsn_probe()
    elif mode == "tls":
        observed = run_tls_probe()
    elif mode == "tls_validity":
        observed = run_tls_validity_probe()
    elif mode == "tls_negotiation":
        observed = run_tls_negotiation_probe()
    elif mode == "mta_sts_discovery":
        observed = run_mta_sts_discovery_probe()
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
