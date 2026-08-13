from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any, cast

import pytest
import redis

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.normalize import FieldRule, constant
from lmyzmail_blackbox.persistent_runtime import (
    LEGACY_SESSION_TOKEN,
    PersistentJavaOracleRuntime,
)
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.protocols import (
    RawHttpResponse,
    connect_bounded,
    http_exchange,
    read_http_response,
)
from lmyzmail_blackbox.runtime import QA_ADDRESS, CandidateRuntime
from lmyzmail_blackbox.snapshots import http_bytes_snapshot, http_json_snapshot

_BOUNDARY = "lmyzmail-multipart-contract"
_MAX_REQUEST_BYTES = 16 * 1024
_MAX_ATTACHMENT_BYTES = 64
_MAX_TOTAL_ATTACHMENT_BYTES = 96
_MAX_EMAIL_BYTES = 4 * 1024
_DATE_RE = re.compile(rb"(?im)^Date:\s*[^\r\n]+")
_MESSAGE_ID_RE = re.compile(rb"(?im)^(Message-ID:\s*)<[^>\r\n]+>")
_DKIM_RE = re.compile(rb"(?ims)^DKIM-Signature:.*?(?=^[^ \t\r\n][^\r\n]*:|\Z)")
_BOUNDARY_RE = re.compile(rb"(?i)boundary=\"?([^\";\r\n]+)")


@dataclass(frozen=True, slots=True)
class _OracleTarget:
    runtime: PersistentJavaOracleRuntime

    @property
    def target_kind(self) -> str:
        return "java-oracle"

    @property
    def workspace(self) -> Path | None:
        return self.runtime.workspace

    @property
    def ports(self) -> PortSet | None:
        return self.runtime.ports


class MultipartJavaRuntime(PersistentJavaOracleRuntime):
    def _application_arguments(self) -> list[str]:
        arguments = super()._application_arguments()
        arguments.extend(
            (
                f"--botmail.netty.http.max-content-length={_MAX_REQUEST_BYTES}",
                f"--botmail.netty.http.max-multipart-size={_MAX_REQUEST_BYTES}",
                f"--botmail.max-email-size-bytes={_MAX_EMAIL_BYTES}",
                f"--botmail.max-attachment-size-bytes={_MAX_ATTACHMENT_BYTES}",
                (f"--botmail.max-total-attachments-size-bytes={_MAX_TOTAL_ATTACHMENT_BYTES}"),
                "--botmail.queue.poll-interval-ms=600000",
                "--botmail.queue.batch-size=1",
            )
        )
        return arguments


class MultipartCandidateRuntime(CandidateRuntime):
    request_deadline_ms: int | None = None

    @property
    def requires_qa_account(self) -> bool:
        return False

    def _start_postgres(self) -> None:
        super()._start_postgres()
        workspace, ports = self._require_state()
        psql = self.paths.runtime / "postgres-root/usr/lib/postgresql/16/bin/psql"
        seed = self.paths.repository / "blackbox/fixtures/legacy/postgres-seed.sql"
        self._run_checked(
            [
                str(psql),
                "--host=127.0.0.1",
                f"--port={ports.postgres}",
                "--username=lmyzmail_test",
                "--dbname=lmyzmail",
                "--single-transaction",
                "--set=ON_ERROR_STOP=1",
                f"--file={seed}",
            ],
            env=self._postgres_env(),
            log_path=workspace / "postgres-seed.log",
        )

    def _start_application(self) -> None:
        workspace, _ = self._require_state()
        source = self.paths.repository / "blackbox/fixtures/legacy/maildir"
        shutil.copytree(source, workspace / "maildir")
        super()._start_application()

    def stop_redis_for_test(self) -> None:
        if self._redis is None:
            raise RuntimeError("Redis is not running")
        self._redis.stop(timeout=2.0, kill_timeout=2.0)

    def remove_outbound_queue_for_test(self) -> None:
        workspace, ports = self._require_state()
        psql = self.paths.runtime / "postgres-root/usr/lib/postgresql/16/bin/psql"
        self._run_checked(
            [
                str(psql),
                "--host=127.0.0.1",
                f"--port={ports.postgres}",
                "--username=lmyzmail_test",
                "--dbname=lmyzmail",
                "--set=ON_ERROR_STOP=1",
                "--command=DROP TABLE outbound_mail_queue CASCADE;",
            ],
            env=self._postgres_env(),
            log_path=workspace / "postgres-fault.log",
        )

    def _candidate_configuration(self) -> Path:
        path = super()._candidate_configuration()
        value = json.loads(path.read_text(encoding="utf-8"))
        limits = cast(dict[str, Any], value["limits"])
        limits.update(
            {
                "max_http_request_bytes": _MAX_REQUEST_BYTES,
                "max_http_multipart_bytes": _MAX_REQUEST_BYTES,
                "max_email_size_bytes": _MAX_EMAIL_BYTES,
                "max_attachment_size_bytes": _MAX_ATTACHMENT_BYTES,
                "max_total_attachments_size_bytes": _MAX_TOTAL_ATTACHMENT_BYTES,
            }
        )
        if self.request_deadline_ms is not None:
            limits["http_deadline_ms"] = self.request_deadline_ms
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return path


@dataclass(frozen=True, slots=True)
class _Part:
    name: str
    body: bytes
    filename: str | None = None
    content_type: str | None = None


def _multipart(parts: tuple[_Part, ...], *, close: bool = True) -> bytes:
    output = bytearray()
    for part in parts:
        output.extend(f"--{_BOUNDARY}\r\n".encode())
        disposition = f'Content-Disposition: form-data; name="{part.name}"'
        if part.filename is not None:
            disposition += f'; filename="{part.filename}"'
        output.extend(disposition.encode("utf-8"))
        output.extend(b"\r\n")
        if part.content_type is not None:
            output.extend(f"Content-Type: {part.content_type}\r\n".encode("ascii"))
        output.extend(b"\r\n")
        output.extend(part.body)
        output.extend(b"\r\n")
    if close:
        output.extend(f"--{_BOUNDARY}--\r\n".encode())
    return bytes(output)


def _data(value: object) -> _Part:
    return _Part(
        "data",
        json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode(),
        filename="blob",
        content_type="application/json",
    )


def _request(
    target: RuntimeTarget,
    body: bytes,
    *,
    token: str | None = LEGACY_SESSION_TOKEN,
    content_type: str = f"multipart/form-data; boundary={_BOUNDARY}",
) -> RawHttpResponse:
    assert target.ports is not None
    headers: tuple[tuple[str, str], ...] = (("Content-Type", content_type),)
    if token is not None:
        headers += (("X-Session-Token", token),)
    return http_exchange(
        "127.0.0.1",
        target.ports.http,
        "POST",
        "/web/mail/send/multipart",
        headers=headers,
        body=body,
        timeout=10.0,
    )


def _fragmented_request(
    target: RuntimeTarget,
    body: bytes,
    *,
    fragment_bytes: int,
) -> RawHttpResponse:
    assert target.ports is not None
    stream = connect_bounded("127.0.0.1", target.ports.http, timeout=10.0)
    head = (
        f"POST /web/mail/send/multipart HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{target.ports.http}\r\n"
        f"Content-Type: multipart/form-data; boundary={_BOUNDARY}\r\n"
        f"X-Session-Token: {LEGACY_SESSION_TOKEN}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    try:
        stream.sock.sendall(head)
        for offset in range(0, len(body), fragment_bytes):
            stream.sock.sendall(body[offset : offset + fragment_bytes])
        return read_http_response(
            stream,
            request_method="POST",
            max_header_bytes=16 * 1024,
            max_body_bytes=64 * 1024,
        )
    finally:
        stream.sock.close()


def _open_partial_request(target: RuntimeTarget, prefix: bytes, declared_length: int) -> Any:
    assert target.ports is not None
    stream = connect_bounded("127.0.0.1", target.ports.http, timeout=10.0)
    head = (
        f"POST /web/mail/send/multipart HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{target.ports.http}\r\n"
        f"Content-Type: multipart/form-data; boundary={_BOUNDARY}\r\n"
        f"X-Session-Token: {LEGACY_SESSION_TOKEN}\r\n"
        f"Content-Length: {declared_length}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    stream.sock.sendall(head + prefix)
    return stream


def _upload_files(target: RuntimeTarget) -> list[Path]:
    assert target.workspace is not None
    root = target.workspace / "maildir" / ".lmyzmail-upload"
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*") if path.is_file())


def _wait_for_upload_state(
    target: RuntimeTarget,
    *,
    present: bool,
    timeout: float = 3.0,
) -> None:
    deadline = time.monotonic() + timeout
    files = _upload_files(target)
    while bool(files) != present and time.monotonic() < deadline:
        time.sleep(0.02)
        files = _upload_files(target)
    assert bool(files) == present, files


def _assert_upload_directory_secure_and_empty(target: RuntimeTarget) -> None:
    _wait_for_upload_state(target, present=False)
    assert target.workspace is not None
    root = target.workspace / "maildir" / ".lmyzmail-upload"
    if root.exists():
        assert stat.S_IMODE(root.stat().st_mode) == 0o700


def _oversized_declared_request(target: RuntimeTarget, *, token: str | None) -> RawHttpResponse:
    assert target.ports is not None
    stream = connect_bounded("127.0.0.1", target.ports.http, timeout=10.0)
    headers = [
        b"POST /web/mail/send/multipart HTTP/1.1\r\n",
        f"Host: 127.0.0.1:{target.ports.http}\r\n".encode(),
        f"Content-Type: multipart/form-data; boundary={_BOUNDARY}\r\n".encode(),
        f"Content-Length: {_MAX_REQUEST_BYTES + 1}\r\n".encode(),
        b"Connection: close\r\n",
    ]
    if token is not None:
        headers.append(f"X-Session-Token: {token}\r\n".encode())
    headers.append(b"\r\n")
    try:
        stream.sendall(b"".join(headers))
        return read_http_response(
            stream,
            request_method="POST",
            max_header_bytes=16 * 1024,
            max_body_bytes=64 * 1024,
        )
    finally:
        stream.sock.close()


def _snapshot(response: RawHttpResponse) -> dict[str, Any]:
    content_types = response.header_values(b"content-type")
    if response.body and any(b"application/json" in value for value in content_types):
        return http_json_snapshot(response, canonicalize_object_order=True)
    return http_bytes_snapshot(response)


def _normalize_message(raw: bytes) -> bytes:
    boundaries: dict[bytes, bytes] = {}
    for match in _BOUNDARY_RE.finditer(raw):
        value = match.group(1)
        boundaries.setdefault(value, f"<BOUNDARY-{len(boundaries) + 1}>".encode())
    for value, replacement in boundaries.items():
        raw = raw.replace(value, replacement)
    raw = _DATE_RE.sub(b"Date: <TIMESTAMP>", raw)
    raw = _MESSAGE_ID_RE.sub(rb"\1<MESSAGE_ID>", raw)
    return _DKIM_RE.sub(b"DKIM-Signature: <NORMALIZED>\r\n", raw)


def _message_snapshot(raw: bytes) -> dict[str, Any]:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    parts: list[dict[str, Any]] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True)
        assert isinstance(payload, bytes)
        parts.append(
            {
                "content_type": part.get_content_type(),
                "disposition": part.get_content_disposition(),
                "filename": part.get_filename(),
                "content_id": part.get("Content-ID"),
                "transfer_encoding": str(part.get("Content-Transfer-Encoding"))
                if part.get("Content-Transfer-Encoding") is not None
                else None,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    normalized = _normalize_message(raw)
    return {
        "content_type": message.get_content_type(),
        "parts": parts,
        "normalized_bytes": len(normalized),
        "normalized_sha256": hashlib.sha256(normalized).hexdigest(),
    }


def _ttl_is_seven_days(ttl: int) -> bool:
    return 7 * 24 * 60 * 60 - 30 <= ttl <= 7 * 24 * 60 * 60


def _queue_snapshot(target: RuntimeTarget, response: RawHttpResponse) -> dict[str, Any]:
    assert target.workspace is not None
    assert target.ports is not None
    payload = json.loads(response.body)
    queue_id = int(payload["queueId"])
    message_id = str(payload["messageId"])
    sent_file_name = str(payload["sentFileName"])
    client = redis.Redis(host="127.0.0.1", port=target.ports.redis, decode_responses=False)
    task_key = f"botmail:mail:queue:task:{queue_id}"
    domains_key = f"botmail:mail:queue:domains:{queue_id}"
    try:
        task_raw = client.get(task_key)
        assert isinstance(task_raw, bytes)
        task = json.loads(task_raw)
        signed = base64.b64decode(task["signedContentBase64"], validate=True)
        domain_values = client.hgetall(domains_key)
        pending = [int(value) for value in client.lrange("botmail:mail:queue:pending", 0, -1)]
        sent_index = client.hget("botmail:mail:queue:sentfile_index", sent_file_name)
        mail_counts = {
            cast(bytes, key).decode(): int(cast(bytes, client.get(key)))
            for key in client.scan_iter(match="mail:count:*:sent")
        }
        task_ttl = int(client.ttl(task_key))
        domains_ttl = int(client.ttl(domains_key))
    finally:
        client.close()

    sent_matches = sorted(
        path
        for path in (target.workspace / "maildir" / QA_ADDRESS / "sent").rglob(sent_file_name)
        if path.is_file()
    )
    assert len(sent_matches) == 1
    sent_raw = sent_matches[0].read_bytes()
    assert sent_raw == signed
    normalized_task = {
        **task,
        "id": "<queue-id>",
        "messageId": "<message-id>",
        "sentFileName": "<sent-file>",
        "createdAt": "<timestamp>",
        "signedContentBase64": "<signed-message>",
    }
    assert task["messageId"] == message_id
    assert task["sentFileName"] == sent_file_name
    normalized_domains = {
        key.decode(): {
            **json.loads(value),
            "updatedAt": "<timestamp>",
        }
        for key, value in sorted(domain_values.items())
    }
    return {
        "task": normalized_task,
        "task_ttl_seven_days": _ttl_is_seven_days(task_ttl),
        "domains": normalized_domains,
        "domains_ttl_seven_days": _ttl_is_seven_days(domains_ttl),
        "pending_contains_task": queue_id in pending,
        "sent_index_matches": sent_index == str(queue_id).encode(),
        "mail_counts": mail_counts,
        "message": _message_snapshot(sent_raw),
    }


def _capture_web_multipart(target: RuntimeTarget) -> dict[str, Any]:
    minimal = _multipart((_data({}),))
    base = {
        "to": ["recipient@multipart.invalid"],
        "subject": "Multipart contract",
        "text": "streamed body",
        "async": True,
    }
    malformed = _multipart((_Part("data", b"{"),))
    oversized_part = _multipart(
        (_data(base), _Part("attachments", b"x" * 65, filename="large.bin"))
    )
    over_total = _multipart(
        (
            _data(base),
            _Part("attachments", b"a" * 49, filename="one.bin"),
            _Part("attachments", b"b" * 49, filename="two.bin"),
        )
    )
    valid = _multipart(
        (
            _data({"to": [], "subject": "discarded", "text": "first"}),
            _data(base),
            _Part("attachments", b"", filename="empty.bin"),
            _Part(
                "attachments",
                b"alpha\x00payload",
                filename="alpha.txt",
                content_type="text/plain",
            ),
            _Part("ignored", b"ignored", filename="ignored.bin"),
            _Part("attachments", bytes(range(16)), filename="bytes.bin"),
        )
    )
    cases = {
        "missing_token": _request(target, minimal, token=None),
        "blank_token": _request(target, minimal, token=" "),  # noqa: S106
        "invalid_token": _request(
            target,
            minimal,
            token="invalid-session",  # noqa: S106
        ),
        "invalid_json": _request(target, malformed),
        "attachment_too_large": _request(target, oversized_part),
        "attachments_total_too_large": _request(target, over_total),
        "aggregate_too_large": _oversized_declared_request(target, token=LEGACY_SESSION_TOKEN),
        "aggregate_too_large_missing_token": _oversized_declared_request(target, token=None),
    }
    valid_response = _request(target, valid)
    response_rules = (
        FieldRule(("queueId",), constant("<queue-id>")),
        FieldRule(("messageId",), constant("<message-id>")),
        FieldRule(("sentFileName",), constant("<sent-file>")),
    )
    return {
        "cases": {name: _snapshot(response) for name, response in cases.items()},
        "valid": http_json_snapshot(valid_response, rules=response_rules),
        "state": _queue_snapshot(target, valid_response),
    }


cast(Any, _capture_web_multipart).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket multipart/form-data",
    "route": "POST /web/mail/send/multipart",
    "authentication": ["missing", "blank", "invalid", "valid session token"],
    "parser": [
        "malformed data JSON",
        "duplicate data last-wins",
        "JSON blob classification",
        "empty, ignored-field, typed, and default-type file parts",
    ],
    "limits": {
        "request": _MAX_REQUEST_BYTES,
        "attachment": _MAX_ATTACHMENT_BYTES,
        "attachments_total": _MAX_TOTAL_ATTACHMENT_BYTES,
        "email": _MAX_EMAIL_BYTES,
    },
    "state": "Redis queue keys and TTL, Sent Maildir MIME bytes, and mail count",
    "normalization": [
        "queue ID",
        "Message-ID",
        "sent filename",
        "timestamps",
        "DKIM signature",
        "MIME boundaries",
    ],
}


WEB_MULTIPART_SCENARIOS = (
    Scenario(
        "http/outbound/web-multipart",
        _capture_web_multipart,
        normalizers=(
            "outbound:generated-identifiers-and-time",
            "mime:generated-boundaries-and-dkim",
            "json-object-order:jdk-map-of:web-multipart-errors",
        ),
    ),
)


def _capture_oracle_defects(target: RuntimeTarget) -> dict[str, Any]:
    base = {
        "to": ["recipient@multipart.invalid"],
        "subject": "Oracle multipart defect evidence",
        "text": "body",
        "async": True,
    }
    missing_data = _multipart((_Part("attachments", b"orphan", filename="orphan.bin"),))
    wrong_data_type = _multipart(
        (
            _Part(
                "data",
                json.dumps(base).encode(),
                filename="blob",
                content_type="application/octet-stream",
            ),
        )
    )
    cases = {
        "missing_boundary": _request(
            target,
            _multipart((_data(base),)),
            content_type="multipart/form-data",
        ),
        "unterminated_boundary": _request(target, _multipart((_data(base),), close=False)),
        "missing_data": _request(target, missing_data),
        "wrong_data_content_type": _request(target, wrong_data_type),
    }
    leak_body = _multipart(
        (
            _data(base),
            _Part("attachments", b"first", filename="first.bin"),
            _Part("attachments", b"second", filename="second.bin"),
        )
    )
    leak_response = _request(target, leak_body)
    assert target.workspace is not None
    decoder_files = list((target.workspace / "java-tmp" / "netty-http-upload").glob("upload-*.tmp"))
    owned_files = list((target.workspace / "java-tmp" / "botmail-web-upload").glob("upload-*.tmp"))
    owned_sizes = sorted(path.stat().st_size for path in owned_files)
    return {
        "malformed": {name: _snapshot(response) for name, response in cases.items()},
        "async_success": {
            "status_code": leak_response.status_code,
            "decoder_temp_files_present": bool(decoder_files),
            "owned_temp_files_present": bool(owned_files),
            "owned_temp_files_nonempty": all(size > 0 for size in owned_sizes),
        },
    }


cast(Any, _capture_oracle_defects).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket multipart/form-data",
    "route": "POST /web/mail/send/multipart",
    "evidence": [
        "malformed part states expose a Java class and null-receiver detail",
        "successful asynchronous admission leaves controller-owned upload files",
    ],
    "candidate_requirement": [
        "return a bounded generic error without implementation details",
        "remove every request-owned upload file after materialization or failure",
    ],
}


WEB_MULTIPART_ORACLE_EVIDENCE_SCENARIOS = (
    Scenario(
        "http/outbound/web-multipart-oracle-defects",
        _capture_oracle_defects,
        normalizers=("json-object-order:jdk-map-of:web-multipart-errors",),
    ),
)


def _candidate(
    repository: Path,
    *,
    request_deadline_ms: int | None = None,
) -> MultipartCandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        runtime = MultipartCandidateRuntime.from_environment()
        assert isinstance(runtime, MultipartCandidateRuntime)
    else:
        runtime = MultipartCandidateRuntime(
            command_template=(
                str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
                "--config",
                "{config}",
            )
        )
    runtime.request_deadline_ms = request_deadline_ms
    return runtime


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_frozen_java_web_multipart_golden(
    tmp_path: Path,
    record_java_golden: bool,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java/managed-web-multipart-v19"
    runner = DifferentialRunner(
        repository,
        golden,
        "managed-web-multipart",
        record_java=record_java_golden,
    )
    with MultipartJavaRuntime(tmp_path / "java-web-multipart") as oracle:
        target = _OracleTarget(oracle)
        if record_java_golden:
            runner.record_from_java(WEB_MULTIPART_SCENARIOS, target)
        else:
            runner.verify_java(WEB_MULTIPART_SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_frozen_java_web_multipart_oracle_evidence(
    tmp_path: Path,
    record_java_golden: bool,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java/managed-web-multipart-oracle-evidence-v15"
    runner = DifferentialRunner(
        repository,
        golden,
        "managed-web-multipart-oracle-evidence",
        record_java=record_java_golden,
    )
    with MultipartJavaRuntime(tmp_path / "java-web-multipart-evidence") as oracle:
        target = _OracleTarget(oracle)
        if record_java_golden:
            runner.record_from_java(WEB_MULTIPART_ORACLE_EVIDENCE_SCENARIOS, target)
        else:
            runner.verify_java(WEB_MULTIPART_ORACLE_EVIDENCE_SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_web_multipart_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java/managed-web-multipart-v19",
            "managed-web-multipart",
        ).verify_candidate(WEB_MULTIPART_SCENARIOS, candidate)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_web_multipart_redacts_errors_and_cleans_uploads() -> None:
    repository = Path(__file__).resolve().parents[2]
    base = {
        "to": ["recipient@multipart.invalid"],
        "subject": "Multipart safety",
        "text": "streamed body",
        "async": True,
    }
    with _candidate(repository) as candidate:
        malformed = (
            _request(
                candidate,
                _multipart((_data(base),)),
                content_type="multipart/form-data",
            ),
            _request(candidate, _multipart((_data(base),), close=False)),
            _request(
                candidate,
                _multipart((_Part("attachments", b"orphan", filename="orphan.bin"),)),
            ),
            _request(
                candidate,
                _multipart(
                    (
                        _Part(
                            "data",
                            json.dumps(base).encode(),
                            filename="blob",
                            content_type="application/octet-stream",
                        ),
                    )
                ),
            ),
        )
        for response in malformed:
            assert response.status_code == 500
            assert json.loads(response.body) == {"error": "internal_error"}
            assert b"java." not in response.body
            assert b"NullPointerException" not in response.body
            assert b"receiver" not in response.body
            _assert_upload_directory_secure_and_empty(candidate)

        rejected = (
            _request(
                candidate,
                _multipart(
                    (
                        _data(base),
                        _Part("attachments", b"x" * 65, filename="large.bin"),
                    )
                ),
            ),
            _request(
                candidate,
                _multipart(
                    (
                        _data(base),
                        _Part("attachments", b"a" * 49, filename="one.bin"),
                        _Part("attachments", b"b" * 49, filename="two.bin"),
                    )
                ),
            ),
            _request(
                candidate,
                _multipart(
                    (
                        _data(
                            {
                                "to": ["recipient@multipart.invalid"],
                                "text": "missing subject",
                                "async": True,
                            }
                        ),
                        _Part("attachments", b"owned", filename="owned.bin"),
                    )
                ),
            ),
        )
        assert [response.status_code for response in rejected] == [400, 400, 400]
        _assert_upload_directory_secure_and_empty(candidate)

        fragmented_body = _multipart(
            (
                _data({**base, "subject": "fragmented"}),
                _Part("attachments", b"fragmented-file", filename="fragmented.bin"),
            )
        )
        fragmented_response = _fragmented_request(
            candidate,
            fragmented_body,
            fragment_bytes=3,
        )
        assert fragmented_response.status_code == 202
        _assert_upload_directory_secure_and_empty(candidate)

        def send_concurrent(index: int) -> int:
            body = _multipart(
                (
                    _data({**base, "subject": f"concurrent-{index}"}),
                    _Part(
                        "attachments",
                        f"payload-{index}".encode(),
                        filename=f"concurrent-{index}.bin",
                    ),
                )
            )
            return _request(candidate, body).status_code

        with ThreadPoolExecutor(max_workers=4) as pool:
            statuses = list(pool.map(send_concurrent, range(8)))
        assert statuses == [202] * 8
        _assert_upload_directory_secure_and_empty(candidate)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_web_multipart_backend_failures_clean_uploads() -> None:
    repository = Path(__file__).resolve().parents[2]
    body = _multipart(
        (
            _data(
                {
                    "to": ["recipient@multipart.invalid"],
                    "subject": "Backend failure cleanup",
                    "text": "body",
                    "async": True,
                }
            ),
            _Part("attachments", b"owned upload", filename="owned.bin"),
        )
    )

    with _candidate(repository) as candidate:
        candidate.stop_redis_for_test()
        response = _request(candidate, body)
        assert response.status_code == 500
        _assert_upload_directory_secure_and_empty(candidate)

    with _candidate(repository) as candidate:
        candidate.remove_outbound_queue_for_test()
        response = _request(candidate, body)
        assert response.status_code == 500
        _assert_upload_directory_secure_and_empty(candidate)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_web_multipart_disconnect_and_timeout_clean_uploads() -> None:
    repository = Path(__file__).resolve().parents[2]
    base = {
        "to": ["recipient@multipart.invalid"],
        "subject": "Interrupted upload cleanup",
        "text": "body",
        "async": True,
    }
    prefix = _multipart(
        (
            _data(base),
            _Part("attachments", b"completed upload", filename="completed.bin"),
        ),
        close=False,
    )
    prefix += (
        f'--{_BOUNDARY}\r\nContent-Disposition: form-data; name="ignored"\r\n\r\npartial'
    ).encode()

    with _candidate(repository) as candidate:
        stream = _open_partial_request(candidate, prefix, len(prefix) + 1024)
        _wait_for_upload_state(candidate, present=True)
        stream.sock.close()
        _assert_upload_directory_secure_and_empty(candidate)

    with _candidate(repository, request_deadline_ms=1000) as candidate:
        stream = _open_partial_request(candidate, prefix, len(prefix) + 1024)
        try:
            _wait_for_upload_state(candidate, present=True)
            time.sleep(1.2)
        finally:
            stream.sock.close()
        _assert_upload_directory_secure_and_empty(candidate)
