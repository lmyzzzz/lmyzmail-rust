from __future__ import annotations

import json
import os
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote

import psycopg
import pytest
import redis

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.normalize import FieldRule, constant
from lmyzmail_blackbox.persistent_runtime import (
    LEGACY_SESSION_TOKEN,
    PersistentJavaOracleRuntime,
)
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.protocols import http_exchange
from lmyzmail_blackbox.runtime import API_KEY, QA_ADDRESS, QA_PASSWORD, CandidateRuntime
from lmyzmail_blackbox.snapshots import http_json_snapshot

_SESSION_HEADERS = (("X-Session-Token", LEGACY_SESSION_TOKEN),)
_API_HEADERS = (("X-API-Key", API_KEY),)


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


def _json_request(
    target: RuntimeTarget,
    method: str,
    path: str,
    *,
    headers: tuple[tuple[str, str], ...],
    value: object | None = None,
    timeout: float = 10.0,
) -> Any:
    assert target.ports is not None
    body = (
        json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
        if value is not None
        else b""
    )
    request_headers = headers
    if value is not None:
        request_headers += (("Content-Type", "application/json"),)
    return http_exchange(
        "127.0.0.1",
        target.ports.http,
        method,
        path,
        headers=request_headers,
        body=body,
        timeout=timeout,
    )


def _evict_legacy_queue_cache(target: RuntimeTarget) -> None:
    assert target.ports is not None
    client = redis.Redis(host="127.0.0.1", port=target.ports.redis, decode_responses=False)
    try:
        client.delete(
            "botmail:mail:queue:task:2101",
            "botmail:mail:queue:domains:2101",
        )
    finally:
        client.close()


def _capture_seeded_status(target: RuntimeTarget) -> dict[str, Any]:
    _evict_legacy_queue_cache(target)
    message_id = quote("<legacy-outbound@example.test>", safe="")
    captures = {
        "web_by_id": _json_request(
            target,
            "GET",
            "/web/mail/send/status/2101",
            headers=_SESSION_HEADERS,
        ),
        "web_by_file_missing": _json_request(
            target,
            "GET",
            "/web/mail/send/status/file/legacy-sent.eml",
            headers=_SESSION_HEADERS,
        ),
        "api_by_id": _json_request(
            target,
            "GET",
            "/api/mail/status/2101",
            headers=_API_HEADERS,
        ),
        "api_by_message": _json_request(
            target,
            "GET",
            f"/api/mail/status/message/{message_id}",
            headers=_API_HEADERS,
        ),
        "api_missing": _json_request(
            target,
            "GET",
            "/api/mail/status/999999",
            headers=_API_HEADERS,
        ),
    }
    return {name: http_json_snapshot(response) for name, response in captures.items()}


cast(Any, _capture_seeded_status).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket",
    "routes": [
        "GET /web/mail/send/status/{queueId}",
        "GET /web/mail/send/status/file/{fileName}",
        "GET /api/mail/status/{queueId}",
        "GET /api/mail/status/message/{messageId}",
    ],
    "state": "attested outbound row with the legacy Redis task cache evicted",
    "security": "web status is sender scoped while API status requires read permission",
}


def _capture_domain_status_projection(target: RuntimeTarget) -> dict[str, Any]:
    assert target.ports is not None
    key = "botmail:mail:queue:domains:2101"
    client = redis.Redis(host="127.0.0.1", port=target.ports.redis, decode_responses=False)

    def status(
        domain: str,
        value: str,
        *,
        error: str | None,
        recipients: list[str],
    ) -> bytes:
        return json.dumps(
            {
                "domain": domain,
                "status": value,
                "error": error,
                "recipients": recipients,
                "updatedAt": "2026-08-07T00:00:00Z",
            },
            separators=(",", ":"),
        ).encode()

    def replace(values: dict[str, bytes]) -> None:
        pipeline = client.pipeline(transaction=True)
        pipeline.delete(key)
        pipeline.hset(key, mapping=values)
        pipeline.expire(key, 7 * 24 * 60 * 60)
        pipeline.execute()

    def capture() -> Any:
        return http_json_snapshot(
            _json_request(
                target,
                "GET",
                "/web/mail/send/status/2101",
                headers=_SESSION_HEADERS,
            )
        )

    try:
        client.delete("botmail:mail:queue:task:2101")
        replace(
            {
                "alpha.test": status(
                    "alpha.test",
                    "PENDING",
                    error=None,
                    recipients=["one@alpha.test"],
                ),
                "beta.test": status(
                    "beta.test",
                    "SENDING",
                    error=None,
                    recipients=["two@beta.test"],
                ),
            }
        )
        active = capture()
        replace(
            {
                "alpha.test": status(
                    "alpha.test",
                    "SENT",
                    error=None,
                    recipients=["one@alpha.test"],
                ),
                "beta.test": status(
                    "beta.test",
                    "FAILED",
                    error="550 5.1.1 user unknown",
                    recipients=["two@beta.test"],
                ),
            }
        )
        mixed_terminal = capture()
        replace(
            {
                "alpha.test": status(
                    "alpha.test",
                    "SENT",
                    error=None,
                    recipients=["one@alpha.test"],
                ),
                "beta.test": status(
                    "beta.test",
                    "SENT",
                    error=None,
                    recipients=["two@beta.test"],
                ),
            }
        )
        terminal = capture()
        ttl = int(client.ttl(key))
        return {
            "active": active,
            "mixed_terminal": mixed_terminal,
            "terminal": terminal,
            "domain_ttl_present": 0 < ttl <= 7 * 24 * 60 * 60,
        }
    finally:
        client.delete(key)
        client.close()


cast(Any, _capture_domain_status_projection).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket",
    "routes": ["GET /web/mail/send/status/{queueId}"],
    "state": "active, mixed terminal, and terminal legacy Redis domain hashes with TTL",
    "security": "sender-scoped status retains bounded recipient details",
}


def _capture_quota(target: RuntimeTarget) -> dict[str, Any]:
    captures = {
        "web": _json_request(
            target,
            "GET",
            "/web/mail/quota",
            headers=_SESSION_HEADERS,
        ),
        "api": _json_request(
            target,
            "GET",
            f"/api/mail/quota?address={QA_ADDRESS}",
            headers=_API_HEADERS,
        ),
        "api_missing_address": _json_request(
            target,
            "GET",
            "/api/mail/quota",
            headers=_API_HEADERS,
        ),
    }
    return {
        name: http_json_snapshot(response, canonicalize_object_order=True)
        for name, response in captures.items()
    }


cast(Any, _capture_quota).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket",
    "routes": ["GET /web/mail/quota", "GET /api/mail/quota"],
    "state": "fresh per-account outbound quota",
}


def _capture_validation(target: RuntimeTarget) -> dict[str, Any]:
    base = {
        "from": QA_ADDRESS,
        "password": QA_PASSWORD,
        "to": ["recipient@example.invalid"],
        "subject": "Outbound validation",
        "text": "body",
    }
    cases: list[tuple[str, str, dict[str, object], tuple[tuple[str, str], ...]]] = [
        (
            "api_from",
            "/api/mail/send",
            {key: value for key, value in base.items() if key != "from"},
            _API_HEADERS,
        ),
        (
            "api_password",
            "/api/mail/send",
            {key: value for key, value in base.items() if key != "password"},
            _API_HEADERS,
        ),
        ("api_to", "/api/mail/send", {**base, "to": []}, _API_HEADERS),
        ("api_subject", "/api/mail/send", {**base, "subject": " "}, _API_HEADERS),
        ("api_body", "/api/mail/send", {**base, "text": " "}, _API_HEADERS),
        (
            "web_recipients",
            "/web/mail/send",
            {"to": [], "subject": "Outbound validation", "text": "body"},
            _SESSION_HEADERS,
        ),
        (
            "web_subject",
            "/web/mail/send",
            {"to": ["recipient@example.invalid"], "subject": " ", "text": "body"},
            _SESSION_HEADERS,
        ),
        (
            "web_body",
            "/web/mail/send",
            {"to": ["recipient@example.invalid"], "subject": "Outbound validation"},
            _SESSION_HEADERS,
        ),
    ]
    return {
        name: http_json_snapshot(
            _json_request(target, "POST", path, headers=headers, value=value),
            canonicalize_object_order=True,
        )
        for name, path, value, headers in cases
    }


cast(Any, _capture_validation).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket",
    "routes": ["POST /web/mail/send", "POST /api/mail/send"],
    "state": "authenticated requests rejected before queue mutation",
    "cases": ["missing sender", "missing password", "recipients", "subject", "body"],
}


def _capture_api_admission(target: RuntimeTarget) -> dict[str, Any]:
    response = _json_request(
        target,
        "POST",
        "/api/mail/send",
        headers=_API_HEADERS,
        value={
            "from": QA_ADDRESS,
            "password": QA_PASSWORD,
            "to": ["recipient@example.invalid"],
            "subject": "Durable outbound admission",
            "text": "queued body",
            "async": True,
        },
    )
    parsed = json.loads(response.body)
    queue_id = int(parsed["queueId"])
    message_id = str(parsed["messageId"])
    status = _json_request(
        target,
        "GET",
        f"/api/mail/status/{queue_id}",
        headers=_API_HEADERS,
    )
    status_by_message = _json_request(
        target,
        "GET",
        f"/api/mail/status/message/{quote(message_id, safe='')}",
        headers=_API_HEADERS,
    )
    quota = _json_request(
        target,
        "GET",
        f"/api/mail/quota?address={QA_ADDRESS}",
        headers=_API_HEADERS,
    )
    response_rules = (
        FieldRule(("queueId",), constant("<queue-id>")),
        FieldRule(("messageId",), constant("<message-id>")),
    )
    status_rules = (
        *response_rules,
        FieldRule(("createdAt",), constant("<timestamp>")),
    )
    return {
        "send": http_json_snapshot(response, rules=response_rules),
        "status": http_json_snapshot(status, rules=status_rules),
        "status_by_message": http_json_snapshot(status_by_message),
        "quota": http_json_snapshot(quota, canonicalize_object_order=True),
    }


cast(Any, _capture_api_admission).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket",
    "routes": [
        "POST /api/mail/send",
        "GET /api/mail/status/{queueId}",
        "GET /api/mail/status/message/{messageId}",
        "GET /api/mail/quota",
    ],
    "state": "one real asynchronous queue admission",
    "normalization": ["generated queue ID", "Message-ID", "creation timestamp"],
}


OUTBOUND_HTTP_SCENARIOS = (
    Scenario("http/outbound/seeded-status", _capture_seeded_status),
    Scenario("http/outbound/domain-status-projection", _capture_domain_status_projection),
    Scenario(
        "http/outbound/quota",
        _capture_quota,
        normalizers=("json-object-order:jdk-map-of:outbound-quota",),
    ),
    Scenario(
        "http/outbound/validation",
        _capture_validation,
        normalizers=("json-object-order:jdk-map-of:outbound-validation",),
    ),
    Scenario(
        "http/outbound/api-admission",
        _capture_api_admission,
        normalizers=(
            "outbound:generated-identifiers-and-time",
            "json-object-order:jdk-map-of:outbound-admission-quota",
        ),
    ),
)


class LegacyCandidateRuntime(CandidateRuntime):
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


def _candidate(repository: Path, *extra: str) -> LegacyCandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        runtime = LegacyCandidateRuntime.from_environment()
        assert isinstance(runtime, LegacyCandidateRuntime)
        if extra:
            runtime.command_template += extra
        return runtime
    return LegacyCandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
            *extra,
        )
    )


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_frozen_java_outbound_http_golden(
    tmp_path: Path,
    record_java_golden: bool,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java/managed-outbound-http-v16"
    runner = DifferentialRunner(
        repository,
        golden,
        "managed-outbound-http",
        record_java=record_java_golden,
    )
    with PersistentJavaOracleRuntime(tmp_path / "java-outbound-http") as oracle:
        target = _OracleTarget(oracle)
        if record_java_golden:
            runner.record_from_java(OUTBOUND_HTTP_SCENARIOS, target)
        else:
            runner.verify_java(OUTBOUND_HTTP_SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_frozen_java_outbound_status_redis_failure_contract(tmp_path: Path) -> None:
    with PersistentJavaOracleRuntime(tmp_path / "java-outbound-http-redis-fault") as oracle:
        target = _OracleTarget(oracle)
        assert target.ports is not None
        client = redis.Redis(
            host="127.0.0.1",
            port=target.ports.redis,
            decode_responses=False,
            socket_connect_timeout=5.0,
            socket_timeout=5.0,
        )
        task_key = "botmail:mail:queue:task:2101"
        domain_key = "botmail:mail:queue:domains:2101"
        original_task = client.get(task_key)
        assert isinstance(original_task, bytes)
        try:
            client.set(task_key, b"{")
            corrupt_task = _json_request(
                target,
                "GET",
                "/api/mail/status/2101",
                headers=_API_HEADERS,
            )
            assert corrupt_task.status_code == 200
            assert json.loads(corrupt_task.body)["messageId"] == ("<legacy-outbound@example.test>")

            client.set(task_key, original_task)
            valid_domain = json.dumps(
                {
                    "domain": "valid.test",
                    "status": "SENT",
                    "error": None,
                    "recipients": ["user@valid.test"],
                    "updatedAt": "2026-08-07T00:00:00Z",
                },
                separators=(",", ":"),
            ).encode()
            pipeline = client.pipeline(transaction=True)
            pipeline.delete(domain_key)
            pipeline.hset(
                domain_key,
                mapping={"example.invalid": b"{", "valid.test": valid_domain},
            )
            pipeline.expire(domain_key, 7 * 24 * 60 * 60)
            pipeline.execute()
            corrupt_domain = _json_request(
                target,
                "GET",
                "/web/mail/send/status/2101",
                headers=_SESSION_HEADERS,
            )
            assert corrupt_domain.status_code == 200
            assert [
                detail["domain"]
                for detail in json.loads(corrupt_domain.body).get("domainDetails", [])
            ] == ["valid.test"]
        finally:
            client.close()

        assert oracle._redis is not None
        oracle._redis.kill()
        with pytest.raises(TimeoutError):
            _json_request(
                target,
                "GET",
                "/api/mail/status/2101",
                headers=_API_HEADERS,
                timeout=10.0,
            )
        with pytest.raises(TimeoutError):
            _json_request(
                target,
                "GET",
                "/web/mail/send/status/file/does-not-exist.eml",
                headers=_SESSION_HEADERS,
                timeout=10.0,
            )


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_outbound_http_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java/managed-outbound-http-v16",
            "managed-outbound-http",
        ).verify_candidate(OUTBOUND_HTTP_SCENARIOS, candidate)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_outbound_status_redis_outage_is_bounded() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        assert candidate._redis is not None
        candidate._redis.kill()
        redis_outage = _json_request(
            candidate,
            "GET",
            "/api/mail/status/2101",
            headers=_API_HEADERS,
            timeout=10.0,
        )
        assert redis_outage.status_code == 500
        assert json.loads(redis_outage.body) == {"error": "internal_error"}
        missing_file = _json_request(
            candidate,
            "GET",
            "/web/mail/send/status/file/does-not-exist.eml",
            headers=_SESSION_HEADERS,
            timeout=10.0,
        )
        assert missing_file.status_code == 404
        assert json.loads(missing_file.body) == {"error": "not_found"}


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_acknowledges_only_after_postgres_admission() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        response = _json_request(
            candidate,
            "POST",
            "/api/mail/send",
            headers=_API_HEADERS,
            value={
                "from": QA_ADDRESS,
                "password": QA_PASSWORD,
                "to": ["recipient@example.invalid"],
                "subject": "Durable database assertion",
                "text": "persist before response",
            },
        )
        assert response.status_code == 202
        queue_id = int(json.loads(response.body)["queueId"])
        assert candidate.ports is not None
        with psycopg.connect(
            host="127.0.0.1",
            port=candidate.ports.postgres,
            dbname="lmyzmail",
            user="lmyzmail_test",
            password="",
        ) as connection:
            row = connection.execute(
                """
                SELECT sender_address, recipients_json, subject, body_text, status,
                       retry_count, max_retries, message_id
                FROM outbound_mail_queue WHERE id=%s
                """,
                (queue_id,),
            ).fetchone()
        assert row is not None
        assert row[0] == QA_ADDRESS
        assert json.loads(row[1]) == {
            "to": ["recipient@example.invalid"],
            "cc": [],
            "bcc": [],
        }
        assert row[2:7] == (
            "Durable database assertion",
            "persist before response",
            "PENDING",
            0,
            5,
        )
        assert isinstance(row[7], str) and row[7].endswith("@example.test>")


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_enforces_outbound_queue_bound_atomically() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository, "--lmyzmail.outbound.max-pending-tasks=1") as candidate:
        payload = {
            "from": QA_ADDRESS,
            "password": QA_PASSWORD,
            "to": ["recipient@example.invalid"],
            "subject": "Bounded outbound queue",
            "text": "one pending task",
        }
        barrier = threading.Barrier(3)

        def send() -> Any:
            barrier.wait(timeout=5)
            return _json_request(
                candidate,
                "POST",
                "/api/mail/send",
                headers=_API_HEADERS,
                value=payload,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(send) for _ in range(2)]
            barrier.wait(timeout=5)
            responses = [future.result(timeout=30) for future in futures]
        assert sorted(response.status_code for response in responses) == [202, 429]
