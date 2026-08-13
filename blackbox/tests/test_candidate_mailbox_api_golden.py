from __future__ import annotations

import json
import os
import shutil
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import psycopg
import pytest

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.errors import ProtocolError
from lmyzmail_blackbox.normalize import FieldRule, constant
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.protocols import http_exchange, json_http_exchange
from lmyzmail_blackbox.runtime import (
    API_KEY,
    READ_ONLY_API_KEY,
    WRITE_ONLY_API_KEY,
    CandidateRuntime,
)
from lmyzmail_blackbox.snapshots import http_json_snapshot

_PROFILE = "managed-mailbox-api"
_GOLDEN = "blackbox/golden/java/managed-mailbox-api-v15"
_ADMIN_HEADERS = (("X-API-Key", API_KEY),)


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


def _capture_mailbox_api(target: RuntimeTarget) -> dict[str, Any]:
    assert target.ports is not None
    port = target.ports.http

    def request(
        method: str,
        path: str,
        *,
        value: object | None = None,
        raw_body: bytes | None = None,
        api_key: str | None = API_KEY,
        canonicalize: bool = True,
        rules: tuple[FieldRule, ...] = (),
    ) -> dict[str, Any]:
        if value is not None and raw_body is not None:
            raise ValueError("value and raw_body are mutually exclusive")
        headers: tuple[tuple[str, str], ...] = ()
        if api_key is not None:
            headers += (("X-API-Key", api_key),)
        if value is not None:
            headers += (("Content-Type", "application/json"),)
            body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
        elif raw_body is not None:
            headers += (("Content-Type", "application/json"),)
            body = raw_body
        else:
            body = b""
        response = http_exchange(
            "127.0.0.1",
            port,
            method,
            path,
            headers=headers,
            body=body,
            timeout=10.0,
        )
        return http_json_snapshot(
            response,
            rules=rules,
            canonicalize_object_order=canonicalize,
        )

    existing = request("GET", "/api/mailboxes/QA%40EXAMPLE.TEST/exists")
    missing_key = request(
        "POST",
        "/api/mailboxes",
        value={"address": "unauthorized@example.test", "password": "MailboxPass123!"},
        api_key=None,
    )
    read_only_create = request(
        "POST",
        "/api/mailboxes",
        value={"address": "read-only@example.test", "password": "MailboxPass123!"},
        api_key=READ_ONLY_API_KEY,
    )
    malformed = request("POST", "/api/mailboxes", raw_body=b'{"address":')
    empty = request("POST", "/api/mailboxes", value={})
    short_password = request(
        "POST",
        "/api/mailboxes",
        value={"address": "short@example.test", "password": "short"},
    )
    wrong_domain = request(
        "POST",
        "/api/mailboxes",
        value={"address": "wrong@invalid.test", "password": "MailboxPass123!"},
    )
    created = request(
        "POST",
        "/api/mailboxes",
        value={
            "address": "  Api-Created@EXAMPLE.TEST  ",
            "password": "MailboxPass123!",
        },
        canonicalize=False,
    )
    created_login = request(
        "POST",
        "/web/login",
        value={"address": "API-CREATED@example.test", "password": "MailboxPass123!"},
        canonicalize=False,
        rules=(FieldRule(("token",), constant("<session-token>")),),
    )
    created_exists = request("GET", "/api/mailboxes/API-CREATED%40EXAMPLE.TEST/exists")
    duplicate = request(
        "POST",
        "/api/mailboxes",
        value={"address": "api-created@example.test", "password": "DifferentPass123!"},
    )
    write_only_exists = request(
        "GET",
        "/api/mailboxes/qa%40example.test/exists",
        api_key=WRITE_ONLY_API_KEY,
    )
    blank_address = request("GET", "/api/mailboxes/%20/exists")
    unknown = request("GET", "/api/mailboxes/unknown%40example.test/exists")

    with psycopg.connect(
        host="127.0.0.1",
        port=target.ports.postgres,
        user="lmyzmail_test",
        dbname="lmyzmail",
        connect_timeout=5,
    ) as connection:
        rows = connection.execute(
            "SELECT id, address, length(password_hash) FROM mailbox "
            "WHERE address IN (%s, %s, %s, %s) ORDER BY address",
            (
                "api-created@example.test",
                "read-only@example.test",
                "unauthorized@example.test",
                "wrong@invalid.test",
            ),
        ).fetchall()

    return {
        "existing": existing,
        "missing_key": missing_key,
        "read_only_create": read_only_create,
        "malformed": malformed,
        "empty": empty,
        "short_password": short_password,
        "wrong_domain": wrong_domain,
        "created": created,
        "created_login": created_login,
        "created_exists": created_exists,
        "duplicate": duplicate,
        "write_only_exists": write_only_exists,
        "blank_address": blank_address,
        "unknown": unknown,
        "database_rows": [list(row) for row in rows],
    }


cast(Any, _capture_mailbox_api).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket",
    "routes": [
        "POST /api/mailboxes",
        "GET /api/mailboxes/{address}/exists",
        "POST /web/login",
    ],
    "sequence": [
        "check the seeded mailbox through a percent-decoded mixed-case path",
        "prove API-key read/write boundaries before request parsing",
        "freeze malformed, empty, short-password, and unconfigured-domain errors",
        "create one normalized mailbox and authenticate with its stored password",
        "check normalized existence, duplicate behavior, blank path input, and unknown input",
        "prove rejected requests did not create PostgreSQL rows",
    ],
    "state": "attested legacy PostgreSQL seed with mailbox identity 1001",
}

MAILBOX_API_SCENARIOS = (
    Scenario(
        "http/mailbox-api/create-and-exists",
        _capture_mailbox_api,
        normalizers=(
            "json-object-order:jdk-map-of:mailbox-api-errors-and-exists",
            "json:session-token",
            "header:content-length:normalized-json",
        ),
    ),
)


class _LegacyCandidateRuntime(CandidateRuntime):
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
        destination = workspace / "maildir"
        if not destination.exists():
            shutil.copytree(source, destination)
        super()._start_application()

    def restart_application(self) -> None:
        if self._application is None:
            raise RuntimeError("candidate application is not running")
        self._application.stop(
            timeout=self.shutdown_timeout,
            kill_timeout=self.shutdown_kill_timeout,
        )
        self._application = None
        CandidateRuntime._start_application(self)


def _candidate(repository: Path, *overrides: str) -> _LegacyCandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        runtime = _LegacyCandidateRuntime.from_environment()
        assert isinstance(runtime, _LegacyCandidateRuntime)
        runtime.command_template = (*runtime.command_template, *overrides)
        return runtime
    return _LegacyCandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
            *overrides,
        )
    )


def _create_mailbox(
    runtime: _LegacyCandidateRuntime,
    address: str,
    *,
    timeout: float = 10.0,
) -> tuple[int, dict[str, Any]]:
    assert runtime.ports is not None
    response = json_http_exchange(
        "127.0.0.1",
        runtime.ports.http,
        "POST",
        "/api/mailboxes",
        value={"address": address, "password": "MailboxPass123!"},
        headers=_ADMIN_HEADERS,
        timeout=timeout,
    )
    return response.status_code, cast(dict[str, Any], json.loads(response.body))


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_frozen_java_mailbox_api_golden(
    tmp_path: Path,
    record_java_golden: bool,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    runner = DifferentialRunner(
        repository,
        repository / _GOLDEN,
        _PROFILE,
        record_java=record_java_golden,
    )
    with PersistentJavaOracleRuntime(tmp_path / "java-mailbox-api") as oracle:
        target = _OracleTarget(oracle)
        if record_java_golden:
            runner.record_from_java(MAILBOX_API_SCENARIOS, target)
        else:
            runner.verify_java(MAILBOX_API_SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_mailbox_api_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(
            repository,
            repository / _GOLDEN,
            _PROFILE,
        ).verify_candidate(MAILBOX_API_SCENARIOS, candidate)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_serializes_duplicate_mailbox_creation() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(
        repository,
        "--lmyzmail.rate-limit.max-registrations-per-ip=100",
    ) as candidate:
        assert candidate.ports is not None

        def create(_: int) -> tuple[int, dict[str, Any]]:
            return _create_mailbox(candidate, "concurrent-mailbox@example.test", timeout=15.0)

        with ThreadPoolExecutor(max_workers=16) as executor:
            responses = tuple(executor.map(create, range(24)))

        statuses = [status for status, _ in responses]
        assert statuses.count(201) == 1
        assert statuses.count(400) == 23
        assert all(
            body.get("error") == "creation_failed"
            for status, body in responses
            if status == 400
        )
        with psycopg.connect(
            host="127.0.0.1",
            port=candidate.ports.postgres,
            user="lmyzmail_test",
            dbname="lmyzmail",
            connect_timeout=5,
        ) as connection:
            row = connection.execute(
                "SELECT count(*) FROM mailbox WHERE address=%s",
                ("concurrent-mailbox@example.test",),
            ).fetchone()
        assert row == (1,)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_mailbox_api_enforces_registration_limit() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        assert candidate.ports is not None
        responses = tuple(
            _create_mailbox(candidate, f"api-rate-{index}@example.test")
            for index in range(8)
        )
        statuses = [status for status, _ in responses]
        assert statuses == [201, 201, 201, 201, 201, 429, 429, 429]
        assert all(
            body.get("error") == "rate_limit_exceeded"
            for status, body in responses
            if status == 429
        )
        with psycopg.connect(
            host="127.0.0.1",
            port=candidate.ports.postgres,
            user="lmyzmail_test",
            dbname="lmyzmail",
            connect_timeout=5,
        ) as connection:
            row = connection.execute(
                "SELECT count(*) FROM mailbox WHERE address LIKE 'api-rate-%@example.test'"
            ).fetchone()
        assert row == (5,)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_mailbox_creation_survives_restart() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        assert candidate.ports is not None
        status, body = _create_mailbox(candidate, "restart-mailbox@example.test")
        assert status == 201
        assert body["address"] == "restart-mailbox@example.test"

        candidate.restart_application()
        exists = http_exchange(
            "127.0.0.1",
            candidate.ports.http,
            "GET",
            "/api/mailboxes/RESTART-MAILBOX%40EXAMPLE.TEST/exists",
            headers=_ADMIN_HEADERS,
            timeout=10.0,
        )
        login = json_http_exchange(
            "127.0.0.1",
            candidate.ports.http,
            "POST",
            "/web/login",
            value={
                "address": "RESTART-MAILBOX@example.test",
                "password": "MailboxPass123!",
            },
            timeout=10.0,
        )
        assert exists.status_code == 200
        assert json.loads(exists.body) == {
            "address": "RESTART-MAILBOX@EXAMPLE.TEST",
            "exists": True,
        }
        assert login.status_code == 200
        assert json.loads(login.body)["address"] == "RESTART-MAILBOX@example.test"


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_management_creation_and_receive_alias_precedence() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(
        repository,
        "--lmyzmail.public-registration-enabled=false",
        "--botmail.domains.main.receiveEnabled=false",
        "--lmyzmail.domains.main.receive-enabled=true",
    ) as candidate:
        assert candidate.ports is not None
        public = json_http_exchange(
            "127.0.0.1",
            candidate.ports.http,
            "POST",
            "/web/register",
            value={
                "address": "public-disabled@example.test",
                "password": "MailboxPass123!",
            },
        )
        managed_status, _ = _create_mailbox(candidate, "managed-enabled@example.test")
        assert public.status_code == 403
        assert managed_status == 201

    with _candidate(
        repository,
        "--botmail.domains.main.receiveEnabled=false",
    ) as candidate:
        legacy_status, legacy_body = _create_mailbox(
            candidate,
            "legacy-disabled@example.test",
        )
        assert legacy_status == 400
        assert legacy_body == {
            "error": "creation_failed",
            "message": "Domain does not accept mail: example.test",
        }

    with _candidate(
        repository,
        "--botmail.domains.main.receiveEnabled=true",
        "--lmyzmail.domains.main.receive-enabled=false",
    ) as candidate:
        new_status, new_body = _create_mailbox(
            candidate,
            "new-disabled@example.test",
        )
        assert new_status == 400
        assert new_body == {
            "error": "creation_failed",
            "message": "Domain does not accept mail: example.test",
        }


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_auth_cancellation_keeps_single_connection_pool_healthy() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(
        repository,
        "--lmyzmail.postgres.pool.max-size=1",
        "--lmyzmail.http.request-timeout-ms=500",
    ) as candidate:
        assert candidate.ports is not None
        with psycopg.connect(
            host="127.0.0.1",
            port=candidate.ports.postgres,
            user="lmyzmail_test",
            dbname="lmyzmail",
            connect_timeout=5,
        ) as blocker:
            blocker.execute("LOCK TABLE mailbox IN ACCESS EXCLUSIVE MODE")
            started = time.monotonic()
            with pytest.raises(ProtocolError):
                http_exchange(
                    "127.0.0.1",
                    candidate.ports.http,
                    "GET",
                    "/api/mailboxes/locked%40example.test/exists",
                    headers=_ADMIN_HEADERS,
                    timeout=3.0,
                )
            assert time.monotonic() - started < 2.0

            preferences = http_exchange(
                "127.0.0.1",
                candidate.ports.http,
                "GET",
                "/web/userdata/preferences",
                headers=(("X-Session-Token", "legacy-session-token"),),
                timeout=3.0,
            )
            assert preferences.status_code == 200
            assert preferences.body == (
                b'{"itemsPerPage":25,"legacyFixture":true,"theme":"dark"}'
            )
            waiting = blocker.execute(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE datname=current_database() AND pid<>pg_backend_pid() "
                "AND wait_event_type='Lock'"
            ).fetchone()
            assert waiting == (0,)
