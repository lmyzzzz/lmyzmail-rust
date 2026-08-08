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
from lmyzmail_blackbox.persistent_runtime import (
    LEGACY_SESSION_TOKEN,
    PersistentJavaOracleRuntime,
)
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.protocols import http_exchange, json_http_exchange
from lmyzmail_blackbox.runtime import CandidateRuntime
from lmyzmail_blackbox.snapshots import http_json_snapshot

_SESSION_HEADERS = (("X-Session-Token", LEGACY_SESSION_TOKEN),)
_PROFILE = "managed-userdata"
_GOLDEN = "blackbox/golden/java/managed-userdata-v12"
_ORACLE_EVIDENCE_GOLDEN = "blackbox/golden/java/managed-userdata-oracle-evidence-v11"


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


def _capture_userdata(target: RuntimeTarget) -> dict[str, Any]:
    assert target.ports is not None
    port = target.ports.http

    def request(
        method: str,
        path: str,
        *,
        value: object | None = None,
        canonicalize: bool = False,
    ) -> dict[str, Any]:
        if value is None:
            response = http_exchange(
                "127.0.0.1",
                port,
                method,
                path,
                headers=_SESSION_HEADERS,
                timeout=10.0,
            )
        else:
            response = json_http_exchange(
                "127.0.0.1",
                port,
                method,
                path,
                value=value,
                headers=_SESSION_HEADERS,
                timeout=10.0,
            )
        return http_json_snapshot(
            response,
            canonicalize_object_order=canonicalize,
        )

    with psycopg.connect(
        host="127.0.0.1",
        port=target.ports.postgres,
        user="lmyzmail_test",
        dbname="lmyzmail",
        connect_timeout=5,
    ) as connection:
        connection.execute(
            "INSERT INTO contact "
            "(id, mailbox_address, email, name, notes, created_at, updated_at) "
            "VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            (
                990_001,
                "foreign@example.test",
                "foreign-contact@example.test",
                "Foreign Contact",
                "must remain isolated",
            ),
        )

    preferences_before = request("GET", "/web/userdata/preferences")
    preferences_saved = request(
        "POST",
        "/web/userdata/preferences",
        value={
            "theme": "solarized",
            "itemsPerPage": 40,
            "nested": {"compact": True, "sender": "用户@example.test"},
            "columns": ["from", "subject", "date"],
            "preview": None,
        },
        canonicalize=True,
    )
    preferences_after = request("GET", "/web/userdata/preferences")

    with psycopg.connect(
        host="127.0.0.1",
        port=target.ports.postgres,
        user="lmyzmail_test",
        dbname="lmyzmail",
        connect_timeout=5,
    ) as connection:
        connection.execute(
            "UPDATE user_preference SET preferences_json = %s WHERE mailbox_address = %s",
            ("{not-json", "qa@example.test"),
        )

    preferences_corrupt_legacy = request("GET", "/web/userdata/preferences")
    preferences_replaced = request(
        "POST",
        "/web/userdata/preferences",
        value={},
        canonicalize=True,
    )
    preferences_empty = request("GET", "/web/userdata/preferences")

    contacts_before = request("GET", "/web/userdata/contacts")
    contact_created = request(
        "POST",
        "/web/userdata/contacts",
        value={
            "name": "Zulu Contact",
            "email": "ZULU@EXAMPLE.TEST",
            "notes": "Created by the userdata differential",
        },
        canonicalize=True,
    )
    contact_duplicate = request(
        "POST",
        "/web/userdata/contacts",
        value={
            "name": "Duplicate",
            "email": "zulu@example.test",
            "notes": "must be rejected",
        },
        canonicalize=True,
    )
    contacts_after_create = request("GET", "/web/userdata/contacts")

    created_id = cast(int, contact_created["body_json"]["id"])
    assert created_id > 0
    contact_updated = request(
        "PUT",
        f"/web/userdata/contacts/{created_id}",
        value={
            "name": "Aaron Contact",
            "email": "AARON@EXAMPLE.TEST",
            "notes": "Updated notes",
        },
        canonicalize=True,
    )
    contacts_after_update = request("GET", "/web/userdata/contacts")
    missing_update = request(
        "PUT",
        "/web/userdata/contacts/999999",
        value={"name": "Missing", "email": "missing@example.test", "notes": None},
        canonicalize=True,
    )
    foreign_update = request(
        "PUT",
        "/web/userdata/contacts/990001",
        value={"name": "Stolen", "email": "stolen@example.test", "notes": None},
        canonicalize=True,
    )
    foreign_delete = request(
        "DELETE",
        "/web/userdata/contacts/990001",
        canonicalize=True,
    )
    contact_deleted = request(
        "DELETE",
        f"/web/userdata/contacts/{created_id}",
        canonicalize=True,
    )
    contact_deleted_again = request(
        "DELETE",
        f"/web/userdata/contacts/{created_id}",
        canonicalize=True,
    )
    contacts_after_delete = request("GET", "/web/userdata/contacts")

    with psycopg.connect(
        host="127.0.0.1",
        port=target.ports.postgres,
        user="lmyzmail_test",
        dbname="lmyzmail",
        connect_timeout=5,
    ) as connection:
        foreign = connection.execute(
            "SELECT mailbox_address, email, name, notes FROM contact WHERE id = %s",
            (990_001,),
        ).fetchone()
    assert foreign == (
        "foreign@example.test",
        "foreign-contact@example.test",
        "Foreign Contact",
        "must remain isolated",
    )

    return {
        "preferences_before": preferences_before,
        "preferences_saved": preferences_saved,
        "preferences_after": preferences_after,
        "preferences_corrupt_legacy": preferences_corrupt_legacy,
        "preferences_replaced": preferences_replaced,
        "preferences_empty": preferences_empty,
        "contacts_before": contacts_before,
        "contact_created": contact_created,
        "contact_duplicate": contact_duplicate,
        "contacts_after_create": contacts_after_create,
        "contact_updated": contact_updated,
        "contacts_after_update": contacts_after_update,
        "missing_update": missing_update,
        "foreign_update": foreign_update,
        "foreign_delete": foreign_delete,
        "contact_deleted": contact_deleted,
        "contact_deleted_again": contact_deleted_again,
        "contacts_after_delete": contacts_after_delete,
    }


cast(Any, _capture_userdata).__lmyzmail_contract__ = {
    "protocol": "http",
    "sequence": [
        "read seeded preferences, replace the whole JSON object, and read it back",
        "inject malformed legacy preferences JSON, observe the fallback, then replace it",
        "list, create, reject duplicate, update, delete, and relist contacts",
        "reject missing and foreign contact ids without mutating the foreign row",
    ],
    "headers": [
        ["X-Session-Token", "<legacy-session-token>"],
        ["Content-Type", "application/json for writes"],
    ],
    "state": "attested legacy PostgreSQL seed plus one foreign tenant contact",
    "normalization": "only Java Map.of response object member order",
}

USERDATA_SCENARIOS = (
    Scenario(
        "http/userdata/preferences-and-contacts",
        _capture_userdata,
        normalizers=("json-object-order:jdk-map-of:write-responses",),
    ),
)


def _capture_malformed_oracle_userdata(target: RuntimeTarget) -> dict[str, Any]:
    assert target.ports is not None
    port = target.ports.http

    def raw(
        method: str,
        path: str,
        body: bytes,
        *,
        content_type: str = "application/json",
    ) -> dict[str, Any]:
        response = http_exchange(
            "127.0.0.1",
            port,
            method,
            path,
            headers=(("Content-Type", content_type), *_SESSION_HEADERS),
            body=body,
            timeout=10.0,
        )
        return http_json_snapshot(response, canonicalize_object_order=True)

    malformed_preferences = raw("POST", "/web/userdata/preferences", b"{")
    null_preferences = raw("POST", "/web/userdata/preferences", b"null")
    preferences_after_null = raw("GET", "/web/userdata/preferences", b"")
    text_plain_preferences = raw(
        "POST",
        "/web/userdata/preferences",
        b'{"acceptedDespiteContentType":true}',
        content_type="text/plain",
    )
    preferences_after_text_plain = raw("GET", "/web/userdata/preferences", b"")
    missing_email = raw(
        "POST",
        "/web/userdata/contacts",
        b'{"name":"Missing Email","notes":"must not persist"}',
    )
    missing_name = raw(
        "POST",
        "/web/userdata/contacts",
        b'{"email":"nameless@example.test","notes":"committed before response failure"}',
    )
    contacts_after_missing_fields = raw("GET", "/web/userdata/contacts", b"")
    non_numeric_id = raw(
        "PUT",
        "/web/userdata/contacts/not-a-number",
        b'{"name":"Invalid Id","email":"invalid-id@example.test"}',
    )
    return {
        "malformed_preferences": malformed_preferences,
        "null_preferences": null_preferences,
        "preferences_after_null": preferences_after_null,
        "text_plain_preferences": text_plain_preferences,
        "preferences_after_text_plain": preferences_after_text_plain,
        "missing_email": missing_email,
        "missing_name": missing_name,
        "contacts_after_missing_fields": contacts_after_missing_fields,
        "non_numeric_id": non_numeric_id,
    }


cast(Any, _capture_malformed_oracle_userdata).__lmyzmail_contract__ = {
    "protocol": "http",
    "sequence": [
        "send malformed and null preferences bodies",
        "prove the oracle accepts valid JSON under text/plain",
        "send contacts with missing email and missing name, then inspect committed state",
        "send a non-numeric contact path id",
    ],
    "headers": [["X-Session-Token", "<legacy-session-token>"]],
    "state": "attested legacy PostgreSQL seed",
    "evidence_only": True,
    "difference_id": "userdata-malformed-write-rejection",
}

USERDATA_ORACLE_EVIDENCE_SCENARIOS = (
    Scenario(
        "http/userdata/oracle-malformed-write-side-effects",
        _capture_malformed_oracle_userdata,
        normalizers=("json-object-order:jdk-map-of:error-responses",),
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

    def restart_application(self) -> None:
        if self._application is None:
            raise RuntimeError("candidate application is not running")
        self._application.stop(
            timeout=self.shutdown_timeout,
            kill_timeout=self.shutdown_kill_timeout,
        )
        self._application = None
        CandidateRuntime._start_application(self)


def _candidate(repository: Path) -> LegacyCandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        runtime = LegacyCandidateRuntime.from_environment()
        assert isinstance(runtime, LegacyCandidateRuntime)
        return runtime
    return LegacyCandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        )
    )


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_frozen_java_userdata_golden(
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
    with PersistentJavaOracleRuntime(tmp_path / "java-userdata") as oracle:
        target = _OracleTarget(oracle)
        if record_java_golden:
            runner.record_from_java(USERDATA_SCENARIOS, target)
        else:
            runner.verify_java(USERDATA_SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_frozen_java_userdata_malformed_evidence(
    tmp_path: Path,
    record_java_golden: bool,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    runner = DifferentialRunner(
        repository,
        repository / _ORACLE_EVIDENCE_GOLDEN,
        "managed-userdata-oracle-evidence",
        record_java=record_java_golden,
    )
    with PersistentJavaOracleRuntime(tmp_path / "java-userdata-evidence") as oracle:
        target = _OracleTarget(oracle)
        if record_java_golden:
            runner.record_from_java(USERDATA_ORACLE_EVIDENCE_SCENARIOS, target)
        else:
            runner.verify_java(USERDATA_ORACLE_EVIDENCE_SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_userdata_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(
            repository,
            repository / _GOLDEN,
            _PROFILE,
        ).verify_candidate(USERDATA_SCENARIOS, candidate)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_userdata_rejects_malformed_writes_without_side_effects() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        assert candidate.ports is not None
        port = candidate.ports.http

        def request(method: str, path: str, body: bytes) -> tuple[int, object]:
            response = http_exchange(
                "127.0.0.1",
                port,
                method,
                path,
                headers=(("Content-Type", "application/json"), *_SESSION_HEADERS),
                body=body,
                timeout=10.0,
            )
            return response.status_code, json.loads(response.body)

        assert request("POST", "/web/userdata/preferences", b"{") == (
            400,
            {"error": "bad_request"},
        )
        assert request("POST", "/web/userdata/preferences", b"null") == (
            400,
            {"error": "bad_request"},
        )
        assert request("POST", "/web/userdata/preferences", b"[]") == (
            400,
            {"error": "bad_request"},
        )
        assert request(
            "POST",
            "/web/userdata/contacts",
            b'{"name":"Missing Email","notes":"must not persist"}',
        ) == (400, {"error": "Invalid contact email"})
        assert request(
            "POST",
            "/web/userdata/contacts",
            b'{"email":"nameless@example.test","notes":"must not persist"}',
        ) == (400, {"error": "Invalid contact name"})
        assert request(
            "POST",
            "/web/userdata/contacts",
            ('{"name":"' + "n" * 256 + '","email":"long-name@example.test"}').encode(),
        ) == (400, {"error": "Invalid contact name"})
        assert request(
            "POST",
            "/web/userdata/contacts",
            ('{"name":"Long Email","email":"' + "e" * 256 + '"}').encode(),
        ) == (400, {"error": "Invalid contact email"})
        assert request(
            "PUT",
            "/web/userdata/contacts/not-a-number",
            b'{"name":"Invalid Id","email":"invalid-id@example.test"}',
        ) == (400, {"error": "bad_request"})

        with psycopg.connect(
            host="127.0.0.1",
            port=candidate.ports.postgres,
            user="lmyzmail_test",
            dbname="lmyzmail",
            connect_timeout=5,
        ) as connection:
            rows = connection.execute(
                "SELECT email FROM contact WHERE mailbox_address = %s AND id <> %s",
                ("qa@example.test", 1201),
            ).fetchall()
            preferences = connection.execute(
                "SELECT preferences_json FROM user_preference WHERE mailbox_address = %s",
                ("qa@example.test",),
            ).fetchone()
        assert rows == []
        assert preferences == ('{"itemsPerPage":25,"legacyFixture":true,"theme":"dark"}',)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_serializes_duplicate_contact_admission() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        assert candidate.ports is not None
        ports = candidate.ports

        def create(index: int) -> int:
            response = json_http_exchange(
                "127.0.0.1",
                ports.http,
                "POST",
                "/web/userdata/contacts",
                value={
                    "name": f"Concurrent {index}",
                    "email": "CONCURRENT@EXAMPLE.TEST",
                    "notes": str(index),
                },
                headers=_SESSION_HEADERS,
                timeout=15.0,
            )
            return response.status_code

        with ThreadPoolExecutor(max_workers=16) as executor:
            statuses = tuple(executor.map(create, range(24)))
        assert statuses.count(201) == 1
        assert statuses.count(400) == 23

        with psycopg.connect(
            host="127.0.0.1",
            port=ports.postgres,
            user="lmyzmail_test",
            dbname="lmyzmail",
            connect_timeout=5,
        ) as connection:
            row = connection.execute(
                "SELECT count(*) FROM contact WHERE mailbox_address = %s AND email = %s",
                ("qa@example.test", "concurrent@example.test"),
            ).fetchone()
        assert row == (1,)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_userdata_survives_restart() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        assert candidate.ports is not None
        port = candidate.ports.http
        saved = json_http_exchange(
            "127.0.0.1",
            port,
            "POST",
            "/web/userdata/preferences",
            value={"restart": True, "theme": "dark"},
            headers=_SESSION_HEADERS,
        )
        created = json_http_exchange(
            "127.0.0.1",
            port,
            "POST",
            "/web/userdata/contacts",
            value={
                "name": "Restart Contact",
                "email": "RESTART@EXAMPLE.TEST",
                "notes": "durable",
            },
            headers=_SESSION_HEADERS,
        )
        assert saved.status_code == 200
        assert created.status_code == 201

        candidate.restart_application()
        preferences = http_exchange(
            "127.0.0.1",
            port,
            "GET",
            "/web/userdata/preferences",
            headers=_SESSION_HEADERS,
        )
        contacts = http_exchange(
            "127.0.0.1",
            port,
            "GET",
            "/web/userdata/contacts",
            headers=_SESSION_HEADERS,
        )
        assert preferences.body == b'{"restart":true,"theme":"dark"}'
        assert b'"email":"restart@example.test"' in contacts.body
        assert b'"notes":"durable"' in contacts.body


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_userdata_database_wait_is_deadline_bounded() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        assert candidate.ports is not None
        with psycopg.connect(
            host="127.0.0.1",
            port=candidate.ports.postgres,
            user="lmyzmail_test",
            dbname="lmyzmail",
            connect_timeout=5,
        ) as blocker:
            blocker.execute("LOCK TABLE user_preference IN ACCESS EXCLUSIVE MODE")
            started = time.monotonic()
            response = http_exchange(
                "127.0.0.1",
                candidate.ports.http,
                "GET",
                "/web/userdata/preferences",
                headers=_SESSION_HEADERS,
                timeout=10.0,
            )
            elapsed = time.monotonic() - started
        assert elapsed < 9.5
        assert response.status_code == 500
        assert response.body == b'{"error":"userdata_unavailable"}'


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_userdata_contact_list_has_a_hard_bound() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        assert candidate.ports is not None
        with psycopg.connect(
            host="127.0.0.1",
            port=candidate.ports.postgres,
            user="lmyzmail_test",
            dbname="lmyzmail",
            connect_timeout=5,
        ) as connection:
            connection.execute(
                "INSERT INTO contact "
                "(mailbox_address, email, name, notes, created_at, updated_at) "
                "SELECT %s, 'bounded-' || value || '@example.test', "
                "'Bounded ' || lpad(value::text, 5, '0'), NULL, "
                "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP "
                "FROM generate_series(1, 10000) AS value",
                ("qa@example.test",),
            )

        started = time.monotonic()
        response = http_exchange(
            "127.0.0.1",
            candidate.ports.http,
            "GET",
            "/web/userdata/contacts",
            headers=_SESSION_HEADERS,
            timeout=10.0,
        )
        elapsed = time.monotonic() - started
        assert elapsed < 9.0
        assert response.status_code == 503
        assert response.body == b'{"error":"userdata_limit_exceeded"}'


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_userdata_contact_list_has_a_byte_bound() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        assert candidate.ports is not None
        with psycopg.connect(
            host="127.0.0.1",
            port=candidate.ports.postgres,
            user="lmyzmail_test",
            dbname="lmyzmail",
            connect_timeout=5,
        ) as connection:
            connection.execute(
                "INSERT INTO contact "
                "(mailbox_address, email, name, notes, created_at, updated_at) "
                "VALUES (%s, %s, %s, repeat('x', 16777217), "
                "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
                ("qa@example.test", "oversized@example.test", "Oversized"),
            )

        started = time.monotonic()
        response = http_exchange(
            "127.0.0.1",
            candidate.ports.http,
            "GET",
            "/web/userdata/contacts",
            headers=_SESSION_HEADERS,
            timeout=10.0,
        )
        elapsed = time.monotonic() - started
        assert elapsed < 9.0
        assert response.status_code == 503
        assert response.body == b'{"error":"userdata_limit_exceeded"}'
