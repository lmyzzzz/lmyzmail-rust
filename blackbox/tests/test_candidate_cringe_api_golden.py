from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import psycopg
import pytest

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.protocols import http_exchange
from lmyzmail_blackbox.runtime import (
    API_KEY,
    READ_ONLY_API_KEY,
    WRITE_ONLY_API_KEY,
    CandidateRuntime,
)
from lmyzmail_blackbox.snapshots import http_bytes_snapshot, http_json_snapshot

_PROFILE = "managed-cringe-api"
_GOLDEN = "blackbox/golden/java/managed-cringe-api-v12"
_BOUNDARY_PROFILE = "managed-cringe-api-oracle-boundaries"
_BOUNDARY_GOLDEN = "blackbox/golden/java/managed-cringe-api-oracle-boundaries-v11"
_DECAY_PROFILE = "managed-cringe-decay"
_DECAY_GOLDEN = "blackbox/golden/java/managed-cringe-decay-v8"
_ADMIN_HEADERS = (("X-API-Key", API_KEY),)
_READ_ONLY_HEADERS = (("X-API-Key", READ_ONLY_API_KEY),)
_WRITE_ONLY_HEADERS = (("X-API-Key", WRITE_ONLY_API_KEY),)


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


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value).replace(tzinfo=UTC)


def _seed_cringe_fixture(target: RuntimeTarget) -> None:
    assert target.ports is not None
    with psycopg.connect(
        host="127.0.0.1",
        port=target.ports.postgres,
        user="lmyzmail_test",
        dbname="lmyzmail",
        connect_timeout=5,
    ) as connection:
        connection.execute("DELETE FROM skibidi_cringe_ip_activity")
        connection.execute("DELETE FROM skibidi_cringe_ip")
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO skibidi_cringe_ip (
                    ip_address, total_score, current_score, activity_count,
                    first_seen_at, last_seen_at, last_decay_at,
                    self_spoofing_count, open_relay_count, auth_probe_count,
                    illegal_domain_count, spamhaus_count, http_on_smtp_count,
                    ssh_on_smtp_count, http_port_scanning_count, honeypot_hit_count,
                    ssh_bruteforce_count, pps_overlimit_count, syn_flood_count, other_count
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    (
                        "203.0.113.77",
                        17,
                        7,
                        4,
                        _timestamp("2024-01-01T00:00:00"),
                        _timestamp("2024-01-03T00:00:00"),
                        _timestamp("2024-01-02T00:00:00"),
                        1,
                        0,
                        0,
                        0,
                        0,
                        1,
                        2,
                        3,
                        1,
                        0,
                        0,
                        0,
                        4,
                    ),
                    (
                        "198.51.100.9",
                        5,
                        19,
                        1,
                        _timestamp("2024-01-01T12:00:00"),
                        _timestamp("2024-01-04T00:00:00"),
                        None,
                        1,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    ),
                ),
            )
            cursor.executemany(
                """
                INSERT INTO skibidi_cringe_ip_activity (
                    id, ip_address, activity_type, score, timestamp, mail_from,
                    rcpt_to, helo_name, session_id, response_message, metadata
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    (
                        920_001,
                        "203.0.113.77",
                        "SELF_SPOOFING",
                        10,
                        _timestamp("2024-01-02T03:04:05.123456"),
                        "from@example.test",
                        "qa@example.test",
                        "helo.example.test",
                        "session-a",
                        "ratio: 你好",
                        '{"fixture":true}',
                    ),
                    (
                        920_002,
                        "203.0.113.77",
                        "HONEYPOT_HIT",
                        7,
                        _timestamp("2024-01-03T00:00:00"),
                        None,
                        None,
                        None,
                        "session-b",
                        "not an insult",
                        None,
                    ),
                    (
                        920_003,
                        "203.0.113.77",
                        "SELF_SPOOFING",
                        10,
                        _timestamp("2024-01-02T04:00:00"),
                        None,
                        None,
                        None,
                        None,
                        "",
                        None,
                    ),
                    (
                        920_004,
                        "203.0.113.77",
                        "SELF_SPOOFING",
                        10,
                        _timestamp("2024-01-02T05:00:00"),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    ),
                    (
                        920_005,
                        "198.51.100.9",
                        "SELF_SPOOFING",
                        10,
                        _timestamp("2024-01-04T00:00:00"),
                        None,
                        None,
                        None,
                        "session-c",
                        "other ip insult",
                        None,
                    ),
                ),
            )


def _capture_cringe_api(target: RuntimeTarget) -> dict[str, Any]:
    ports = target.ports
    assert ports is not None
    _seed_cringe_fixture(target)

    def json_request(
        path: str,
        headers: tuple[tuple[str, str], ...] = _ADMIN_HEADERS,
        *,
        canonicalize_object_order: bool = False,
    ) -> Any:
        return http_json_snapshot(
            http_exchange(
                "127.0.0.1",
                ports.http,
                "GET",
                path,
                headers=headers,
                timeout=10.0,
            ),
            canonicalize_object_order=canonicalize_object_order,
        )

    export = http_exchange(
        "127.0.0.1",
        ports.http,
        "GET",
        "/api/cringe-ips/export?minScore=0&scoreType=TOTAL",
        headers=_ADMIN_HEADERS,
        timeout=10.0,
    )
    return {
        "above_total": json_request("/api/cringe-ips/above-score/10"),
        "above_current": json_request(
            "/api/cringe-ips/above-score/10?scoreType=current"
        ),
        "insults": json_request("/api/cringe-ips/insults?page=0&size=1"),
        "insults_search": json_request(
            "/api/cringe-ips/insults?page=0&size=50&search=203.0"
        ),
        "activities_first": json_request(
            "/api/cringe-ips/203.0.113.77/activities?page=0&size=2"
        ),
        "activities_last": json_request(
            "/api/cringe-ips/203.0.113.77/activities?page=1&size=2"
        ),
        "export_total_case_preserved": http_bytes_snapshot(export),
        "missing_key": json_request(
            "/api/cringe-ips/above-score/10",
            (),
            canonicalize_object_order=True,
        ),
        "write_only_key": json_request(
            "/api/cringe-ips/export",
            (("X-API-Key", WRITE_ONLY_API_KEY),),
            canonicalize_object_order=True,
        ),
    }


cast(Any, _capture_cringe_api).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket",
    "sequence": [
        "replace isolated PostgreSQL cringe rows with fixed dual-score and activity fixtures",
        "query total and current score lists",
        "page and search SELF_SPOOFING insults",
        "page one IP's complete activity history",
        "export total scores while preserving caller scoreType spelling",
        "probe missing and write-only API keys",
    ],
    "state": "isolated PostgreSQL schema and deterministic timestamps",
    "normalization": (
        "HTTP Date and proven Java Map.of member order for the two API-key errors only; "
        "data JSON order, timestamp precision, and export bytes are exact"
    ),
}


def _capture_invalid_paging(target: RuntimeTarget) -> dict[str, Any]:
    ports = target.ports
    assert ports is not None

    def request(path: str) -> Any:
        return http_bytes_snapshot(
            http_exchange(
                "127.0.0.1",
                ports.http,
                "GET",
                path,
                headers=_ADMIN_HEADERS,
                timeout=10.0,
            )
        )

    return {
        "negative_page": request("/api/cringe-ips/insults?page=-1&size=50"),
        "zero_size": request(
            "/api/cringe-ips/203.0.113.77/activities?page=0&size=0"
        ),
    }


cast(Any, _capture_invalid_paging).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket",
    "sequence": ["send negative page", "send zero page size"],
    "state": "isolated Java oracle",
    "evidence_only": True,
    "difference_id": "cringe-pagination-input-validation",
}


def _seed_decay_fixture(target: RuntimeTarget) -> None:
    ports = target.ports
    assert ports is not None
    with psycopg.connect(
        host="127.0.0.1",
        port=ports.postgres,
        user="lmyzmail_test",
        dbname="lmyzmail",
        connect_timeout=5,
    ) as connection:
        connection.execute("DELETE FROM skibidi_cringe_ip_activity")
        connection.execute("DELETE FROM skibidi_cringe_ip")
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO skibidi_cringe_ip (
                    ip_address, total_score, current_score, activity_count,
                    first_seen_at, last_seen_at, last_decay_at,
                    self_spoofing_count, open_relay_count, auth_probe_count,
                    illegal_domain_count, spamhaus_count, http_on_smtp_count,
                    ssh_on_smtp_count, http_port_scanning_count, honeypot_hit_count,
                    ssh_bruteforce_count, pps_overlimit_count, syn_flood_count, other_count
                ) VALUES (
                    %s, %s, %s, 1, %s, %s, %s,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                )
                """,
                (
                    (
                        "203.0.113.10",
                        100,
                        47,
                        _timestamp("2024-01-01T00:00:00"),
                        _timestamp("2024-01-02T00:00:00"),
                        _timestamp("2024-01-02T00:00:00"),
                    ),
                    (
                        "203.0.113.11",
                        6,
                        6,
                        _timestamp("2024-01-01T00:00:00"),
                        _timestamp("2024-01-02T00:00:00"),
                        _timestamp("2024-01-02T00:00:00"),
                    ),
                    (
                        "198.51.100.12",
                        31,
                        31,
                        _timestamp("2024-01-01T00:00:00"),
                        _timestamp("2024-01-02T00:00:00"),
                        None,
                    ),
                    (
                        "198.51.100.13",
                        50,
                        0,
                        _timestamp("2024-01-01T00:00:00"),
                        _timestamp("2024-01-02T00:00:00"),
                        _timestamp("2024-01-02T00:00:00"),
                    ),
                    (
                        "198.51.100.14",
                        52,
                        52,
                        _timestamp("2024-01-01T00:00:00"),
                        _timestamp("2024-01-02T00:00:00"),
                        _timestamp("2099-01-01T00:00:00"),
                    ),
                ),
            )


def _decay_database_state(
    target: RuntimeTarget,
    request_started: datetime,
    request_finished: datetime,
) -> list[dict[str, Any]]:
    ports = target.ports
    assert ports is not None
    expected_updated = {"198.51.100.12", "203.0.113.10", "203.0.113.11"}
    with psycopg.connect(
        host="127.0.0.1",
        port=ports.postgres,
        user="lmyzmail_test",
        dbname="lmyzmail",
        connect_timeout=5,
    ) as connection:
        rows = connection.execute(
            """
            SELECT ip_address,total_score,current_score,last_decay_at
            FROM skibidi_cringe_ip
            ORDER BY ip_address
            """
        ).fetchall()

    state: list[dict[str, Any]] = []
    observed_updated: set[str] = set()
    for ip_address, total_score, current_score, last_decay_at in rows:
        assert isinstance(ip_address, str)
        assert isinstance(last_decay_at, datetime)
        if request_started <= last_decay_at <= request_finished:
            observed_updated.add(ip_address)
            normalized_last_decay: str = "<decay-transaction-time>"
        else:
            normalized_last_decay = last_decay_at.isoformat().replace("+00:00", "Z")
        state.append(
            {
                "ipAddress": ip_address,
                "totalScore": total_score,
                "currentScore": current_score,
                "lastDecayAt": normalized_last_decay,
            }
        )
    assert observed_updated == expected_updated
    return state


def _capture_cringe_decay(target: RuntimeTarget) -> dict[str, Any]:
    ports = target.ports
    assert ports is not None
    _seed_decay_fixture(target)

    def json_request(
        method: str,
        path: str,
        headers: tuple[tuple[str, str], ...] = _ADMIN_HEADERS,
        *,
        canonicalize_object_order: bool = False,
    ) -> Any:
        return http_json_snapshot(
            http_exchange(
                "127.0.0.1",
                ports.http,
                method,
                path,
                headers=headers,
                timeout=10.0,
            ),
            canonicalize_object_order=canonicalize_object_order,
        )

    before = {
        "config": http_bytes_snapshot(
            http_exchange(
                "127.0.0.1",
                ports.http,
                "GET",
                "/api/cringe-ips/decay-config",
                headers=_ADMIN_HEADERS,
                timeout=10.0,
            )
        ),
        "high_estimate": json_request(
            "GET",
            "/api/cringe-ips/203.0.113.10/decay-estimate",
            canonicalize_object_order=True,
        ),
        "below_threshold_estimate": json_request(
            "GET",
            "/api/cringe-ips/203.0.113.11/decay-estimate",
            canonicalize_object_order=True,
        ),
        "missing_estimate": http_bytes_snapshot(
            http_exchange(
                "127.0.0.1",
                ports.http,
                "GET",
                "/api/cringe-ips/192.0.2.250/decay-estimate",
                headers=_ADMIN_HEADERS,
                timeout=10.0,
            )
        ),
        "read_only_decay": json_request(
            "POST",
            "/api/cringe-ips/decay",
            _READ_ONLY_HEADERS,
            canonicalize_object_order=True,
        ),
        "write_only_config": json_request(
            "GET",
            "/api/cringe-ips/decay-config",
            _WRITE_ONLY_HEADERS,
            canonicalize_object_order=True,
        ),
    }
    request_started = datetime.now(UTC)
    decay = json_request("POST", "/api/cringe-ips/decay")
    request_finished = datetime.now(UTC)
    database_state = _decay_database_state(target, request_started, request_finished)
    after_estimate = json_request(
        "GET",
        "/api/cringe-ips/203.0.113.10/decay-estimate",
        canonicalize_object_order=True,
    )
    second_decay = json_request("POST", "/api/cringe-ips/decay")
    _seed_decay_fixture(target)
    write_only_started = datetime.now(UTC)
    write_only_decay = json_request(
        "POST",
        "/api/cringe-ips/decay",
        _WRITE_ONLY_HEADERS,
    )
    write_only_finished = datetime.now(UTC)
    write_only_database_state = _decay_database_state(
        target,
        write_only_started,
        write_only_finished,
    )

    return {
        "before": before,
        "first_decay": decay,
        "database_after_first_decay": database_state,
        "high_estimate_after_decay": after_estimate,
        "second_decay": second_decay,
        "write_only_decay": write_only_decay,
        "database_after_write_only_decay": write_only_database_state,
    }


cast(Any, _capture_cringe_decay).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket+postgresql",
    "sequence": [
        "replace isolated PostgreSQL cringe rows with due, future, zero, and NULL decay states",
        "read the default decay configuration and estimates around the unban threshold",
        "probe missing-IP, read-only mutation, and write-only read boundaries",
        "trigger one manual decay and inspect the atomic PostgreSQL state transition",
        "re-estimate the changed score and prove an immediate second decay is idempotent",
        "re-seed the fixture and prove a write-only key can run the same atomic decay",
    ],
    "state": "isolated PostgreSQL schema with deterministic pre-decay timestamps",
    "normalization": (
        "HTTP Date, proven Java Map.of member order, and each transaction timestamp bounded "
        "by its triggering request; scores, affected rows, unchanged timestamps, and all "
        "duration strings are exact"
    ),
    "oracle_evidence": "evidence/freeze/java-oracle/cringe-decay.json",
}


CRINGE_SCENARIOS = (
    Scenario(
        "http/cringe/data-plane",
        _capture_cringe_api,
        normalizers=("json-object-order:jdk-map-of:cringe-api-key-errors",),
    ),
)
CRINGE_BOUNDARY_SCENARIOS = (
    Scenario("http/cringe/invalid-paging", _capture_invalid_paging),
)
CRINGE_DECAY_SCENARIOS = (
    Scenario(
        "http/cringe/decay",
        _capture_cringe_decay,
        normalizers=(
            "json-object-order:jdk-map-of:cringe-decay",
            "database-time:bounded-decay-transaction",
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


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_frozen_java_cringe_api_goldens(
    tmp_path: Path,
    record_java_golden: bool,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    with PersistentJavaOracleRuntime(tmp_path / "java-cringe-api") as oracle:
        target = _OracleTarget(oracle)
        for root, profile, scenarios in (
            (_GOLDEN, _PROFILE, CRINGE_SCENARIOS),
            (_BOUNDARY_GOLDEN, _BOUNDARY_PROFILE, CRINGE_BOUNDARY_SCENARIOS),
            (_DECAY_GOLDEN, _DECAY_PROFILE, CRINGE_DECAY_SCENARIOS),
        ):
            runner = DifferentialRunner(
                repository,
                repository / root,
                profile,
                record_java=record_java_golden,
            )
            if record_java_golden:
                runner.record_from_java(scenarios, target)
            else:
                runner.verify_java(scenarios, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_cringe_api_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(
            repository,
            repository / _GOLDEN,
            _PROFILE,
        ).verify_candidate(CRINGE_SCENARIOS, candidate)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_cringe_decay_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(
            repository,
            repository / _DECAY_GOLDEN,
            _DECAY_PROFILE,
        ).verify_candidate(CRINGE_DECAY_SCENARIOS, candidate)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_rejects_invalid_cringe_paging() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        assert candidate.ports is not None
        for path in (
            "/api/cringe-ips/insults?page=-1&size=50",
            "/api/cringe-ips/203.0.113.77/activities?page=0&size=0",
            "/api/cringe-ips/insults?page=0&size=2147483648",
        ):
            response = http_exchange(
                "127.0.0.1",
                candidate.ports.http,
                "GET",
                path,
                headers=_ADMIN_HEADERS,
                timeout=10.0,
            )
            assert response.status_code == 400
            assert json.loads(response.body) == {"error": "invalid_request"}


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_caps_cringe_score_exports_at_ten_thousand_rows() -> None:
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
            connection.execute("DELETE FROM skibidi_cringe_ip_activity")
            connection.execute("DELETE FROM skibidi_cringe_ip")
            connection.execute(
                """
                INSERT INTO skibidi_cringe_ip (
                    ip_address, total_score, current_score, activity_count,
                    first_seen_at, last_seen_at, last_decay_at,
                    self_spoofing_count, open_relay_count, auth_probe_count,
                    illegal_domain_count, spamhaus_count, http_on_smtp_count,
                    ssh_on_smtp_count, http_port_scanning_count, honeypot_hit_count,
                    ssh_bruteforce_count, pps_overlimit_count, syn_flood_count, other_count
                )
                SELECT
                    'cap-' || n, n, n, 0,
                    TIMESTAMPTZ '2024-01-01 00:00:00+00',
                    TIMESTAMPTZ '2024-01-01 00:00:00+00', NULL,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                FROM generate_series(0, 10000) AS series(n)
                """
            )
        response = http_exchange(
            "127.0.0.1",
            candidate.ports.http,
            "GET",
            "/api/cringe-ips/above-score/0?scoreType=current",
            headers=_ADMIN_HEADERS,
            timeout=20.0,
        )
        body = cast(list[dict[str, Any]], json.loads(response.body))
        assert response.status_code == 200
        assert len(body) == 10_000
        assert body[0]["currentScore"] == 10_000
        assert body[-1]["currentScore"] == 1


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_cancels_stalled_cringe_query_and_recovers_pool() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository, "--lmyzmail.postgres.pool.max-size=1") as candidate:
        assert candidate.ports is not None
        blocker = psycopg.connect(
            host="127.0.0.1",
            port=candidate.ports.postgres,
            user="lmyzmail_test",
            dbname="lmyzmail",
            connect_timeout=5,
        )
        try:
            blocker.execute("LOCK TABLE skibidi_cringe_ip IN ACCESS EXCLUSIVE MODE")
            started = time.monotonic()
            stalled = http_exchange(
                "127.0.0.1",
                candidate.ports.http,
                "GET",
                "/api/cringe-ips/above-score/0",
                headers=_ADMIN_HEADERS,
                timeout=15.0,
            )
            elapsed = time.monotonic() - started
            assert stalled.status_code == 500
            assert json.loads(stalled.body) == {"error": "internal_error"}
            assert 7.0 <= elapsed <= 11.0
        finally:
            blocker.rollback()
            blocker.close()

        healthy = http_exchange(
            "127.0.0.1",
            candidate.ports.http,
            "GET",
            "/api/cringe-ips/above-score/0",
            headers=_ADMIN_HEADERS,
            timeout=10.0,
        )
        assert healthy.status_code == 200
        healthy_body = cast(list[dict[str, Any]], json.loads(healthy.body))
        assert len(healthy_body) == 1
        assert healthy_body[0]["ipAddress"] == "203.0.113.77"
        with psycopg.connect(
            host="127.0.0.1",
            port=candidate.ports.postgres,
            user="lmyzmail_test",
            dbname="lmyzmail",
            connect_timeout=5,
        ) as inspector:
            active = inspector.execute(
                """
                SELECT count(*) FROM pg_stat_activity
                WHERE datname = 'lmyzmail'
                  AND pid <> pg_backend_pid()
                  AND state = 'active'
                  AND query LIKE 'SELECT %skibidi_cringe_ip%'
                """
            ).fetchone()
        assert active == (0,)
