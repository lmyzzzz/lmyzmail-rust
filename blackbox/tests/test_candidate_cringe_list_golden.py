from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlencode

import psycopg
import pytest
from test_candidate_cringe_api_golden import (
    _ADMIN_HEADERS,
    _READ_ONLY_HEADERS,
    _WRITE_ONLY_HEADERS,
    _candidate,
    _OracleTarget,
)

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.protocols import http_exchange
from lmyzmail_blackbox.snapshots import http_bytes_snapshot, http_json_snapshot

_PROFILE = "managed-cringe-list"
_GOLDEN = "blackbox/golden/java/managed-cringe-list-v1"
_SORT_FIELDS = (
    "currentScore", "totalScore", "activityCount", "lastSeenAt", "firstSeenAt",
    "selfSpoofingCount", "openRelayCount", "authProbeCount", "illegalDomainCount",
    "spamhausCount", "httpOnSmtpCount", "sshOnSmtpCount", "httpPortScanningCount",
    "honeypotHitCount", "sshBruteforceCount", "otherCount", "ipAddress",
)
_INVALID_QUERIES = (
    "page=-1", "size=0", "size=-1", "page=2147483648", "size=2147483648",
    "page=abc", "size=1.5",
)


def _connection(target: RuntimeTarget) -> psycopg.Connection[Any]:
    assert target.ports is not None
    return psycopg.connect(
        host="127.0.0.1", port=target.ports.postgres,
        user="lmyzmail_test", dbname="lmyzmail", connect_timeout=5,
    )


def _seed_list(target: RuntimeTarget) -> None:
    with _connection(target) as connection:
        connection.execute("DELETE FROM skibidi_cringe_ip_activity")
        connection.execute("DELETE FROM skibidi_cringe_ip")
        for n, ip in enumerate((
            "203.0.113.77", "198.51.100.9", "2001:DB8::AA", "\t203.0.113.88%2F\n",
        ), 1):
            first = datetime(2024, 1, n, tzinfo=UTC)
            connection.execute(
                """
                INSERT INTO skibidi_cringe_ip (
                    ip_address,total_score,current_score,activity_count,
                    first_seen_at,last_seen_at,last_decay_at,
                    self_spoofing_count,open_relay_count,auth_probe_count,
                    illegal_domain_count,spamhaus_count,http_on_smtp_count,
                    ssh_on_smtp_count,http_port_scanning_count,honeypot_hit_count,
                    ssh_bruteforce_count,other_count,pps_overlimit_count,syn_flood_count
                ) VALUES (
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0,0
                )
                """,
                (ip, n * 11, 50 - n, n * 2, first, first + timedelta(hours=1),
                 None if n == 2 else first + timedelta(minutes=30),
                 *(n * 10 + k for k in range(11))),
            )


def _state(target: RuntimeTarget) -> list[Any]:
    with _connection(target) as connection:
        return connection.execute(
            "SELECT row_to_json(c)::text FROM skibidi_cringe_ip c ORDER BY ip_address"
        ).fetchall()


def _capture_list(target: RuntimeTarget) -> dict[str, Any]:
    assert target.ports is not None

    def request(query: str = "", headers: Any = _ADMIN_HEADERS) -> Any:
        response = http_exchange(
            "127.0.0.1", target.ports.http, "GET", "/api/cringe-ips" + query,
            headers=headers, timeout=12.0,
        )
        return http_json_snapshot(
            response, canonicalize_object_order=response.status_code != 200,
        )

    _seed_list(target)
    before = _state(target)
    observed = {
        "default": request(),
        "read_only": request(headers=_READ_ONLY_HEADERS),
        "missing_key": request(headers=()),
        "write_only": request(headers=_WRITE_ONLY_HEADERS),
        "first": request("?size=3"),
        "last": request("?page=1&size=3"),
        "beyond": request("?page=2&size=3"),
        "max_page": request("?page=2147483647&size=500"),
        "capped": request("?size=2147483647"),
        "invalid_sort": request(
            "?sortBy=ip_address%3BDROP%20TABLE%20skibidi_cringe_ip&sortDir=invalid"
        ),
        "sort_case_sensitive": request("?sortBy=TOTALSCORE&sortDir=ASC"),
    }
    for field in _SORT_FIELDS:
        for direction in ("asc", "DESC"):
            observed[f"sort_{field}_{direction}"] = request(
                "?" + urlencode({"sortBy": field, "sortDir": direction, "size": 1}),
            )
    for i, search in enumerate((
        " 203.0 ", "db8", "DB8", "%", "_", "no-such-ip", "x' OR true --",
        "\u00a0DB8\u00a0", "\u2003", "\u2003DB8\u2003", "\t \r\n",
    )):
        observed[f"search_{i}"] = request("?" + urlencode({"search": search}))
    assert _state(target) == before, "GET list must not mutate stored scores or counters"
    with _connection(target) as connection:
        connection.execute("DELETE FROM skibidi_cringe_ip")
    observed["empty"] = request()
    return observed


cast(Any, _capture_list).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket",
    "sequence": [
        "seed four distinct rows including IPv6, legacy control/percent IP and null decay",
        "list with all 17 allowed sorts in both directions and invalid-sort fallback",
        "page, cap size, search case/wildcards/SQL text/Unicode whitespace",
        "probe read-only/write-only/missing keys and confirm no database writes",
        "query empty database",
    ],
    "state": "isolated PostgreSQL, fixed timestamps, XDP disabled",
    "normalization": (
        "HTTP Date and previously evidenced JDK Map.of API-key error object order only; "
        "successful JSON bytes and array order exact"
    ),
}


def _capture_boundaries(target: RuntimeTarget) -> dict[str, Any]:
    assert target.ports is not None
    return {
        query: http_bytes_snapshot(http_exchange(
            "127.0.0.1", target.ports.http, "GET", "/api/cringe-ips?" + query,
            headers=_ADMIN_HEADERS, timeout=10.0,
        ))
        for query in _INVALID_QUERIES
    }


cast(Any, _capture_boundaries).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket",
    "sequence": ["invalid page/size and malformed integer inputs"],
    "evidence_only": True,
    "difference_id": "cringe-pagination-input-validation",
}

_SCENARIOS = (Scenario(
    "http/cringe/list", _capture_list,
    normalizers=("json-object-order:jdk-map-of:cringe-api-key-errors",),
),)
_BOUNDARIES = (Scenario("http/cringe/list-boundaries", _capture_boundaries),)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_frozen_java_cringe_list_golden(tmp_path: Path, record_java_golden: bool) -> None:
    repository = Path(__file__).resolve().parents[2]
    with PersistentJavaOracleRuntime(tmp_path / "java-cringe-list") as oracle:
        for scenarios, suffix in ((_SCENARIOS, ""), (_BOUNDARIES, "-boundaries")):
            runner = DifferentialRunner(
                repository, repository / (_GOLDEN + suffix), _PROFILE + suffix,
                record_java=record_java_golden,
            )
            if record_java_golden:
                runner.record_from_java(scenarios, _OracleTarget(oracle))
            else:
                runner.verify_java(scenarios, _OracleTarget(oracle))


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_candidate_cringe_list_matches_frozen_java() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(repository, repository / _GOLDEN, _PROFILE).verify_candidate(
            _SCENARIOS, candidate,
        )
        assert candidate.ports is not None
        for query in _INVALID_QUERIES:
            response = http_exchange(
                "127.0.0.1", candidate.ports.http, "GET", "/api/cringe-ips?" + query,
                headers=_ADMIN_HEADERS, timeout=10.0,
            )
            assert response.status_code == 400
            assert json.loads(response.body) == {"error": "invalid_request"}


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_candidate_cringe_list_caps_pages_cancels_lock_wait_and_recovers() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository, "--lmyzmail.postgres.pool.max-size=1") as candidate:
        assert candidate.ports is not None
        _seed_list(candidate)
        with _connection(candidate) as connection:
            connection.execute(
                """
                INSERT INTO skibidi_cringe_ip (
                    ip_address,total_score,current_score,activity_count,
                    first_seen_at,last_seen_at,last_decay_at,
                    self_spoofing_count,open_relay_count,auth_probe_count,
                    illegal_domain_count,spamhaus_count,http_on_smtp_count,
                    ssh_on_smtp_count,http_port_scanning_count,honeypot_hit_count,
                    ssh_bruteforce_count,other_count,pps_overlimit_count,syn_flood_count
                ) SELECT 'cap-' || n, n, n, 0,
                    TIMESTAMPTZ '2024-01-01 00:00:00+00',
                    TIMESTAMPTZ '2024-01-01 00:00:00+00', NULL,
                    0,0,0,0,0,0,0,0,0,0,0,0,0
                FROM generate_series(1000,1500) AS series(n)
                """
            )

        def request(query: str = "") -> Any:
            return http_exchange(
                "127.0.0.1", candidate.ports.http, "GET", "/api/cringe-ips" + query,
                headers=_ADMIN_HEADERS, timeout=15.0,
            )

        for page, expected_count in ((0, 500), (1, 5), (2, 0)):
            response = request(f"?page={page}&size=2147483647")
            assert response.status_code == 200
            body = json.loads(response.body)
            assert body["size"] == 500
            assert body["page"] == page
            assert body["totalElements"] == 505
            assert body["totalPages"] == 2
            assert len(body["content"]) == expected_count
        with ThreadPoolExecutor(max_workers=8) as workers:
            responses = list(workers.map(request, ["?size=1"] * 24))
        assert all(response.status_code == 200 for response in responses)
        assert all(json.loads(response.body)["totalElements"] == 505 for response in responses)

        with _connection(candidate) as blocker:
            blocker.execute("LOCK TABLE skibidi_cringe_ip IN ACCESS EXCLUSIVE MODE")
            started = time.monotonic()
            invalid = request("?page=-1")
            assert invalid.status_code == 400
            assert time.monotonic() - started < 2.0, "invalid paging must not await the database"
            started = time.monotonic()
            stalled = request("?size=1")
            assert stalled.status_code == 500
            assert json.loads(stalled.body) == {"error": "internal_error"}
            assert 7.0 <= time.monotonic() - started <= 11.0
            blocker.rollback()
        healthy = request("?size=1")
        assert healthy.status_code == 200
        assert json.loads(healthy.body)["totalElements"] == 505
        with _connection(candidate) as connection:
            assert connection.execute(
                """SELECT count(*) FROM pg_stat_activity
                WHERE datname='lmyzmail' AND pid<>pg_backend_pid()
                AND state='active' AND query LIKE 'SELECT %skibidi_cringe_ip%'"""
            ).fetchone() == (0,)


@pytest.mark.integration
@pytest.mark.parametrize("kind", (
    pytest.param("oracle", marks=pytest.mark.oracle),
    pytest.param("candidate", marks=pytest.mark.candidate),
))
@pytest.mark.timeout(180)
def test_cringe_list_empty_parameters_and_duplicate_first_values(
    tmp_path: Path, kind: str,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    runtime = (
        PersistentJavaOracleRuntime(tmp_path / "java-list-query-edges")
        if kind == "oracle" else _candidate(repository)
    )
    with runtime as started:
        target = _OracleTarget(started) if kind == "oracle" else started
        _seed_list(target)
        assert target.ports is not None

        def request(query: str) -> bytes:
            response = http_exchange(
                "127.0.0.1", target.ports.http, "GET", "/api/cringe-ips" + query,
                headers=_ADMIN_HEADERS, timeout=10.0,
            )
            assert response.status_code == 200
            return response.body

        baseline = request("")
        assert request("?page=&size=&sortBy=&sortDir=&search=") == baseline
        assert request(
            "?page=&page=bad&size=&size=bad&sortBy=&sortBy=ipAddress"
            "&sortDir=&sortDir=asc&search=&search=hidden"
        ) == baseline
        first_values = "?page=0&size=2&sortBy=totalScore&sortDir=asc&search=203.0"
        assert request(
            "?page=0&page=bad&size=2&size=bad&sortBy=totalScore&sortBy=ipAddress"
            "&sortDir=asc&sortDir=desc&search=203.0&search=hidden"
        ) == request(first_values)
        for search in ("\\%", "\\_", "\\"):
            result = json.loads(request("?" + urlencode({"search": search})))
            assert result["content"] == []
            assert result["totalElements"] == 0
        assert request("?" + urlencode({"sortDir": "aſc"})) == request("?sortDir=asc")
