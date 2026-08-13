from __future__ import annotations

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast

import httpx
import psycopg
import pytest
from test_oracle_http_golden import HTTP_SCENARIOS

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.protocols import http_exchange
from lmyzmail_blackbox.runtime import (
    QA_ADDRESS,
    QA_PASSWORD,
    CandidateRuntime,
    JavaOracleRuntime,
)


def _post_json_status(
    target: RuntimeTarget,
    path: str,
    payload: dict[str, str],
    *,
    headers: tuple[tuple[str, str], ...] = (),
) -> int:
    assert target.ports is not None
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return http_exchange(
        "127.0.0.1",
        target.ports.http,
        "POST",
        path,
        headers=(("Content-Type", "application/json"), *headers),
        body=body,
    ).status_code


def _get_status(
    target: RuntimeTarget,
    path: str,
    *,
    headers: tuple[tuple[str, str], ...] = (),
) -> int:
    assert target.ports is not None
    return http_exchange(
        "127.0.0.1",
        target.ports.http,
        "GET",
        path,
        headers=headers,
    ).status_code


def _capture_auth_rate_limits(target: RuntimeTarget) -> dict[str, Any]:
    registration_statuses = [
        _post_json_status(
            target,
            "/web/register",
            {"address": f"rate-{index}@example.test", "password": QA_PASSWORD},
        )
        for index in range(5)
    ]
    forwarded_a = (("X-Forwarded-For", "198.51.100.70, 127.0.0.1"),)
    forwarded_b = (("X-Forwarded-For", "198.51.100.71, 127.0.0.1"),)
    forwarded_login_statuses = [
        _post_json_status(
            target,
            "/web/login",
            {"address": QA_ADDRESS, "password": "wrong-password"},
            headers=forwarded_a,
        )
        for _ in range(11)
    ]
    forwarded_ban_statuses = [
        _get_status(target, "/api/health", headers=forwarded_a),
        _get_status(target, "/api/health", headers=forwarded_b),
    ]
    login_statuses = [
        _post_json_status(
            target,
            "/web/login",
            {"address": QA_ADDRESS, "password": "wrong-password"},
        )
        for _ in range(10)
    ]
    return {
        "registration_statuses_after_startup_registration": registration_statuses,
        "trusted_proxy_login_statuses": forwarded_login_statuses,
        "trusted_proxy_banned_and_independent_health_statuses": forwarded_ban_statuses,
        "login_statuses_after_one_prior_failure": login_statuses,
    }


cast(Any, _capture_auth_rate_limits).__lmyzmail_contract__ = {
    "protocol": "http",
    "sequence": [
        "5 unique POST /web/register after startup QA registration",
        "11 invalid proxied logins from one client followed by banned/independent health probes",
        "10 invalid POST /web/login after one prior suite failure",
    ],
    "rate_limit_contract": "dual-ip-principal-login-and-per-ip-registration",
}

AUTH_HTTP_SCENARIOS = (
    *HTTP_SCENARIOS[10:14],
    HTTP_SCENARIOS[21],
    Scenario("http/web/auth-rate-limits", _capture_auth_rate_limits),
)


def _candidate(repository: Path) -> CandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        return CandidateRuntime.from_environment()
    return CandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        )
    )


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(120)
def test_frozen_java_auth_http_golden(record_java_golden: bool) -> None:
    paths = JavaOracleRuntime().paths
    runner = DifferentialRunner(
        paths.repository,
        paths.repository / "blackbox/golden/java/managed-candidate-auth-v32",
        "managed-candidate-auth",
        record_java=record_java_golden,
    )
    with JavaOracleRuntime(paths=paths) as oracle:
        if record_java_golden:
            runner.record_from_java(AUTH_HTTP_SCENARIOS, oracle)
        else:
            runner.verify_java(AUTH_HTTP_SCENARIOS, oracle)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(120)
def test_rust_candidate_auth_http_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    candidate = _candidate(repository)
    with candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java/managed-candidate-auth-v32",
            "managed-candidate-auth",
        ).verify_candidate(AUTH_HTTP_SCENARIOS, candidate)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(120)
def test_rust_candidate_persists_only_session_token_hash_and_logout_deletes_it() -> None:
    repository = Path(__file__).resolve().parents[2]
    candidate = _candidate(repository)
    with candidate:
        assert candidate.ports is not None
        base_url = f"http://127.0.0.1:{candidate.ports.http}"
        with httpx.Client(trust_env=False, timeout=10.0) as client:
            response = client.post(
                f"{base_url}/web/login",
                json={"address": QA_ADDRESS, "password": QA_PASSWORD},
            )
            assert response.status_code == 200
            token = cast(str, response.json()["token"])
            with psycopg.connect(
                host="127.0.0.1",
                port=candidate.ports.postgres,
                user="lmyzmail_test",
                dbname="lmyzmail",
                connect_timeout=5,
            ) as connection:
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                row = connection.execute(
                    "SELECT count(*) FROM user_session WHERE token_hash = %s",
                    (token_hash,),
                ).fetchone()
                assert row == (1,)
                plaintext = connection.execute(
                    "SELECT count(*) FROM user_session WHERE token_hash = %s",
                    (token,),
                ).fetchone()
                assert plaintext == (0,)

                logout = client.post(
                    f"{base_url}/web/logout",
                    headers={"X-Session-Token": token},
                    json={},
                )
                assert logout.status_code == 200
                deleted = connection.execute(
                    "SELECT count(*) FROM user_session WHERE token_hash = %s",
                    (token_hash,),
                ).fetchone()
                assert deleted == (0,)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(120)
def test_rust_candidate_bounds_concurrent_sessions_per_mailbox() -> None:
    repository = Path(__file__).resolve().parents[2]
    candidate = _candidate(repository)
    with candidate:
        assert candidate.ports is not None
        login_url = f"http://127.0.0.1:{candidate.ports.http}/web/login"

        def login() -> tuple[int, str]:
            with httpx.Client(trust_env=False, timeout=15.0) as client:
                response = client.post(
                    login_url,
                    json={"address": QA_ADDRESS, "password": QA_PASSWORD},
                )
            return response.status_code, cast(str, response.json().get("token", ""))

        with ThreadPoolExecutor(max_workers=16) as executor:
            results = tuple(executor.map(lambda _: login(), range(24)))

        assert [status for status, _ in results] == [200] * 24
        tokens = {token for _, token in results}
        assert len(tokens) == 24
        expected_hashes = {hashlib.sha256(token.encode()).hexdigest() for token in tokens}

        with psycopg.connect(
            host="127.0.0.1",
            port=candidate.ports.postgres,
            user="lmyzmail_test",
            dbname="lmyzmail",
            connect_timeout=5,
        ) as connection:
            rows = connection.execute(
                "SELECT token_hash, token_prefix FROM user_session "
                "WHERE mailbox_address = %s AND expires_at > CURRENT_TIMESTAMP",
                (QA_ADDRESS,),
            ).fetchall()
        assert len(rows) == 10
        assert {cast(str, row[0]) for row in rows} <= expected_hashes
        assert all(len(cast(str, row[1])) == 8 for row in rows)
        assert all(cast(str, row[0]) not in tokens for row in rows)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(120)
def test_rust_candidate_enforces_registration_limit_under_concurrency() -> None:
    repository = Path(__file__).resolve().parents[2]
    candidate = _candidate(repository)
    with candidate:
        assert candidate.ports is not None
        register_url = f"http://127.0.0.1:{candidate.ports.http}/web/register"

        def register(index: int) -> int:
            with httpx.Client(trust_env=False, timeout=15.0) as client:
                response = client.post(
                    register_url,
                    json={
                        "address": f"concurrent-{index}@example.test",
                        "password": QA_PASSWORD,
                    },
                )
            return response.status_code

        with ThreadPoolExecutor(max_workers=12) as executor:
            statuses = tuple(executor.map(register, range(12)))

        assert statuses.count(201) == 4
        assert statuses.count(429) == 8
        with psycopg.connect(
            host="127.0.0.1",
            port=candidate.ports.postgres,
            user="lmyzmail_test",
            dbname="lmyzmail",
            connect_timeout=5,
        ) as connection:
            row = connection.execute(
                "SELECT count(*) FROM mailbox WHERE address LIKE 'concurrent-%@example.test'"
            ).fetchone()
        assert row == (4,)
