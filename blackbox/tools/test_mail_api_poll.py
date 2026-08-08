from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.protocols import json_http_exchange
from lmyzmail_blackbox.snapshots import http_bytes_snapshot, http_json_snapshot

# Reuse the attested legacy fixture installer and candidate lifecycle without
# adding this exploratory surface to the historical definition-tree hash.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from test_candidate_mail_read_golden import LegacyCandidateRuntime, _OracleTarget

_API_HEADERS = (("X-API-Key", "blackbox-admin-key"),)
_CREDENTIALS = {"address": "qa@example.test", "password": "BlackboxPass123!"}
_GOLDEN = "managed-mail-api-poll-v6"


def _capture_json(path: str, value: object) -> Callable[[RuntimeTarget], dict[str, Any]]:
    def capture(target: RuntimeTarget) -> dict[str, Any]:
        if target.ports is None:
            raise RuntimeError("mail API capture target is not running")
        response = json_http_exchange(
            "127.0.0.1",
            target.ports.http,
            "POST",
            path,
            value=value,
            headers=_API_HEADERS,
            timeout=10.0,
        )
        return http_json_snapshot(response, canonicalize_object_order=True)

    cast(Any, capture).__lmyzmail_contract__ = {
        "protocol": "http",
        "method": "POST",
        "target": path,
        "headers": [["X-API-Key", "blackbox-admin-key"]],
        "json": value,
        "state": "attested legacy PostgreSQL seed and Maildir fixture",
    }
    return capture


def _capture_raw(path: str, value: object) -> Callable[[RuntimeTarget], dict[str, Any]]:
    def capture(target: RuntimeTarget) -> dict[str, Any]:
        if target.ports is None:
            raise RuntimeError("mail API capture target is not running")
        response = json_http_exchange(
            "127.0.0.1",
            target.ports.http,
            "POST",
            path,
            value=value,
            headers=_API_HEADERS,
            timeout=10.0,
        )
        return http_bytes_snapshot(response)

    cast(Any, capture).__lmyzmail_contract__ = {
        "protocol": "http",
        "method": "POST",
        "target": path,
        "headers": [["X-API-Key", "blackbox-admin-key"]],
        "json": value,
        "state": "attested legacy PostgreSQL seed and Maildir fixture",
        "body": "exact bytes",
    }
    return capture


SCENARIOS = (
    Scenario(
        "http/mail-api/poll-limit",
        _capture_json("/api/mail/poll", {**_CREDENTIALS, "limit": 2}),
    ),
    Scenario(
        "http/mail-api/poll-limit-zero",
        _capture_json("/api/mail/poll", {**_CREDENTIALS, "limit": 0}),
    ),
    Scenario("http/mail-api/poll-missing-key", _capture_json("/api/mail/poll", {})),
    Scenario(
        "http/mail-api/poll-since",
        _capture_json(
            "/api/mail/poll",
            {**_CREDENTIALS, "sinceEpochMillis": 1704153600000, "limit": 10},
        ),
    ),
    Scenario(
        "http/mail-api/poll-since-i64-max",
        _capture_json(
            "/api/mail/poll",
            {**_CREDENTIALS, "sinceEpochMillis": 9223372036854775807},
        ),
    ),
    Scenario(
        "http/mail-api/poll-since-i64-min",
        _capture_json(
            "/api/mail/poll",
            {**_CREDENTIALS, "sinceEpochMillis": -9223372036854775808},
        ),
    ),
    Scenario(
        "http/mail-api/poll-invalid-credentials",
        _capture_json("/api/mail/poll", {"address": "qa@example.test", "password": "wrong"}),
    ),
    Scenario(
        "http/mail-api/raw",
        _capture_raw("/api/mail/raw", {**_CREDENTIALS, "file": "legacy-root.eml"}),
    ),
    Scenario(
        "http/mail-api/raw-missing",
        _capture_json("/api/mail/raw", {**_CREDENTIALS, "file": "missing.eml"}),
    ),
    Scenario("http/mail-api/raw-missing-key", _capture_json("/api/mail/raw", {})),
    Scenario(
        "http/mail-api/raw-decoded",
        _capture_json("/api/mail/rawDecoded", {**_CREDENTIALS, "file": "legacy-root.eml"}),
    ),
    Scenario(
        "http/mail-api/raw-decoded-missing-key",
        _capture_json("/api/mail/rawDecoded", {}),
    ),
    Scenario(
        "http/mail-api/raw-decoded-missing",
        _capture_json(
            "/api/mail/rawDecoded",
            {**_CREDENTIALS, "file": "missing.eml"},
        ),
    ),
    Scenario(
        "http/mail-api/raw-decoded-html",
        _capture_json(
            "/api/mail/rawDecoded",
            {**_CREDENTIALS, "file": "legacy-shard-2.eml", "html": True},
        ),
    ),
)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_frozen_java_mail_api_poll_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java" / _GOLDEN
    record_java_golden = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        golden,
        "managed-mail-api-poll",
        record_java=record_java_golden,
    )
    with PersistentJavaOracleRuntime(tmp_path / "java-mail-api") as oracle:
        target = _OracleTarget(oracle)
        if record_java_golden:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_mail_api_poll_matches_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    runtime = LegacyCandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        )
    )
    with runtime as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java" / _GOLDEN,
            "managed-mail-api-poll",
        ).verify_candidate(SCENARIOS, candidate)
