from __future__ import annotations

import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest

from lmyzmail_blackbox.golden import GoldenAttestation, GoldenStore


def _repository() -> Path:
    return Path(__file__).resolve().parents[2]


def _run_probe(repository: Path, *, target: str) -> dict[str, object]:
    result = subprocess.run(  # noqa: S603,S607
        [
            "/bin/bash",
            str(repository / "blackbox/bin/run-outbound-probe.sh"),
        ],
        cwd=repository,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "LMYZMAIL_BLACKBOX_PYTHON": sys.executable,
            "LMYZMAIL_OUTBOUND_ORACLE_MODE": "4XX",
            "LMYZMAIL_OUTBOUND_TARGET": target,
        },
        timeout=850,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            "outbound 4xx probe failed with "
            f"{result.returncode}:\nstdout={result.stdout}\nstderr={result.stderr}"
        )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise AssertionError(f"outbound 4xx probe returned a non-object: {value!r}")
    return value


def _assert_contract(observed: dict[str, object]) -> None:
    assert observed["codes"] == [400, 421, 450, 451, 452, 499]
    assert observed["retryable_codes"] == [421, 450, 451, 452]
    assert observed["terminal_codes"] == [400, 499]
    assert observed["phases"] == ["RCPT", "DATA"]
    assert observed["case_count"] == 12
    cases = observed["cases"]
    assert isinstance(cases, list)
    for case in cases:
        assert isinstance(case, dict)
        phase = case["phase"]
        code = case["code"]
        retryable = code in (421, 450, 451, 452)
        assert case["classification"] == ("retryable" if retryable else "terminal")
        assert case["response"]["status_code"] == 202
        assert case["response"]["queued"] is True
        first = case["first_retry"]
        if retryable:
            assert first["retry_count"] == 1
            assert first["scheduled_delay_seconds"] == 30
            assert first["redis"]["task"]["status"] == "PENDING"
            assert first["redis"]["task"]["retry_count"] == 1
            assert first["redis"]["retry_zset_member"] is True
            assert first["redis"]["aggregate_status"] == "PROCESSING"
            assert str(code) in first["redis"]["task"]["last_error"]
            assert case["forced_exhaustion_retry_count"] == 5
        else:
            assert first is None
            assert case["forced_exhaustion_retry_count"] is None
        terminal = case["terminal"]
        assert terminal["db"]["status"] == "FAILED"
        assert terminal["db"]["retry_count"] == (5 if retryable else 0)
        assert terminal["redis"]["task"] is None
        assert terminal["redis"]["retry_zset_member"] is False
        assert terminal["redis"]["aggregate_status"] == "PROCESSING"
        assert case["wire"]["failure_reply_count"] == (2 if retryable else 1)
        assert case["wire"]["data_observed"] is (phase == "DATA")

    backoff = cast(dict[str, Any], observed["backoff"])
    assert backoff["phase"] == "DATA"
    assert backoff["code"] == 451
    assert [entry["retry_count"] for entry in backoff["retries"]] == [1, 2, 3, 4, 5]
    assert [entry["scheduled_delay_seconds"] for entry in backoff["retries"]] == [
        30,
        60,
        120,
        240,
        480,
    ]
    assert backoff["wire"]["failure_reply_count"] == 6
    assert backoff["terminal"]["db"]["status"] == "FAILED"
    assert backoff["terminal"]["db"]["retry_count"] == 5
    assert observed["time_advancement"] == {
        "storage_contract": "legacy PostgreSQL row plus Redis task and retry ZSET",
        "wall_clock_modified": False,
        "observed_deadline_before_each_advance": True,
    }


def _assert_golden(
    repository: Path,
    observed: dict[str, object],
    *,
    record_java: bool,
) -> None:
    path = repository / "blackbox/golden/java/managed-outbound-4xx-v3.json"
    attestation = GoldenAttestation.from_repository(
        repository,
        profile="managed-outbound-4xx",
        normalizers=("outbound:queue-id", "outbound:retry-deadline"),
    )
    store = GoldenStore(path.parent, attestation, record=record_java)
    store.assert_observation(path.name, observed)


def _assert_candidate_checkpoint_difference(
    repository: Path, observed: dict[str, object]
) -> None:
    path = repository / "blackbox/golden/java/managed-outbound-4xx-v3.json"
    envelope = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    attestation = GoldenAttestation.from_repository(
        repository,
        profile="managed-outbound-4xx",
        normalizers=("outbound:queue-id", "outbound:retry-deadline"),
    )
    assert envelope["schema_version"] == 2
    assert envelope["attestation"] == attestation.as_json()

    manifest = json.loads(
        (repository / "blackbox/manifests/behavior-differences.json").read_text(
            encoding="utf-8"
        )
    )
    assert any(
        entry["id"] == "outbound-retry-postgres-checkpoint"
        for entry in manifest["differences"]
    )

    expected = cast(dict[str, Any], deepcopy(envelope["observation"]))
    actual = cast(dict[str, Any], deepcopy(observed))

    def assert_checkpoint(
        expected_retry: dict[str, Any], actual_retry: dict[str, Any]
    ) -> None:
        assert expected_retry.pop("db") == {
            "deadline_matches_retry": None,
            "present": False,
        }
        task = cast(dict[str, Any], actual_retry["redis"]["task"])
        assert actual_retry.pop("db") == {
            "deadline_matches_retry": True,
            "last_error": task["last_error"],
            "max_retries": 5,
            "present": True,
            "retry_count": actual_retry["retry_count"],
            "status": "PENDING",
        }

    for expected_case, actual_case in zip(
        cast(list[dict[str, Any]], expected["cases"]),
        cast(list[dict[str, Any]], actual["cases"]),
        strict=True,
    ):
        if expected_case["classification"] == "retryable":
            assert_checkpoint(expected_case["first_retry"], actual_case["first_retry"])

    for expected_retry, actual_retry in zip(
        cast(list[dict[str, Any]], expected["backoff"]["retries"]),
        cast(list[dict[str, Any]], actual["backoff"]["retries"]),
        strict=True,
    ):
        assert_checkpoint(expected_retry, actual_retry)

    assert actual == expected


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(900)
def test_managed_java_outbound_4xx_retry_and_exhaustion(record_java_golden: bool) -> None:
    repository = _repository()
    observed = _run_probe(repository, target="java")
    _assert_contract(observed)
    _assert_golden(repository, observed, record_java=record_java_golden)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(900)
def test_rust_candidate_outbound_4xx_matches_frozen_java_golden() -> None:
    repository = _repository()
    observed = _run_probe(repository, target="candidate")
    _assert_contract(observed)
    _assert_candidate_checkpoint_difference(repository, observed)
