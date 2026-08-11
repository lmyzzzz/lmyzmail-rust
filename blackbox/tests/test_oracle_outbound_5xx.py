from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

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
            "LMYZMAIL_OUTBOUND_ORACLE_MODE": "5XX",
            "LMYZMAIL_OUTBOUND_TARGET": target,
        },
        timeout=350,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            "outbound 5xx probe failed with "
            f"{result.returncode}:\nstdout={result.stdout}\nstderr={result.stderr}"
        )

    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise AssertionError(f"outbound 5xx probe returned a non-object: {value!r}")
    return value


def _assert_contract(observed: dict[str, object]) -> None:
    assert observed["codes"] == [500, 501, 549, 550, 554]
    assert observed["case_count"] == 10
    cases = observed["cases"]
    assert isinstance(cases, list)
    for case in cases:
        assert isinstance(case, dict)
        code = case["code"]
        phase = case["phase"]
        task = case["redis"]["task"]
        domains = case["redis"]["domains"]
        assert case["response"]["status_code"] == 202
        assert case["response"]["queued"] is True
        assert task is None
        assert case["redis"]["task_present_after_archive"] is False
        assert case["db"]["status"] == "FAILED"
        assert case["db"]["retry_count"] == 0
        assert str(code) in case["db"]["last_error"]
        assert list(domains) == ["outbound.fixture.test"]
        domain = domains["outbound.fixture.test"]
        assert domain["status"] == "FAILED"
        assert str(code) in domain["error"]
        assert case["wire"]["data_observed"] is (phase == "DATA")
        assert (case["wire"]["data_event_count"] > 0) is (phase == "DATA")
        assert case["redis"]["aggregate_status"] == (
            "FAILED" if code in (550, 554) else "PROCESSING"
        )


def _assert_golden(
    repository: Path,
    observed: dict[str, object],
    *,
    record_java: bool,
) -> None:
    path = repository / "blackbox/golden/java/managed-outbound-5xx-v4.json"
    attestation = GoldenAttestation.from_repository(
        repository,
        profile="managed-outbound-5xx",
        normalizers=("outbound:queue-id",),
    )
    store = GoldenStore(path.parent, attestation, record=record_java)
    store.assert_observation(path.name, observed)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(360)
def test_managed_java_outbound_5xx_wire_and_statuses(record_java_golden: bool) -> None:
    repository = _repository()
    observed = _run_probe(repository, target="java")
    _assert_contract(observed)
    _assert_golden(repository, observed, record_java=record_java_golden)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(360)
def test_rust_candidate_outbound_5xx_matches_frozen_java_golden() -> None:
    repository = _repository()
    observed = _run_probe(repository, target="candidate")
    _assert_contract(observed)
    _assert_golden(repository, observed, record_java=False)
