from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


def _repository() -> Path:
    return Path(__file__).resolve().parents[2]


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(360)
def test_managed_java_outbound_5xx_wire_and_statuses() -> None:
    repository = _repository()
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
        },
        timeout=350,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            "outbound 5xx probe failed with "
            f"{result.returncode}:\nstdout={result.stdout}\nstderr={result.stderr}"
        )

    observed = json.loads(result.stdout)
    assert observed["codes"] == [500, 501, 549, 550, 554]
    assert observed["case_count"] == 10
    for case in observed["cases"]:
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
