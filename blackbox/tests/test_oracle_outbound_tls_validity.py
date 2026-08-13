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


def _run_probe(repository: Path, *, target: str) -> dict[str, Any]:
    result = subprocess.run(  # noqa: S603,S607
        ["/bin/bash", str(repository / "blackbox/bin/run-outbound-probe.sh")],
        cwd=repository,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "LMYZMAIL_BLACKBOX_PYTHON": sys.executable,
            "LMYZMAIL_OUTBOUND_ORACLE_MODE": "TLS_VALIDITY",
            "LMYZMAIL_OUTBOUND_TARGET": target,
        },
        timeout=150,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            "outbound TLS validity probe failed with "
            f"{result.returncode}:\nstdout={result.stdout}\nstderr={result.stderr}"
        )
    observed = json.loads(result.stdout)
    if not isinstance(observed, dict):
        raise AssertionError(f"outbound TLS validity probe returned a non-object: {observed!r}")
    return observed


def _assert_response(case: dict[str, Any]) -> None:
    assert case["response"] == {
        "error": None,
        "message_id_present": True,
        "queue_id_present": True,
        "queued": True,
        "status": "PENDING",
        "status_code": 202,
    }


def _assert_contract(observed: dict[str, Any], *, target: str) -> None:
    assert observed["target"] == target
    cases = observed["cases"]
    assert set(cases) == {
        "opportunistic_expired",
        "opportunistic_future",
        "mta_sts_enforce_expired",
        "mta_sts_enforce_future",
    }

    for label in ("opportunistic_expired", "opportunistic_future"):
        case = cases[label]
        _assert_response(case)
        assert case["terminal"] == {"last_error": None, "retry_count": 0, "status": "SENT"}
        assert case["smtp"]["connections"] == [1, 2]
        assert [entry["connection"] for entry in case["smtp"]["commands"][:3]] == [1, 1, 2]
        assert [entry["value"] for entry in case["smtp"]["commands"][:3]] == [
            "EHLO blackbox.example",
            "STARTTLS",
            "EHLO blackbox.example",
        ]
        assert case["smtp"]["tls_established_connections"] == []
        assert case["smtp"]["attempts"][0]["connection_id"] == 2

    for label in ("mta_sts_enforce_expired", "mta_sts_enforce_future"):
        case = cases[label]
        _assert_response(case)
        assert case["terminal"]["status"] == "FAILED"
        assert case["terminal"]["retry_count"] == 0
        assert case["terminal"]["last_error"] == (
            "All domains failed: {outbound.fixture.test=MTA-STS policy requires TLS, "
            "but TLS failed: MTA-STS requires TLS: MTA-STS enforced TLS handshake failed: "
            "TLS handshake failed: General OpenSslEngine problem}"
        )
        assert case["smtp"]["connections"] == [1]
        assert [entry["value"] for entry in case["smtp"]["commands"]] == [
            "EHLO blackbox.example",
            "STARTTLS",
        ]
        assert case["smtp"]["tls_established_connections"] == []
        assert case["smtp"]["attempts"] == []


def _golden(repository: Path, observed: dict[str, Any], *, record_java: bool) -> None:
    path = repository / "blackbox/golden/java/managed-outbound-tls-validity-v4.json"
    attestation = GoldenAttestation.from_repository(
        repository,
        profile="managed-outbound-tls-validity",
        normalizers=("outbound:queue-id", "outbound:message-metadata"),
    )
    GoldenStore(path.parent, attestation, record=record_java).assert_observation(
        path.name, observed
    )


def _assert_candidate_matches(repository: Path, observed: dict[str, Any]) -> None:
    envelope = cast(
        dict[str, Any],
        json.loads(
            (
                repository
                / "blackbox/golden/java/managed-outbound-tls-validity-v4.json"
            ).read_text(encoding="utf-8")
        ),
    )
    expected = cast(dict[str, Any], deepcopy(envelope["observation"]))
    expected["target"] = "candidate"
    assert observed == expected


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(160)
def test_managed_java_outbound_tls_certificate_validity(record_java_golden: bool) -> None:
    repository = _repository()
    observed = _run_probe(repository, target="java")
    _assert_contract(observed, target="java")
    _golden(repository, observed, record_java=record_java_golden)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(160)
def test_rust_candidate_outbound_tls_certificate_validity() -> None:
    repository = _repository()
    observed = _run_probe(repository, target="candidate")
    _assert_contract(observed, target="candidate")
    _assert_candidate_matches(repository, observed)
