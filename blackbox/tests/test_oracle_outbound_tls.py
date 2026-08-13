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
            "LMYZMAIL_OUTBOUND_ORACLE_MODE": "TLS",
            "LMYZMAIL_OUTBOUND_TARGET": target,
        },
        timeout=180,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            "outbound TLS probe failed with "
            f"{result.returncode}:\nstdout={result.stdout}\nstderr={result.stderr}"
        )
    observed = json.loads(result.stdout)
    if not isinstance(observed, dict):
        raise AssertionError(f"outbound TLS probe returned a non-object: {observed!r}")
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


def _assert_sent(case: dict[str, Any]) -> None:
    assert case["terminal"] == {"last_error": None, "retry_count": 0, "status": "SENT"}
    assert len(case["smtp"]["attempts"]) == 1
    assert case["smtp"]["attempts"][0]["accepted"] is True


def _commands(case: dict[str, Any]) -> list[dict[str, Any]]:
    return cast(list[dict[str, Any]], case["smtp"]["commands"])


def _assert_contract(observed: dict[str, Any], *, target: str) -> None:
    assert observed["target"] == target
    cases = observed["cases"]
    assert set(cases) == {
        "opportunistic_trusted",
        "opportunistic_untrusted_fallback",
        "opportunistic_rejected_fallback",
        "opportunistic_hostname_mismatch",
        "mta_sts_enforce_trusted",
        "mta_sts_enforce_missing_starttls",
        "mta_sts_enforce_untrusted",
        "mta_sts_enforce_rejected_starttls",
        "mta_sts_enforce_handshake_timeout",
    }

    for label in ("opportunistic_trusted", "mta_sts_enforce_trusted"):
        case = cases[label]
        _assert_response(case)
        _assert_sent(case)
        assert [entry["value"] for entry in _commands(case)[:3]] == [
            "EHLO blackbox.example",
            "STARTTLS",
            "EHLO blackbox.example",
        ]
        assert case["smtp"]["connections"] == [1]
        assert case["smtp"]["tls_established_connections"] == [1]

    for label in ("opportunistic_untrusted_fallback", "opportunistic_rejected_fallback"):
        case = cases[label]
        _assert_sent(case)
        assert case["smtp"]["connections"] == [1, 2]
        assert [entry["connection"] for entry in _commands(case)[:3]] == [1, 1, 2]
        assert [entry["value"] for entry in _commands(case)[:3]] == [
            "EHLO blackbox.example",
            "STARTTLS",
            "EHLO blackbox.example",
        ]
        assert case["smtp"]["tls_established_connections"] == []
        assert case["smtp"]["attempts"][0]["connection_id"] == 2

    mismatch = cases["opportunistic_hostname_mismatch"]
    _assert_sent(mismatch)
    if target == "java":
        assert mismatch["outcome"] == "tls-accepted-without-hostname-verification"
        assert mismatch["smtp"]["connections"] == [1]
        assert mismatch["smtp"]["tls_established_connections"] == [1]
    else:
        assert mismatch["outcome"] == "hostname-verified-then-plaintext-fallback"
        assert mismatch["smtp"]["connections"] == [1, 2]
        assert mismatch["smtp"]["tls_established_connections"] == []

    missing = cases["mta_sts_enforce_missing_starttls"]
    _assert_response(missing)
    assert missing["terminal"] == {
        "last_error": (
            "All domains failed: {outbound.fixture.test=MTA-STS policy requires TLS, "
            "but server does not support STARTTLS}"
        ),
        "retry_count": 0,
        "status": "FAILED",
    }
    assert [entry["value"] for entry in _commands(missing)] == ["EHLO blackbox.example"]
    assert missing["smtp"]["attempts"] == []
    assert missing["smtp"]["tls_established_connections"] == []

    for label in ("mta_sts_enforce_untrusted", "mta_sts_enforce_rejected_starttls"):
        case = cases[label]
        _assert_response(case)
        assert case["terminal"]["status"] == "FAILED"
        assert case["terminal"]["retry_count"] == 0
        assert case["terminal"]["last_error"].startswith(
            "All domains failed: {outbound.fixture.test=MTA-STS policy requires TLS"
        )
        assert case["smtp"]["connections"] == [1]
        assert [entry["value"] for entry in _commands(case)] == [
            "EHLO blackbox.example",
            "STARTTLS",
        ]
        assert case["smtp"]["attempts"] == []
        assert case["smtp"]["tls_established_connections"] == []

    timeout = cases["mta_sts_enforce_handshake_timeout"]
    _assert_response(timeout)
    assert timeout["retry"]["retry_count"] == 1
    assert timeout["retry"]["scheduled_delay_seconds"] == 30
    assert timeout["retry"]["redis"]["task"]["status"] == "PENDING"
    assert timeout["retry"]["redis"]["task"]["retry_count"] == 1
    assert "timeout" in timeout["retry"]["redis"]["task"]["last_error"].lower()
    assert timeout["retry"]["redis"]["retry_zset_member"] is True
    assert timeout["smtp"]["connections"] == [1]
    assert [entry["value"] for entry in _commands(timeout)] == [
        "EHLO blackbox.example",
        "STARTTLS",
    ]
    assert timeout["smtp"]["attempts"] == []
    assert timeout["smtp"]["tls_established_connections"] == []


def _golden(repository: Path, observed: dict[str, Any], *, record_java: bool) -> None:
    path = repository / "blackbox/golden/java/managed-outbound-tls-v9.json"
    attestation = GoldenAttestation.from_repository(
        repository,
        profile="managed-outbound-tls",
        normalizers=("outbound:queue-id", "outbound:message-metadata"),
    )
    GoldenStore(path.parent, attestation, record=record_java).assert_observation(
        path.name, observed
    )


def _assert_approved_hostname_difference(
    repository: Path,
    observed: dict[str, Any],
) -> None:
    envelope = cast(
        dict[str, Any],
        json.loads(
            (repository / "blackbox/golden/java/managed-outbound-tls-v9.json").read_text(
                encoding="utf-8"
            )
        ),
    )
    manifest = json.loads(
        (repository / "blackbox/manifests/behavior-differences.json").read_text(encoding="utf-8")
    )
    difference_ids = {value["id"] for value in manifest["differences"]}
    assert {
        "outbound-retry-postgres-checkpoint",
        "outbound-starttls-hostname-verification",
    } <= difference_ids

    expected = cast(dict[str, Any], deepcopy(envelope["observation"]))
    actual = deepcopy(observed)
    expected["target"] = "candidate"
    expected_mismatch = expected["cases"].pop("opportunistic_hostname_mismatch")
    actual_mismatch = actual["cases"].pop("opportunistic_hostname_mismatch")

    expected_retry = expected["cases"]["mta_sts_enforce_handshake_timeout"]["retry"]
    actual_retry = actual["cases"]["mta_sts_enforce_handshake_timeout"]["retry"]
    assert expected_retry.pop("db") == {
        "deadline_matches_retry": None,
        "present": False,
    }
    task = actual_retry["redis"]["task"]
    assert actual_retry.pop("db") == {
        "deadline_matches_retry": True,
        "last_error": task["last_error"],
        "max_retries": 5,
        "present": True,
        "retry_count": actual_retry["retry_count"],
        "status": "PENDING",
    }
    assert actual == expected

    assert expected_mismatch["outcome"] == "tls-accepted-without-hostname-verification"
    assert expected_mismatch["smtp"]["connections"] == [1]
    assert expected_mismatch["smtp"]["tls_established_connections"] == [1]
    assert actual_mismatch["outcome"] == "hostname-verified-then-plaintext-fallback"
    assert actual_mismatch["smtp"]["connections"] == [1, 2]
    assert actual_mismatch["smtp"]["tls_established_connections"] == []
    assert actual_mismatch["terminal"] == expected_mismatch["terminal"]
    assert actual_mismatch["smtp"]["attempts"][0].pop("connection_id") == 2
    assert expected_mismatch["smtp"]["attempts"][0].pop("connection_id") == 1
    assert actual_mismatch["smtp"]["attempts"] == expected_mismatch["smtp"]["attempts"]


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(190)
def test_managed_java_outbound_starttls_and_mta_sts(record_java_golden: bool) -> None:
    repository = _repository()
    observed = _run_probe(repository, target="java")
    _assert_contract(observed, target="java")
    _golden(repository, observed, record_java=record_java_golden)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(190)
def test_rust_candidate_outbound_starttls_and_mta_sts() -> None:
    repository = _repository()
    observed = _run_probe(repository, target="candidate")
    _assert_contract(observed, target="candidate")
    _assert_approved_hostname_difference(repository, observed)
