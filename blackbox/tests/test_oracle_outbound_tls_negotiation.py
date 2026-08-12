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

_PROTOCOL_VERSION_ERROR = (
    "All domains failed: {outbound.fixture.test=MTA-STS policy requires TLS, "
    "but TLS failed: MTA-STS requires TLS: MTA-STS enforced TLS handshake failed: "
    "TLS handshake failed: error:1000042e:SSL routines:OPENSSL_internal:"
    "TLSV1_ALERT_PROTOCOL_VERSION}"
)
_HANDSHAKE_FAILURE_ERROR = (
    "All domains failed: {outbound.fixture.test=MTA-STS policy requires TLS, "
    "but TLS failed: MTA-STS requires TLS: MTA-STS enforced TLS handshake failed: "
    "TLS handshake failed: error:10000410:SSL routines:OPENSSL_internal:"
    "SSLV3_ALERT_HANDSHAKE_FAILURE}"
)


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
            "LMYZMAIL_OUTBOUND_ORACLE_MODE": "TLS_NEGOTIATION",
            "LMYZMAIL_OUTBOUND_TARGET": target,
        },
        timeout=180,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            "outbound TLS negotiation probe failed with "
            f"{result.returncode}:\nstdout={result.stdout}\nstderr={result.stderr}"
        )
    observed = json.loads(result.stdout)
    if not isinstance(observed, dict):
        raise AssertionError(
            f"outbound TLS negotiation probe returned a non-object: {observed!r}"
        )
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


def _assert_contract(observed: dict[str, Any], *, target: str) -> None:
    assert observed["target"] == target
    cases = cast(dict[str, dict[str, Any]], observed["cases"])
    assert set(cases) == {
        "opportunistic_tls11_only",
        "opportunistic_no_shared_cipher",
        "opportunistic_legacy_rsa_cbc",
        "mta_sts_enforce_tls13_only",
        "mta_sts_enforce_tls12_strong",
        "mta_sts_enforce_tls11_only",
        "mta_sts_enforce_no_shared_cipher",
        "mta_sts_enforce_legacy_rsa_cbc",
    }
    for case in cases.values():
        _assert_response(case)

    successful = {
        "mta_sts_enforce_tls13_only": {
            "connection": 1,
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "secret_bits": 256,
        },
        "mta_sts_enforce_tls12_strong": {
            "connection": 1,
            "protocol": "TLSv1.2",
            "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
            "secret_bits": 128,
        },
    }
    for label, session in successful.items():
        case = cases[label]
        _assert_sent(case)
        assert case["tls_sessions"] == [session]
        assert case["smtp"]["connections"] == [1]
        assert case["smtp"]["tls_established_connections"] == [1]
        assert [entry["value"] for entry in case["smtp"]["commands"][:3]] == [
            "EHLO blackbox.example",
            "STARTTLS",
            "EHLO blackbox.example",
        ]

    for label in ("opportunistic_tls11_only", "opportunistic_no_shared_cipher"):
        case = cases[label]
        _assert_sent(case)
        assert case["tls_sessions"] == []
        assert case["smtp"]["connections"] == [1, 2]
        assert [entry["connection"] for entry in case["smtp"]["commands"][:3]] == [1, 1, 2]
        assert case["smtp"]["attempts"][0]["connection_id"] == 2

    for label, error in (
        ("mta_sts_enforce_tls11_only", _PROTOCOL_VERSION_ERROR),
        ("mta_sts_enforce_no_shared_cipher", _HANDSHAKE_FAILURE_ERROR),
    ):
        case = cases[label]
        assert case["terminal"] == {
            "last_error": error,
            "retry_count": 0,
            "status": "FAILED",
        }
        assert case["tls_sessions"] == []
        assert case["smtp"]["connections"] == [1]
        assert [entry["value"] for entry in case["smtp"]["commands"]] == [
            "EHLO blackbox.example",
            "STARTTLS",
        ]
        assert case["smtp"]["attempts"] == []

    opportunistic_legacy = cases["opportunistic_legacy_rsa_cbc"]
    _assert_sent(opportunistic_legacy)
    enforce_legacy = cases["mta_sts_enforce_legacy_rsa_cbc"]
    if target == "java":
        expected_session = {
            "connection": 1,
            "protocol": "TLSv1.2",
            "cipher": "AES128-SHA",
            "secret_bits": 128,
        }
        assert opportunistic_legacy["tls_sessions"] == [expected_session]
        assert enforce_legacy["tls_sessions"] == [expected_session]
        _assert_sent(enforce_legacy)
    else:
        assert opportunistic_legacy["tls_sessions"] == []
        assert opportunistic_legacy["smtp"]["connections"] == [1, 2]
        assert opportunistic_legacy["smtp"]["attempts"][0]["connection_id"] == 2
        assert enforce_legacy["terminal"] == {
            "last_error": _HANDSHAKE_FAILURE_ERROR,
            "retry_count": 0,
            "status": "FAILED",
        }
        assert enforce_legacy["tls_sessions"] == []
        assert enforce_legacy["smtp"]["attempts"] == []


def _golden(repository: Path, observed: dict[str, Any], *, record_java: bool) -> None:
    path = repository / "blackbox/golden/java/managed-outbound-tls-negotiation-v1.json"
    attestation = GoldenAttestation.from_repository(
        repository,
        profile="managed-outbound-tls-negotiation",
        normalizers=("outbound:queue-id", "outbound:message-metadata"),
    )
    GoldenStore(path.parent, attestation, record=record_java).assert_observation(
        path.name, observed
    )


def _assert_approved_legacy_cipher_difference(
    repository: Path,
    observed: dict[str, Any],
) -> None:
    envelope = cast(
        dict[str, Any],
        json.loads(
            (
                repository
                / "blackbox/golden/java/managed-outbound-tls-negotiation-v1.json"
            ).read_text(encoding="utf-8")
        ),
    )
    manifest = json.loads(
        (repository / "blackbox/manifests/behavior-differences.json").read_text(
            encoding="utf-8"
        )
    )
    assert "outbound-starttls-static-rsa-cbc-rejection" in {
        value["id"] for value in manifest["differences"]
    }

    expected = cast(dict[str, Any], deepcopy(envelope["observation"]))
    actual = deepcopy(observed)
    expected["target"] = "candidate"
    expected_opportunistic = expected["cases"].pop("opportunistic_legacy_rsa_cbc")
    actual_opportunistic = actual["cases"].pop("opportunistic_legacy_rsa_cbc")
    expected_enforce = expected["cases"].pop("mta_sts_enforce_legacy_rsa_cbc")
    actual_enforce = actual["cases"].pop("mta_sts_enforce_legacy_rsa_cbc")
    assert actual == expected

    assert expected_opportunistic["tls_sessions"] == [
        {
            "connection": 1,
            "protocol": "TLSv1.2",
            "cipher": "AES128-SHA",
            "secret_bits": 128,
        }
    ]
    assert actual_opportunistic["tls_sessions"] == []
    expected_opportunistic["smtp"]["connections"] = [1, 2]
    expected_opportunistic["smtp"]["tls_established_connections"] = []
    expected_opportunistic["smtp"]["fixture_terminal_events"] = [
        {"connection": 1, "kind": "peer-disconnected"}
    ]
    for command in expected_opportunistic["smtp"]["commands"][2:]:
        command["connection"] = 2
    expected_opportunistic["smtp"]["attempts"][0]["connection_id"] = 2
    expected_opportunistic["tls_sessions"] = []
    assert actual_opportunistic == expected_opportunistic

    expected_enforce["terminal"] = {
        "last_error": _HANDSHAKE_FAILURE_ERROR,
        "retry_count": 0,
        "status": "FAILED",
    }
    expected_enforce["smtp"]["commands"] = expected_enforce["smtp"]["commands"][:2]
    expected_enforce["smtp"]["tls_established_connections"] = []
    expected_enforce["smtp"]["attempts"] = []
    expected_enforce["smtp"]["fixture_terminal_events"] = [
        {"connection": 1, "kind": "peer-disconnected"}
    ]
    expected_enforce["tls_sessions"] = []
    assert actual_enforce == expected_enforce


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(190)
def test_managed_java_outbound_tls_negotiation(record_java_golden: bool) -> None:
    repository = _repository()
    observed = _run_probe(repository, target="java")
    _assert_contract(observed, target="java")
    _golden(repository, observed, record_java=record_java_golden)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(190)
def test_rust_candidate_outbound_tls_negotiation() -> None:
    repository = _repository()
    observed = _run_probe(repository, target="candidate")
    _assert_contract(observed, target="candidate")
    _assert_approved_legacy_cipher_difference(repository, observed)
