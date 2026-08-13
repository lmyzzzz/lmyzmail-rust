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

_DOMAINS = {
    "no_txt": "no-txt.sts.fixture.test",
    "malformed_txt": "malformed-txt.sts.fixture.test",
    "multiple_txt": "multiple-txt.sts.fixture.test",
    "a_failure": "a-failure.sts.fixture.test",
    "certificate_failure": "certificate-failure.sts.fixture.test",
    "status_404": "status-404.sts.fixture.test",
    "status_500": "status-500.sts.fixture.test",
    "redirect": "redirect.sts.fixture.test",
    "missing_content_type": "missing-content-type.sts.fixture.test",
    "wrong_content_type": "wrong-content-type.sts.fixture.test",
    "invalid_utf8": "invalid-utf8.sts.fixture.test",
    "malformed_policy": "malformed-policy.sts.fixture.test",
    "oversized_policy": "oversized-policy.sts.fixture.test",
    "timeout": "timeout.sts.fixture.test",
    "testing": "testing.sts.fixture.test",
    "none": "none.sts.fixture.test",
    "enforce": "enforce.sts.fixture.test",
    "zero": "zero.sts.fixture.test",
    "positive": "positive.sts.fixture.test",
}
_RESTART_CASES = {"no_txt_restart", "positive_restart"}
_NO_HTTPS = {"no_txt", "malformed_txt", "multiple_txt", "a_failure"}
_NEGATIVE = {
    *_NO_HTTPS,
    "certificate_failure",
    "status_404",
    "status_500",
    "redirect",
    "missing_content_type",
    "wrong_content_type",
    "invalid_utf8",
    "malformed_policy",
    "oversized_policy",
    "timeout",
    "none",
}
_VALID = {"testing", "enforce", "zero", "positive"}
_HTTPS_CASES = set(_DOMAINS) - _NO_HTTPS


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
            "LMYZMAIL_OUTBOUND_ORACLE_MODE": "MTA_STS_DISCOVERY",
            "LMYZMAIL_OUTBOUND_TARGET": target,
        },
        timeout=360,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            "MTA-STS discovery probe failed with "
            f"{result.returncode}:\nstdout={result.stdout}\nstderr={result.stderr}"
        )
    observed = json.loads(result.stdout)
    if not isinstance(observed, dict):
        raise AssertionError(f"MTA-STS discovery probe returned a non-object: {observed!r}")
    return observed


def _assert_response(value: dict[str, Any]) -> None:
    assert value == {
        "error": None,
        "message_id_present": True,
        "queue_id_present": True,
        "queued": True,
        "status": "PENDING",
        "status_code": 202,
    }


def _assert_dns_query(query: dict[str, Any], *, name: str, query_type: int) -> None:
    assert query == {"class": 1, "name": name, "type": query_type}


def _source_case(label: str) -> str:
    if label == "no_txt_restart":
        return "no_txt"
    if label == "positive_restart":
        return "positive"
    return label


def _assert_java_dns(label: str, queries: list[dict[str, Any]]) -> None:
    source = _source_case(label)
    if label == "positive_restart":
        assert queries == []
        return
    domain = _DOMAINS[source]
    expected_count = 2 if source in {"no_txt", "zero"} else 1
    assert len(queries) == expected_count
    for query in queries:
        _assert_dns_query(query, name=f"_mta-sts.{domain}", query_type=16)


def _assert_candidate_dns(label: str, queries: list[dict[str, Any]]) -> None:
    source = _source_case(label)
    domain = _DOMAINS[source]
    expected: list[tuple[str, int]] = []
    delivery_count = 2 if source in {"zero", "positive"} and label == source else 1
    for delivery_index in range(delivery_count):
        discovers_policy = label != "positive_restart" and (
            source != "positive" or delivery_index == 0
        )
        if discovers_policy:
            expected.append((f"_mta-sts.{domain}", 16))
            if source not in {"no_txt", "malformed_txt", "multiple_txt"}:
                expected.extend(
                    ((f"mta-sts.{domain}", 1), (f"mta-sts.{domain}", 28))
                )
        expected.extend(("outbound.fixture.test", query_type) for query_type in (1, 28))
    assert len(queries) == len(expected)
    for query, (name, query_type) in zip(queries, expected, strict=True):
        _assert_dns_query(query, name=name, query_type=query_type)


def _assert_https(label: str, case: dict[str, Any], *, target: str) -> None:
    https = cast(dict[str, Any], case["https"])
    requests = cast(list[dict[str, Any]], https["requests"])
    if label in _NO_HTTPS or label in _RESTART_CASES:
        assert requests == []
        assert https["handshake_failures"] == 0
        assert case["https_scenario"] is None
        return
    scenario = cast(dict[str, Any], case["https_scenario"])
    assert set(scenario) == {
        "body_bytes",
        "body_sha256",
        "content_type",
        "response_delay_seconds",
        "status",
    }
    assert len(scenario["body_sha256"]) == 64
    if label == "certificate_failure":
        assert requests == []
        assert https["handshake_failures"] == 1
        return
    expected_count = 2 if label == "zero" else 1
    assert https["handshake_failures"] == 0
    assert len(requests) == expected_count
    domain = _DOMAINS[label]
    expected_user_agent = (
        "Botmail-MTA-STS/1.0" if target == "java" else "lmyzmail-MTA-STS/1.0"
    )
    for index, request in enumerate(requests, start=1):
        assert request == {
            "connection": index,
            "host": f"mta-sts.{domain}",
            "method": "GET",
            "sni": f"mta-sts.{domain}",
            "target": "/.well-known/mta-sts.txt",
            "tls_cipher": "TLS_AES_256_GCM_SHA384",
            "tls_protocol": "TLSv1.3",
            "tls_secret_bits": 256,
            "user_agent": expected_user_agent,
            "version": "HTTP/1.1",
        }


def _assert_cache(label: str, value: dict[str, Any]) -> None:
    if label == "zero":
        assert value == {"present": False, "ttl_seconds": None, "value": None}
        return
    source = _source_case(label)
    policy = cast(dict[str, Any], value["value"])
    if source in _NEGATIVE:
        assert value["present"] is True
        assert value["ttl_seconds"] == 300
        if source == "none":
            assert policy == {
                "fetched_at_present": True,
                "max_age": "600",
                "mode": "NONE",
                "mx": "outbound.fixture.test",
                "policy_id": "None1",
                "version": "STSv1",
            }
        else:
            assert policy == {
                "fetched_at_present": True,
                "max_age": "0",
                "mode": "NONE",
                "mx": "",
                "policy_id": "",
                "version": "",
            }
        return
    assert source in _VALID
    assert value["present"] is True
    assert value["ttl_seconds"] == 600
    assert policy == {
        "fetched_at_present": True,
        "max_age": "600",
        "mode": "ENFORCE" if source == "enforce" else "TESTING",
        "mx": "outbound.fixture.test",
        "policy_id": f"{source.title()}1",
        "version": "STSv1",
    }


def _assert_contract(observed: dict[str, Any], *, target: str) -> None:
    assert observed["target"] == target
    cases = cast(dict[str, dict[str, Any]], observed["cases"])
    assert set(cases) == {*_DOMAINS, *_RESTART_CASES}
    for label, case in cases.items():
        expected_deliveries = 2 if label in {"zero", "positive"} else 1
        assert len(case["deliveries"]) == expected_deliveries
        for delivery in case["deliveries"]:
            _assert_response(delivery["response"])
            if label == "enforce":
                assert delivery["terminal"] == {
                    "last_error": (
                        "All domains failed: {enforce.sts.fixture.test=MTA-STS policy "
                        "requires TLS, but server does not support STARTTLS}"
                    ),
                    "retry_count": 0,
                    "status": "FAILED",
                }
            else:
                assert delivery["terminal"] == {
                    "last_error": None,
                    "retry_count": 0,
                    "status": "SENT",
                }
        assert case["smtp_attempt_count"] == (0 if label == "enforce" else expected_deliveries)
        if target == "java":
            _assert_java_dns(label, case["dns"])
        else:
            _assert_candidate_dns(label, case["dns"])
        _assert_https(label, case, target=target)
        _assert_cache(label, case["redis"])


def _golden(repository: Path, observed: dict[str, Any], *, record_java: bool) -> None:
    path = repository / "blackbox/golden/java/managed-mta-sts-discovery-v7.json"
    attestation = GoldenAttestation.from_repository(
        repository,
        profile="managed-mta-sts-discovery",
        normalizers=(
            "outbound:queue-id",
            "outbound:message-metadata",
            "mta-sts:fetched-at-presence",
            "mta-sts:ttl-observation-window",
        ),
    )
    GoldenStore(path.parent, attestation, record=record_java).assert_observation(
        path.name, observed
    )


def _assert_candidate_matches(repository: Path, observed: dict[str, Any]) -> None:
    envelope = cast(
        dict[str, Any],
        json.loads(
            (
                repository / "blackbox/golden/java/managed-mta-sts-discovery-v7.json"
            ).read_text(encoding="utf-8")
        ),
    )
    expected = cast(dict[str, Any], deepcopy(envelope["observation"]))
    expected["target"] = "candidate"
    actual = deepcopy(observed)
    for label in expected["cases"]:
        expected["cases"][label]["dns"] = actual["cases"][label]["dns"]
        for request in expected["cases"][label]["https"]["requests"]:
            request["user_agent"] = "lmyzmail-MTA-STS/1.0"
    assert actual == expected


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(380)
def test_managed_java_mta_sts_discovery(record_java_golden: bool) -> None:
    repository = _repository()
    observed = _run_probe(repository, target="java")
    _assert_contract(observed, target="java")
    _golden(repository, observed, record_java=record_java_golden)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(380)
def test_rust_candidate_mta_sts_discovery() -> None:
    repository = _repository()
    observed = _run_probe(repository, target="candidate")
    _assert_contract(observed, target="candidate")
    _assert_candidate_matches(repository, observed)
