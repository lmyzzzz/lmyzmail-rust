from __future__ import annotations

import gzip
import hashlib
import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest

from lmyzmail_blackbox.golden import GoldenAttestation, GoldenStore
from lmyzmail_blackbox.tlsrpt_https_probe import _decompress_gzip_bounded

_CASES = ("success", "redirect", "certificate_failure", "private_address", "timeout")
_DOMAINS = {label: f"{label.replace('_', '-')}.delivery.tlsrpt.fixture.test" for label in _CASES}
_COLLECTORS = {
    label: f"collector-{label.replace('_', '-')}.tlsrpt.fixture.test" for label in _CASES
}
_ENDPOINTS = {
    label: f"https://{_COLLECTORS[label]}/v1/reports/tls?case={label.replace('_', '-')}"
    for label in _CASES
}


def _repository() -> Path:
    return Path(__file__).resolve().parents[2]


def test_tlsrpt_gzip_decompression_is_bounded_before_allocation() -> None:
    payload = gzip.compress(b"x" * 1025, mtime=0)
    with pytest.raises(AssertionError, match="decompressed body exceeded"):
        _decompress_gzip_bounded(payload, max_bytes=1024)


def _run_probe(repository: Path, *, target: str) -> dict[str, Any]:
    result = subprocess.run(  # noqa: S603,S607
        ["/bin/bash", str(repository / "blackbox/bin/run-tlsrpt-https-probe.sh")],
        cwd=repository,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "LMYZMAIL_BLACKBOX_PYTHON": sys.executable,
            "LMYZMAIL_TLSRPT_TARGET": target,
        },
        timeout=240,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            "TLSRPT HTTPS probe failed with "
            f"{result.returncode}:\nstdout={result.stdout}\nstderr={result.stderr}"
        )
    observed = json.loads(result.stdout)
    if not isinstance(observed, dict):
        raise AssertionError(f"TLSRPT HTTPS probe returned a non-object: {observed!r}")
    return observed


def _assert_dns_query(query: dict[str, Any], *, name: str, query_type: int) -> None:
    assert query == {"class": 1, "name": name, "type": query_type}


def _expected_result(label: str) -> dict[str, Any]:
    base: dict[str, Any] = {
        "method": "https",
        "success": label == "success",
        "target": _ENDPOINTS[label],
    }
    if label == "redirect":
        base["error"] = "HTTP 302"
    elif label == "certificate_failure":
        base["error"] = "Unable to connect to validated HTTP target"
    elif label == "private_address":
        base["error"] = (
            "SSRF protection: Host 'collector-private-address.tlsrpt.fixture.test' "
            "resolves to non-public address(es): 127.0.0.1"
        )
    elif label == "timeout":
        base["error"] = "HTTP request deadline exceeded"
    return base


def _assert_report(label: str, report: dict[str, Any]) -> None:
    domain = _DOMAINS[label]
    assert report == {
        "organization-name": "Blackbox Reports",
        "date-range": {
            "start-datetime": "2024-01-01T00:00:00Z",
            "end-datetime": "2024-01-01T23:59:59Z",
        },
        "contact-info": "reports@example.test",
        "report-id": "<report-id>",
        "policies": [
            {
                "policy": {
                    "policy-type": "sts",
                    "policy-string": [
                        "version: STSv1",
                        "mode: enforce",
                        f"mx: mx.{domain}",
                        "max_age: 604800",
                    ],
                    "policy-domain": domain,
                    "mx-host": [f"mx.{domain}"],
                },
                "summary": {
                    "total-successful-session-count": _CASES.index(label) + 1,
                    "total-failure-session-count": 0,
                },
            }
        ],
    }


def _assert_contract(observed: dict[str, Any], *, target: str) -> None:
    assert observed["target"] == target
    cases = cast(dict[str, dict[str, Any]], observed["cases"])
    assert set(cases) == set(_CASES)
    for label in _CASES:
        case = cases[label]
        response = cast(dict[str, Any], case["response"])
        assert response["status_code"] == 200
        body_wire = cast(str, response["body_wire"])
        assert response["headers"] == [
            ["content-type", "application/json; charset=UTF-8"],
            ["content-length", str(len(body_wire.encode("utf-8")))],
        ]
        assert response["body"] == {
            "domain": _DOMAINS[label],
            "date": "2024-01-01",
            "dmarc": {
                "results": [],
                "error": "No DMARC data for this domain/date",
            },
            "tls": {"results": [_expected_result(label)], "error": "none"},
        }
        assert case["source_row_unchanged"] is True

        queries = cast(list[dict[str, Any]], case["dns"])
        _assert_dns_query(
            queries[0], name=f"_smtp._tls.{_DOMAINS[label]}", query_type=16
        )
        if target == "java":
            assert len(queries) == 1
        else:
            assert len(queries) == 3
            _assert_dns_query(queries[1], name=_COLLECTORS[label], query_type=28)
            _assert_dns_query(queries[2], name=_COLLECTORS[label], query_type=1)

        https = cast(dict[str, Any], case["https"])
        requests = cast(list[dict[str, Any]], https["requests"])
        if label == "private_address":
            assert requests == []
            assert https["handshake_failures"] == 0
            continue
        if label == "certificate_failure":
            assert requests == []
            assert https["handshake_failures"] == 1
            continue
        assert https["handshake_failures"] == 0
        assert len(requests) == 1
        request = requests[0]
        assert request["connection"] == 1
        assert request["method"] == "POST"
        assert request["target"] == f"/v1/reports/tls?case={label.replace('_', '-')}"
        assert request["version"] == "HTTP/1.1"
        assert request["headers"] == [
            ["connection", "close"],
            ["content-length", "<uuid-derived-content-length>"],
            ["content-type", "application/tlsrpt+gzip"],
            ["host", _COLLECTORS[label]],
            [
                "user-agent",
                "Botmail-TLSRPT/1.0" if target == "java" else "lmyzmail-TLSRPT/1.0",
            ],
        ]
        assert request["host"] == _COLLECTORS[label]
        assert request["connection_header"] == "close"
        assert request["content_type"] == "application/tlsrpt+gzip"
        assert request["content_length_matches"] is True
        assert request["user_agent"] == (
            "Botmail-TLSRPT/1.0" if target == "java" else "lmyzmail-TLSRPT/1.0"
        )
        assert request["sni"] == _COLLECTORS[label]
        assert request["tls_protocol"] == "TLSv1.3"
        assert request["tls_cipher"] == "TLS_AES_256_GCM_SHA384"
        assert request["tls_secret_bits"] == 256
        assert request["gzip_header_hex"].startswith("1f8b08")
        assert request["compressed_bytes_bounded"] is True
        assert isinstance(request["decompressed_bytes"], int)
        assert 0 < request["decompressed_bytes"] <= 4 * 1024 * 1024
        normalized_text = request["normalized_decompressed_text"]
        assert isinstance(normalized_text, str)
        assert normalized_text.count("<report-id>") == 1
        assert request["normalized_decompressed_sha256"] == hashlib.sha256(
            normalized_text.encode("utf-8")
        ).hexdigest()
        _assert_report(label, request["report"])


def _golden(repository: Path, observed: dict[str, Any], *, record_java: bool) -> None:
    path = repository / "blackbox/golden/java/managed-tlsrpt-https-v12.json"
    attestation = GoldenAttestation.from_repository(
        repository,
        profile="managed-tlsrpt-https",
        normalizers=(
            "report-id:uuid-v4",
            "json-object-order:reports-contract",
            "http:header-order",
            "tlsrpt:uuid-derived-content-length",
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
                repository / "blackbox/golden/java/managed-tlsrpt-https-v11.json"
            ).read_text(encoding="utf-8")
        ),
    )
    expected = cast(dict[str, Any], deepcopy(envelope["observation"]))
    actual = deepcopy(observed)
    expected["target"] = "candidate"
    for label in _CASES:
        expected["cases"][label]["dns"] = actual["cases"][label]["dns"]
        for request in expected["cases"][label]["https"]["requests"]:
            request["user_agent"] = "lmyzmail-TLSRPT/1.0"
            request["headers"][-1][1] = "lmyzmail-TLSRPT/1.0"
    assert actual == expected


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(260)
def test_managed_java_tlsrpt_https(record_java_golden: bool) -> None:
    repository = _repository()
    observed = _run_probe(repository, target="java")
    _assert_contract(observed, target="java")
    _golden(repository, observed, record_java=record_java_golden)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(260)
def test_rust_candidate_tlsrpt_https() -> None:
    repository = _repository()
    observed = _run_probe(repository, target="candidate")
    _assert_contract(observed, target="candidate")
    _assert_candidate_matches(repository, observed)
