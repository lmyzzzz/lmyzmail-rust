from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from lmyzmail_blackbox import smtp_dkim_contract
from lmyzmail_blackbox.differential import DifferentialRunner
from lmyzmail_blackbox.runtime import CandidateRuntime, JavaOracleRuntime
from lmyzmail_blackbox.scripted_dns import DnsQuery, ScriptedDnsServer
from lmyzmail_blackbox.smtp_dkim_contract import (
    SMTP_DKIM_IDENTITY_ORACLE_EVIDENCE_SCENARIOS,
    SMTP_DKIM_SCENARIOS,
    capture_external_dkim_identity_candidate_security,
    dkim_dns_answers,
)


@dataclass(slots=True)
class _DkimJavaRuntime(JavaOracleRuntime):
    _dns: ScriptedDnsServer | None = field(default=None, init=False, repr=False)

    @property
    def requires_qa_account(self) -> bool:
        return True

    def _start_application(self) -> None:
        self._dns = ScriptedDnsServer(dkim_dns_answers())
        self._dns.start()
        JavaOracleRuntime._start_application(self)

    def _application_arguments(self) -> list[str]:
        arguments = JavaOracleRuntime._application_arguments(self)
        if self._dns is None:
            raise RuntimeError("DKIM DNS fixture is not running")
        arguments.insert(
            arguments.index("-jar"),
            f"-Ddns.server={self._dns.host}:{self._dns.port}",
        )
        arguments.append("--botmail.contentfilter.enabled=false")
        return arguments

    def drain_dkim_dns_queries(self) -> tuple[DnsQuery, ...]:
        if self._dns is None:
            raise RuntimeError("DKIM DNS fixture is not running")
        return self._dns.drain_queries()

    def stop(self) -> None:
        try:
            JavaOracleRuntime.stop(self)
        finally:
            if self._dns is not None:
                self._dns.stop()
            self._dns = None


@dataclass(slots=True)
class _DkimCandidateRuntime(CandidateRuntime):
    _dns: ScriptedDnsServer | None = field(default=None, init=False, repr=False)

    @property
    def requires_qa_account(self) -> bool:
        return True

    def _start_application(self) -> None:
        self._dns = ScriptedDnsServer(dkim_dns_answers())
        self._dns.start()
        CandidateRuntime._start_application(self)

    def _candidate_configuration(self) -> Path:
        path = CandidateRuntime._candidate_configuration(self)
        value = json.loads(path.read_text(encoding="utf-8"))
        if self._dns is None:
            raise RuntimeError("DKIM DNS fixture is not running")
        value["features"]["smtp_spf_dns_server"] = f"{self._dns.host}:{self._dns.port}"
        value["content_filter"] = {"enabled": False}
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def drain_dkim_dns_queries(self) -> tuple[DnsQuery, ...]:
        if self._dns is None:
            raise RuntimeError("DKIM DNS fixture is not running")
        return self._dns.drain_queries()

    def stop(self) -> None:
        try:
            CandidateRuntime.stop(self)
        finally:
            if self._dns is not None:
                self._dns.stop()
            self._dns = None


def _runner(repository: Path, *, record_java: bool = False) -> DifferentialRunner:
    return DifferentialRunner(
        repository,
        repository / "blackbox/golden/java/managed-smtp-dkim-v8",
        "managed-smtp-dkim",
        record_java=record_java,
    )


def _identity_evidence_runner(
    repository: Path, *, record_java: bool = False
) -> DifferentialRunner:
    return DifferentialRunner(
        repository,
        repository / "blackbox/golden/java/managed-smtp-dkim-identity-oracle-evidence-v4",
        "managed-smtp-dkim-identity-oracle-evidence",
        record_java=record_java,
    )


def _candidate(repository: Path) -> CandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        return cast(_DkimCandidateRuntime, _DkimCandidateRuntime.from_environment())
    return _DkimCandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        )
    )


def _relaxed_header(name: str, value: str) -> bytes:
    normalized = re.sub(r"[ \t]+", " ", value).strip()
    return f"{name.lower()}:{normalized}\r\n".encode("ascii")


def _verify_fixed_signature(message: bytes, valid_index: int, public_key_record: str) -> None:
    head, body = message.split(b"\r\n\r\n", 1)
    headers = []
    for line in head.decode("ascii").split("\r\n"):
        name, value = line.split(":", 1)
        headers.append((name, value))
    signature_header = [
        header for header in headers if header[0].lower() == "dkim-signature"
    ][valid_index]
    tags = {
        name.strip(): value.strip()
        for item in signature_header[1].split(";")
        if "=" in item
        for name, value in (item.split("=", 1),)
    }
    canonical_body = body.rstrip(b"\r\n") + b"\r\n"
    body_hash = base64.b64encode(hashlib.sha256(canonical_body).digest()).decode("ascii")
    assert body_hash == tags["bh"]

    signed = bytearray()
    for wanted in tags["h"].split(":"):
        selected = next(header for header in reversed(headers) if header[0].lower() == wanted)
        signed.extend(_relaxed_header(*selected))
    unsigned_value = re.sub(r"(?i)(\bb\s*=\s*)[^;]*$", r"\1", signature_header[1])
    signed.extend(_relaxed_header(signature_header[0], unsigned_value)[:-2])

    public_der = base64.b64decode(public_key_record.split("p=", 1)[1])
    public_key = cast(RSAPublicKey, serialization.load_der_public_key(public_der))
    public_key.verify(
        base64.b64decode(tags["b"]),
        bytes(signed),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def test_fixed_multiple_signature_fixtures_verify() -> None:
    _verify_fixed_signature(
        smtp_dkim_contract._VALID_FIRST_MISSING_SECOND,
        0,
        smtp_dkim_contract._MULTI_PUBLIC_KEY,
    )
    _verify_fixed_signature(
        smtp_dkim_contract._MISSING_FIRST_VALID_SECOND,
        1,
        smtp_dkim_contract._MULTI_PUBLIC_KEY,
    )


def test_fixed_identity_signature_fixtures_verify() -> None:
    cases = (
        *smtp_dkim_contract._IDENTITY_COMPAT_CASES,
        *smtp_dkim_contract._IDENTITY_ORACLE_EVIDENCE_CASES,
    )
    for case in cases:
        _verify_fixed_signature(case.message, 0, smtp_dkim_contract._IDENTITY_PUBLIC_KEY)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(360)
def test_managed_java_smtp_dkim_golden(record_java_golden: bool) -> None:
    paths = JavaOracleRuntime().paths
    differential = _runner(paths.repository, record_java=record_java_golden)
    identity_evidence = _identity_evidence_runner(
        paths.repository, record_java=record_java_golden
    )
    with _DkimJavaRuntime(paths=paths) as oracle:
        if record_java_golden:
            differential.record_from_java(SMTP_DKIM_SCENARIOS, oracle)
            identity_evidence.record_from_java(
                SMTP_DKIM_IDENTITY_ORACLE_EVIDENCE_SCENARIOS, oracle
            )
        else:
            differential.verify_java(SMTP_DKIM_SCENARIOS, oracle)
            identity_evidence.verify_java(
                SMTP_DKIM_IDENTITY_ORACLE_EVIDENCE_SCENARIOS, oracle
            )


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(360)
def test_rust_candidate_smtp_dkim_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    differential = _runner(repository)
    with _candidate(repository) as candidate:
        differential.verify_candidate(SMTP_DKIM_SCENARIOS, candidate)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(360)
def test_rust_candidate_rejects_invalid_dkim_identities() -> None:
    repository = Path(__file__).resolve().parents[2]
    manifest = json.loads(
        (repository / "blackbox/manifests/behavior-differences.json").read_text(
            encoding="utf-8"
        )
    )
    difference = next(
        entry
        for entry in manifest["differences"]
        if entry["id"] == "smtp-dkim-auid-domain-validation"
    )
    assert difference["candidate_requirement"].startswith("Reject an explicit DKIM AUID")

    with _candidate(repository) as candidate:
        observed = capture_external_dkim_identity_candidate_security(candidate)
    cases = cast(list[dict[str, Any]], observed["cases"])
    assert {case["name"] for case in cases} == {
        "identity-unrelated",
        "identity-strict-subdomain",
        "identity-strict-prefix-confusion",
        "identity-missing-at",
    }
    for case in cases:
        assert case["expected_dkim_result"] == "fail"
        assert case["expected_folder"] == "spam"
        assert case["dkim_txt_query_count"] == 1
        delivery = case["delivery"]
        assert delivery["storage"]["postgres"]["folder"] == "spam"
        raw = base64.b64decode(delivery["storage"]["maildir"]["raw"]["base64"])
        assert b"dkim=fail (Signature verification failed for " in raw
        assert b"AUID does not match domain name)" in raw
        assert b"X-Spam-Status: Yes\r\n" in raw
        assert b"X-Spam-Score: 3.0\r\n" in raw
