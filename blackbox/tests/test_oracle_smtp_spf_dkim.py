from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from lmyzmail_blackbox.differential import DifferentialRunner
from lmyzmail_blackbox.runtime import CandidateRuntime, JavaOracleRuntime
from lmyzmail_blackbox.scripted_dns import DnsQuery, ScriptedDnsServer
from lmyzmail_blackbox.smtp_spf_dkim_contract import (
    _CASES,
    _COMBINED_PUBLIC_KEY,
    SMTP_SPF_DKIM_SCENARIOS,
    authentication_dns_answers,
    combined_message,
)


@dataclass(slots=True)
class _SpfDkimJavaRuntime(JavaOracleRuntime):
    _dns: ScriptedDnsServer | None = field(default=None, init=False, repr=False)

    @property
    def requires_qa_account(self) -> bool:
        return True

    def _start_application(self) -> None:
        self._dns = ScriptedDnsServer(authentication_dns_answers())
        self._dns.start()
        JavaOracleRuntime._start_application(self)

    def _application_arguments(self) -> list[str]:
        arguments = JavaOracleRuntime._application_arguments(self)
        if self._dns is None:
            raise RuntimeError("SPF/DKIM DNS fixture is not running")
        arguments.insert(
            arguments.index("-jar"),
            f"-Ddns.server={self._dns.host}:{self._dns.port}",
        )
        arguments.append("--botmail.contentfilter.enabled=false")
        return arguments

    def drain_authentication_dns_queries(self) -> tuple[DnsQuery, ...]:
        if self._dns is None:
            raise RuntimeError("SPF/DKIM DNS fixture is not running")
        return self._dns.drain_queries()

    def stop(self) -> None:
        try:
            JavaOracleRuntime.stop(self)
        finally:
            if self._dns is not None:
                self._dns.stop()
            self._dns = None


@dataclass(slots=True)
class _SpfDkimCandidateRuntime(CandidateRuntime):
    _dns: ScriptedDnsServer | None = field(default=None, init=False, repr=False)

    @property
    def requires_qa_account(self) -> bool:
        return True

    def _start_application(self) -> None:
        self._dns = ScriptedDnsServer(authentication_dns_answers())
        self._dns.start()
        CandidateRuntime._start_application(self)

    def _candidate_configuration(self) -> Path:
        path = CandidateRuntime._candidate_configuration(self)
        value = json.loads(path.read_text(encoding="utf-8"))
        if self._dns is None:
            raise RuntimeError("SPF/DKIM DNS fixture is not running")
        value["features"]["smtp_spf_dns_server"] = f"{self._dns.host}:{self._dns.port}"
        value["content_filter"] = {"enabled": False}
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def drain_authentication_dns_queries(self) -> tuple[DnsQuery, ...]:
        if self._dns is None:
            raise RuntimeError("SPF/DKIM DNS fixture is not running")
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
        repository / "blackbox/golden/java/managed-smtp-spf-dkim-v8",
        "managed-smtp-spf-dkim",
        record_java=record_java,
    )


def _candidate(repository: Path) -> CandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        return cast(
            _SpfDkimCandidateRuntime,
            _SpfDkimCandidateRuntime.from_environment(),
        )
    return _SpfDkimCandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        )
    )


def _relaxed_header(name: str, value: str) -> bytes:
    normalized = re.sub(r"[ \t]+", " ", value).strip()
    return f"{name.lower()}:{normalized}\r\n".encode("ascii")


def _verify_combined_signature(message: bytes, expected_body: bytes) -> None:
    head, body = message.split(b"\r\n\r\n", 1)
    headers = []
    for line in head.decode("ascii").split("\r\n"):
        name, value = line.split(":", 1)
        headers.append((name, value))
    signature_header = next(
        header for header in headers if header[0].lower() == "dkim-signature"
    )
    tags = {
        name.strip(): value.strip()
        for item in signature_header[1].split(";")
        if "=" in item
        for name, value in (item.split("=", 1),)
    }
    canonical_body = expected_body.rstrip(b"\r\n") + b"\r\n"
    body_hash = base64.b64encode(hashlib.sha256(canonical_body).digest()).decode(
        "ascii"
    )
    assert body_hash == tags["bh"]
    if body != expected_body:
        actual_hash = base64.b64encode(
            hashlib.sha256(body.rstrip(b"\r\n") + b"\r\n").digest()
        ).decode("ascii")
        assert actual_hash != tags["bh"]

    signed = bytearray()
    for wanted in tags["h"].split(":"):
        selected = next(
            header for header in reversed(headers) if header[0].lower() == wanted
        )
        signed.extend(_relaxed_header(*selected))
    unsigned_value = re.sub(r"(?i)(\bb\s*=\s*)[^;]*$", r"\1", signature_header[1])
    signed.extend(_relaxed_header(signature_header[0], unsigned_value)[:-2])

    public_der = base64.b64decode(_COMBINED_PUBLIC_KEY.split("p=", 1)[1])
    public_key = cast(RSAPublicKey, serialization.load_der_public_key(public_der))
    public_key.verify(
        base64.b64decode(tags["b"]),
        bytes(signed),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def test_combined_messages_have_unique_identity_and_valid_signatures() -> None:
    for case in _CASES:
        message, subject, selector = combined_message(case)
        assert message.count(b"Message-ID:") == 1
        assert f"Message-ID: {case.message_id}\r\n".encode("ascii") in message
        assert f"Subject: {subject}\r\n".encode("ascii") in message
        if case.dkim.result == "none":
            assert b"DKIM-Signature:" not in message
            assert selector is None
            continue
        if case.dkim.result == "permerror":
            assert selector == f"missing-{case.spf.name}"
            assert f"s={selector};".encode("ascii") in message
            continue
        assert selector == "combined"
        expected_body = (
            f"Combined SPF {case.spf.name} and DKIM {case.dkim.name} signed fixture.\r\n"
        ).encode("ascii")
        _verify_combined_signature(message, expected_body)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(900)
def test_managed_java_smtp_spf_dkim_golden(record_java_golden: bool) -> None:
    paths = JavaOracleRuntime().paths
    differential = _runner(paths.repository, record_java=record_java_golden)
    with _SpfDkimJavaRuntime(paths=paths) as oracle:
        if record_java_golden:
            differential.record_from_java(SMTP_SPF_DKIM_SCENARIOS, oracle)
        else:
            differential.verify_java(SMTP_SPF_DKIM_SCENARIOS, oracle)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(900)
def test_rust_candidate_smtp_spf_dkim_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    differential = _runner(repository)
    with _candidate(repository) as candidate:
        differential.verify_candidate(SMTP_SPF_DKIM_SCENARIOS, candidate)
