from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner
from lmyzmail_blackbox.runtime import CandidateRuntime, JavaOracleRuntime
from lmyzmail_blackbox.scripted_dns import ScriptedDnsServer
from lmyzmail_blackbox.smtp_sender_domain_contract import SMTP_SENDER_DOMAIN_SCENARIOS


@dataclass(slots=True)
class _SenderDomainJavaRuntime(JavaOracleRuntime):
    _dns: ScriptedDnsServer | None = field(default=None, init=False, repr=False)

    @property
    def requires_qa_account(self) -> bool:
        return False

    def _start_application(self) -> None:
        self._dns = ScriptedDnsServer({})
        self._dns.start()
        JavaOracleRuntime._start_application(self)

    def _application_arguments(self) -> list[str]:
        arguments = JavaOracleRuntime._application_arguments(self)
        if self._dns is None:
            raise RuntimeError("sender-domain DNS fixture is not running")
        arguments.insert(
            arguments.index("-jar"),
            f"-Ddns.server={self._dns.host}:{self._dns.port}",
        )
        domain_index = arguments.index("--botmail.domains.main.domain=example.test")
        arguments[domain_index] = "--botmail.domains.main.domain=blackbox.example.com"
        return arguments

    def stop(self) -> None:
        try:
            JavaOracleRuntime.stop(self)
        finally:
            if self._dns is not None:
                self._dns.stop()
            self._dns = None


@dataclass(slots=True)
class _SenderDomainCandidateRuntime(CandidateRuntime):
    _dns: ScriptedDnsServer | None = field(default=None, init=False, repr=False)

    @property
    def requires_qa_account(self) -> bool:
        return False

    def _start_application(self) -> None:
        self._dns = ScriptedDnsServer({})
        self._dns.start()
        CandidateRuntime._start_application(self)

    def _candidate_configuration(self) -> Path:
        path = CandidateRuntime._candidate_configuration(self)
        value = json.loads(path.read_text(encoding="utf-8"))
        if self._dns is None:
            raise RuntimeError("sender-domain DNS fixture is not running")
        value["domain"] = "blackbox.example.com"
        value["features"]["smtp_spf_dns_server"] = f"{self._dns.host}:{self._dns.port}"
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def stop(self) -> None:
        try:
            CandidateRuntime.stop(self)
        finally:
            if self._dns is not None:
                self._dns.stop()
            self._dns = None


def _candidate(repository: Path) -> CandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        return cast(
            _SenderDomainCandidateRuntime,
            _SenderDomainCandidateRuntime.from_environment(),
        )
    return _SenderDomainCandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        )
    )


def _runner(repository: Path, *, record_java: bool = False) -> DifferentialRunner:
    return DifferentialRunner(
        repository,
        repository / "blackbox/golden/java/managed-smtp-sender-domain-v7",
        "managed-smtp-sender-domain",
        record_java=record_java,
    )


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(360)
def test_managed_java_smtp_sender_domain_golden(record_java_golden: bool) -> None:
    paths = JavaOracleRuntime().paths
    differential = _runner(paths.repository, record_java=record_java_golden)
    with _SenderDomainJavaRuntime(paths=paths) as oracle:
        if record_java_golden:
            differential.record_from_java(SMTP_SENDER_DOMAIN_SCENARIOS, oracle)
        else:
            differential.verify_java(SMTP_SENDER_DOMAIN_SCENARIOS, oracle)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(360)
def test_rust_candidate_smtp_sender_domain_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    differential = _runner(repository)
    with _candidate(repository) as candidate:
        differential.verify_candidate(SMTP_SENDER_DOMAIN_SCENARIOS, candidate)
