from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, cast

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner, Scenario
from lmyzmail_blackbox.runtime import CandidateRuntime, JavaOracleRuntime
from lmyzmail_blackbox.scripted_dns import DnsQuery, ScriptedDnsServer
from lmyzmail_blackbox.smtp_spamhaus_contract import (
    SMTP_SPAMHAUS_DISABLED_SCENARIOS,
    SMTP_SPAMHAUS_REJECT_DISABLED_SCENARIOS,
    SMTP_SPAMHAUS_REJECT_SCENARIOS,
    SPAMHAUS_DBL_ZONE,
    spamhaus_dns_answers,
)

_Profile = Literal["reject", "reject-disabled", "disabled"]


@dataclass(slots=True)
class _SpamhausJavaRuntime(JavaOracleRuntime):
    spamhaus_profile: _Profile = "reject"
    _dns: ScriptedDnsServer | None = field(default=None, init=False, repr=False)

    @property
    def requires_qa_account(self) -> bool:
        return False

    def _start_application(self) -> None:
        self._dns = ScriptedDnsServer(spamhaus_dns_answers())
        self._dns.start()
        JavaOracleRuntime._start_application(self)

    def _application_arguments(self) -> list[str]:
        arguments = JavaOracleRuntime._application_arguments(self)
        if self._dns is None:
            raise RuntimeError("Spamhaus DNS fixture is not running")
        arguments.insert(
            arguments.index("-jar"),
            f"-Ddns.server={self._dns.host}:{self._dns.port}",
        )
        domain_index = arguments.index("--botmail.domains.main.domain=example.test")
        arguments[domain_index] = "--botmail.domains.main.domain=blackbox.example.com"
        enabled_index = arguments.index("--botmail.smtp-security.spamhaus-enabled=false")
        enabled = self.spamhaus_profile != "disabled"
        arguments[enabled_index] = (
            f"--botmail.smtp-security.spamhaus-enabled={str(enabled).lower()}"
        )
        dbl_index = arguments.index("--botmail.smtp-security.spamhaus-dbl-enabled=false")
        arguments[dbl_index] = "--botmail.smtp-security.spamhaus-dbl-enabled=true"
        reject = self.spamhaus_profile != "reject-disabled"
        arguments.extend(
            (
                f"--botmail.smtp-security.spamhaus-reject-on-listed={str(reject).lower()}",
                "--botmail.smtp-security.spamhaus-timeout-ms=300",
                "--botmail.smtp-security.spamhaus-cache-ttl-seconds=1",
                f"--botmail.smtp-security.spamhaus-dbl-zone={SPAMHAUS_DBL_ZONE}",
            )
        )
        return arguments

    def drain_spamhaus_dns_queries(self) -> tuple[DnsQuery, ...]:
        if self._dns is None:
            raise RuntimeError("Spamhaus DNS fixture is not running")
        return self._dns.drain_queries()

    def stop(self) -> None:
        try:
            JavaOracleRuntime.stop(self)
        finally:
            if self._dns is not None:
                self._dns.stop()
            self._dns = None


@dataclass(slots=True)
class _SpamhausCandidateRuntime(CandidateRuntime):
    spamhaus_profile: _Profile = "reject"
    _dns: ScriptedDnsServer | None = field(default=None, init=False, repr=False)

    @property
    def requires_qa_account(self) -> bool:
        return False

    def _start_application(self) -> None:
        self._dns = ScriptedDnsServer(spamhaus_dns_answers())
        self._dns.start()
        CandidateRuntime._start_application(self)

    def _candidate_configuration(self) -> Path:
        path = CandidateRuntime._candidate_configuration(self)
        value = json.loads(path.read_text(encoding="utf-8"))
        if self._dns is None:
            raise RuntimeError("Spamhaus DNS fixture is not running")
        enabled = self.spamhaus_profile != "disabled"
        reject = self.spamhaus_profile != "reject-disabled"
        value["domain"] = "blackbox.example.com"
        value["features"].update(
            {
                "smtp_spf_dns_server": f"{self._dns.host}:{self._dns.port}",
                "spamhaus": enabled,
                "smtp_spamhaus_reject_on_listed": reject,
                "smtp_spamhaus_timeout_ms": 300,
                "smtp_spamhaus_cache_ttl_seconds": 1,
                "smtp_spamhaus_dbl_enabled": True,
                "smtp_spamhaus_dbl_zone": SPAMHAUS_DBL_ZONE,
            }
        )
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def drain_spamhaus_dns_queries(self) -> tuple[DnsQuery, ...]:
        if self._dns is None:
            raise RuntimeError("Spamhaus DNS fixture is not running")
        return self._dns.drain_queries()

    def stop(self) -> None:
        try:
            CandidateRuntime.stop(self)
        finally:
            if self._dns is not None:
                self._dns.stop()
            self._dns = None


def _candidate(repository: Path, profile: _Profile) -> CandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        runtime = cast(
            _SpamhausCandidateRuntime,
            _SpamhausCandidateRuntime.from_environment(),
        )
        runtime.spamhaus_profile = profile
        return runtime
    return _SpamhausCandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        ),
        spamhaus_profile=profile,
    )


def _profile_settings(profile: _Profile) -> tuple[str, tuple[Scenario, ...]]:
    if profile == "reject":
        return "managed-smtp-spamhaus-v5", SMTP_SPAMHAUS_REJECT_SCENARIOS
    if profile == "reject-disabled":
        return (
            "managed-smtp-spamhaus-reject-disabled-v5",
            SMTP_SPAMHAUS_REJECT_DISABLED_SCENARIOS,
        )
    return "managed-smtp-spamhaus-disabled-v5", SMTP_SPAMHAUS_DISABLED_SCENARIOS


def _runner(
    repository: Path,
    profile: _Profile,
    *,
    record_java: bool = False,
) -> tuple[DifferentialRunner, tuple[Scenario, ...]]:
    golden_name, scenarios = _profile_settings(profile)
    return (
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java" / golden_name,
            golden_name.removesuffix("-v1"),
            record_java=record_java,
        ),
        scenarios,
    )


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.parametrize("profile", ("reject", "reject-disabled", "disabled"))
@pytest.mark.timeout(360)
def test_managed_java_smtp_spamhaus_golden(
    record_java_golden: bool,
    profile: _Profile,
) -> None:
    paths = JavaOracleRuntime().paths
    differential, scenarios = _runner(paths.repository, profile, record_java=record_java_golden)
    with _SpamhausJavaRuntime(paths=paths, spamhaus_profile=profile) as oracle:
        if record_java_golden:
            differential.record_from_java(scenarios, oracle)
        else:
            differential.verify_java(scenarios, oracle)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.parametrize("profile", ("reject", "reject-disabled", "disabled"))
@pytest.mark.timeout(360)
def test_rust_candidate_smtp_spamhaus_matches_frozen_java_golden(profile: _Profile) -> None:
    repository = Path(__file__).resolve().parents[2]
    differential, scenarios = _runner(repository, profile)
    with _candidate(repository, profile) as candidate:
        differential.verify_candidate(scenarios, candidate)
