from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, cast

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner, Scenario
from lmyzmail_blackbox.runtime import CandidateRuntime, JavaOracleRuntime
from lmyzmail_blackbox.scripted_dns import ScriptedDnsServer
from lmyzmail_blackbox.smtp_self_spoof_contract import (
    SMTP_SELF_SPOOF_FALLBACK_SCENARIOS,
    SMTP_SELF_SPOOF_GENERIC_SCENARIOS,
    SMTP_SELF_SPOOF_INFERX_SCENARIOS,
)

type Profile = Literal["inferx", "fallback", "generic"]

_SCENARIOS: dict[Profile, tuple[Scenario, ...]] = {
    "inferx": SMTP_SELF_SPOOF_INFERX_SCENARIOS,
    "fallback": SMTP_SELF_SPOOF_FALLBACK_SCENARIOS,
    "generic": SMTP_SELF_SPOOF_GENERIC_SCENARIOS,
}


@dataclass(slots=True)
class _ProfileJavaRuntime(JavaOracleRuntime):
    profile: Profile = "inferx"
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
            raise RuntimeError("self-spoofing DNS fixture is not running")
        arguments.insert(
            arguments.index("-jar"),
            f"-Ddns.server={self._dns.host}:{self._dns.port}",
        )
        domain_index = arguments.index("--botmail.domains.main.domain=example.test")
        arguments[domain_index] = "--botmail.domains.main.domain=blackbox.example.com"
        if self.profile == "inferx":
            arguments.extend(
                (
                    "--botmail.skibidi-inferx.timeout-ms=5000",
                    "--botmail.skibidi-inferx.simd-level=scalar",
                )
            )
        elif self.profile == "fallback":
            arguments.append("--botmail.skibidi-inferx.enabled=false")
        else:
            arguments.extend(
                (
                    "--botmail.skibidi-inferx.enabled=false",
                    "--botmail.smtp.skibidi-insults-enabled=false",
                )
            )
        return arguments

    def stop(self) -> None:
        try:
            JavaOracleRuntime.stop(self)
        finally:
            if self._dns is not None:
                self._dns.stop()
            self._dns = None


@dataclass(slots=True)
class _ProfileCandidateRuntime(CandidateRuntime):
    profile: Profile = "inferx"
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
            raise RuntimeError("self-spoofing DNS fixture is not running")
        value["domain"] = "blackbox.example.com"
        value["features"]["smtp_spf_dns_server"] = f"{self._dns.host}:{self._dns.port}"
        inferx = value["skibidi_inferx"]
        if self.profile == "inferx":
            inferx["timeout_ms"] = 5_000
            inferx["simd_level"] = "scalar"
        else:
            inferx["enabled"] = False
        if self.profile == "generic":
            value["features"]["smtp_skibidi_insults"] = False
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


def _candidate(repository: Path, profile: Profile) -> CandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        runtime = cast(
            _ProfileCandidateRuntime,
            _ProfileCandidateRuntime.from_environment(),
        )
        runtime.profile = profile
        return runtime
    return _ProfileCandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        ),
        profile=profile,
    )


def _runner(repository: Path, profile: Profile, *, record_java: bool = False) -> DifferentialRunner:
    name = f"managed-smtp-self-spoof-{profile}"
    return DifferentialRunner(
        repository,
        repository / f"blackbox/golden/java/{name}-v1",
        name,
        record_java=record_java,
    )


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(360)
@pytest.mark.parametrize("profile", ("inferx", "fallback", "generic"))
def test_managed_java_smtp_self_spoof_golden(
    record_java_golden: bool,
    profile: Profile,
) -> None:
    paths = JavaOracleRuntime().paths
    differential = _runner(paths.repository, profile, record_java=record_java_golden)
    with _ProfileJavaRuntime(paths=paths, profile=profile) as oracle:
        if record_java_golden:
            differential.record_from_java(_SCENARIOS[profile], oracle)
        else:
            differential.verify_java(_SCENARIOS[profile], oracle)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(360)
@pytest.mark.parametrize("profile", ("inferx", "fallback", "generic"))
def test_rust_candidate_smtp_self_spoof_matches_frozen_java_golden(profile: Profile) -> None:
    repository = Path(__file__).resolve().parents[2]
    differential = _runner(repository, profile)
    with _candidate(repository, profile) as candidate:
        differential.verify_candidate(_SCENARIOS[profile], candidate)
