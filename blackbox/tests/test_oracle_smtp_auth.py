from __future__ import annotations

import os
from pathlib import Path

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner
from lmyzmail_blackbox.runtime import (
    CandidateRuntime,
    CandidateTlsRuntime,
    JavaOracleRuntime,
    JavaOracleTlsRuntime,
)
from lmyzmail_blackbox.smtp_auth_contract import (
    SMTP_AUTH_SCENARIOS,
    SMTP_AUTH_TLS_SCENARIOS,
)


def _candidate(repository: Path, *, tls: bool = False) -> CandidateRuntime:
    runtime_type = CandidateTlsRuntime if tls else CandidateRuntime
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        return runtime_type.from_environment()
    return runtime_type(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        )
    )


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(240)
def test_managed_java_smtp_auth_goldens(record_java_golden: bool) -> None:
    paths = JavaOracleRuntime().paths
    differential = DifferentialRunner(
        paths.repository,
        paths.repository / "blackbox/golden/java/managed-smtp-auth-v40",
        "managed-smtp-auth",
        record_java=record_java_golden,
    )

    with JavaOracleRuntime(paths=paths) as oracle:
        if record_java_golden:
            differential.record_from_java(SMTP_AUTH_SCENARIOS, oracle)
        else:
            differential.verify_java(SMTP_AUTH_SCENARIOS, oracle)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(240)
def test_rust_candidate_smtp_auth_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    differential = DifferentialRunner(
        repository,
        repository / "blackbox/golden/java/managed-smtp-auth-v40",
        "managed-smtp-auth",
    )
    with _candidate(repository) as candidate:
        differential.verify_candidate(SMTP_AUTH_SCENARIOS, candidate)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(240)
def test_managed_java_smtp_auth_starttls_goldens(record_java_golden: bool) -> None:
    paths = JavaOracleRuntime().paths
    differential = DifferentialRunner(
        paths.repository,
        paths.repository / "blackbox/golden/java/managed-smtp-auth-starttls-v40",
        "managed-smtp-auth-starttls",
        record_java=record_java_golden,
    )

    with JavaOracleTlsRuntime(paths=paths) as oracle:
        if record_java_golden:
            differential.record_from_java(SMTP_AUTH_TLS_SCENARIOS, oracle)
        else:
            differential.verify_java(SMTP_AUTH_TLS_SCENARIOS, oracle)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(240)
def test_rust_candidate_smtp_auth_starttls_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    differential = DifferentialRunner(
        repository,
        repository / "blackbox/golden/java/managed-smtp-auth-starttls-v40",
        "managed-smtp-auth-starttls",
    )
    with _candidate(repository, tls=True) as candidate:
        differential.verify_candidate(SMTP_AUTH_TLS_SCENARIOS, candidate)
