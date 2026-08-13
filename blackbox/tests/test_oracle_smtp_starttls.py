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
from lmyzmail_blackbox.smtp_tls_contract import (
    STARTTLS_ORACLE_EVIDENCE_SCENARIOS,
    STARTTLS_SCENARIOS,
)


def _candidate(repository: Path) -> CandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        return CandidateTlsRuntime.from_environment()
    return CandidateTlsRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        )
    )


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_managed_java_starttls_goldens(record_java_golden: bool) -> None:
    paths = JavaOracleRuntime().paths
    differential = DifferentialRunner(
        paths.repository,
        paths.repository / "blackbox/golden/java/managed-starttls-v40",
        "managed-starttls",
        record_java=record_java_golden,
    )
    oracle_evidence = DifferentialRunner(
        paths.repository,
        paths.repository / "blackbox/golden/java/managed-starttls-oracle-evidence-v40",
        "managed-starttls-oracle-evidence",
        record_java=record_java_golden,
    )

    with JavaOracleTlsRuntime(paths=paths) as oracle:
        if record_java_golden:
            differential.record_from_java(STARTTLS_SCENARIOS, oracle)
            oracle_evidence.record_from_java(STARTTLS_ORACLE_EVIDENCE_SCENARIOS, oracle)
        else:
            differential.verify_java(STARTTLS_SCENARIOS, oracle)
            oracle_evidence.verify_java(STARTTLS_ORACLE_EVIDENCE_SCENARIOS, oracle)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_starttls_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    differential = DifferentialRunner(
        repository,
        repository / "blackbox/golden/java/managed-starttls-v40",
        "managed-starttls",
    )
    with _candidate(repository) as candidate:
        differential.verify_candidate(STARTTLS_SCENARIOS, candidate)
