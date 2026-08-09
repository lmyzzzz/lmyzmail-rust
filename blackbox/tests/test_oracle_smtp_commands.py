from __future__ import annotations

import os
from pathlib import Path

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner
from lmyzmail_blackbox.runtime import CandidateRuntime, JavaOracleRuntime
from lmyzmail_blackbox.smtp_command_contract import (
    SMTP_COMMAND_ORACLE_EVIDENCE_SCENARIOS,
    SMTP_COMMAND_SCENARIOS,
)


def _candidate(repository: Path) -> CandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        return CandidateRuntime.from_environment()
    return CandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        )
    )


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(240)
def test_managed_java_smtp_command_goldens(record_java_golden: bool) -> None:
    paths = JavaOracleRuntime().paths
    differential = DifferentialRunner(
        paths.repository,
        paths.repository / "blackbox/golden/java/managed-smtp-command-v32",
        "managed-smtp-command",
        record_java=record_java_golden,
    )
    oracle_evidence = DifferentialRunner(
        paths.repository,
        paths.repository / "blackbox/golden/java/managed-smtp-command-oracle-evidence-v32",
        "managed-smtp-command-oracle-evidence",
        record_java=record_java_golden,
    )

    with JavaOracleRuntime(paths=paths) as oracle:
        if record_java_golden:
            differential.record_from_java(SMTP_COMMAND_SCENARIOS, oracle)
            oracle_evidence.record_from_java(
                SMTP_COMMAND_ORACLE_EVIDENCE_SCENARIOS,
                oracle,
            )
        else:
            differential.verify_java(SMTP_COMMAND_SCENARIOS, oracle)
            oracle_evidence.verify_java(
                SMTP_COMMAND_ORACLE_EVIDENCE_SCENARIOS,
                oracle,
            )


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(240)
def test_rust_candidate_smtp_commands_match_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    differential = DifferentialRunner(
        repository,
        repository / "blackbox/golden/java/managed-smtp-command-v32",
        "managed-smtp-command",
    )
    with _candidate(repository) as candidate:
        differential.verify_candidate(SMTP_COMMAND_SCENARIOS, candidate)
