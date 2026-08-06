from __future__ import annotations

import os
from pathlib import Path

import pytest
from test_oracle_http_golden import HTTP_SCENARIOS

from lmyzmail_blackbox.differential import DifferentialRunner
from lmyzmail_blackbox.runtime import CandidateRuntime, JavaOracleRuntime

PUBLIC_HTTP_SCENARIOS = (
    HTTP_SCENARIOS[0],
    HTTP_SCENARIOS[1],
    HTTP_SCENARIOS[6],
    HTTP_SCENARIOS[7],
)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(120)
def test_frozen_java_public_http_golden(record_java_golden: bool) -> None:
    paths = JavaOracleRuntime().paths
    runner = DifferentialRunner(
        paths.repository,
        paths.repository / "blackbox/golden/java/managed-candidate-public-http-v1",
        "managed-candidate-public-http",
        record_java=record_java_golden,
    )
    with JavaOracleRuntime(paths=paths) as oracle:
        if record_java_golden:
            runner.record_from_java(PUBLIC_HTTP_SCENARIOS, oracle)
        else:
            runner.verify_java(PUBLIC_HTTP_SCENARIOS, oracle)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(120)
def test_rust_candidate_public_http_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    command = os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON")
    if command is not None:
        candidate = CandidateRuntime.from_environment()
    else:
        candidate = CandidateRuntime(command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        ))
    with candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java/managed-candidate-public-http-v1",
            "managed-candidate-public-http",
        ).verify_candidate(PUBLIC_HTTP_SCENARIOS, candidate)
