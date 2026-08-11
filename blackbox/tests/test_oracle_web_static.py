from __future__ import annotations

import os
from pathlib import Path

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner
from lmyzmail_blackbox.runtime import CandidateRuntime, JavaOracleRuntime
from lmyzmail_blackbox.web_static_contract import WEB_STATIC_SCENARIOS


def _runner(repository: Path, *, record_java: bool = False) -> DifferentialRunner:
    return DifferentialRunner(
        repository,
        repository / "blackbox/golden/java/managed-web-static-v2",
        "managed-web-static",
        record_java=record_java,
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
@pytest.mark.timeout(180)
def test_managed_java_web_static_golden(record_java_golden: bool) -> None:
    paths = JavaOracleRuntime().paths
    runner = _runner(paths.repository, record_java=record_java_golden)
    with JavaOracleRuntime(paths=paths) as oracle:
        if record_java_golden:
            runner.record_from_java(WEB_STATIC_SCENARIOS, oracle)
        else:
            runner.verify_java(WEB_STATIC_SCENARIOS, oracle)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_web_static_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        _runner(repository).verify_candidate(WEB_STATIC_SCENARIOS, candidate)
