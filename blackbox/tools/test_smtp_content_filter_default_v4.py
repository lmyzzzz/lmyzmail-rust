from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
import test_oracle_smtp_content_filter_default as base  # noqa: E402

_GOLDEN = "managed-smtp-content-filter-default-v13"
_PROFILE = "managed-smtp-content-filter-default-v4"


def _runner(repository: Path) -> DifferentialRunner:
    return DifferentialRunner(
        repository,
        repository / "blackbox/golden/java" / _GOLDEN,
        _PROFILE,
        record_java=os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1",
    )


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(240)
def test_frozen_java_smtp_content_filter_default_v4(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    with base._DefaultFilterJavaRuntime(tmp_path / "java-smtp-content-filter-default-v4") as oracle:
        target = base._OracleTarget(oracle)
        runner = _runner(repository)
        if runner.record_java:
            runner.record_from_java(base.SCENARIOS, target)
        else:
            runner.verify_java(base.SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(240)
def test_rust_candidate_smtp_content_filter_default_v4() -> None:
    repository = Path(__file__).resolve().parents[2]
    with base._candidate(repository) as candidate:
        _runner(repository).verify_candidate(base.SCENARIOS, candidate)
