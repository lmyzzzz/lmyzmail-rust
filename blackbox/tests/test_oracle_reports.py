from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.report_contract import REPORT_SCENARIOS


@dataclass(frozen=True, slots=True)
class _OracleTarget:
    runtime: PersistentJavaOracleRuntime

    @property
    def target_kind(self) -> str:
        return "java-oracle"

    @property
    def workspace(self) -> Path | None:
        return self.runtime.workspace

    @property
    def ports(self) -> PortSet | None:
        return self.runtime.ports


def _verify_fresh_java(
    runner: DifferentialRunner,
    workspace: Path,
    *,
    record: bool,
) -> None:
    with PersistentJavaOracleRuntime(workspace) as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(REPORT_SCENARIOS, target)
        else:
            runner.verify_java(REPORT_SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(360)
def test_frozen_java_reports_golden(
    tmp_path: Path,
    record_java_golden: bool,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    runner = DifferentialRunner(
        repository,
        repository / "blackbox/golden/java/managed-reports-v1",
        "managed-reports",
        record_java=record_java_golden,
    )

    if record_java_golden:
        _verify_fresh_java(runner, tmp_path / "reports-record", record=True)

    _verify_fresh_java(runner, tmp_path / "reports-verify", record=False)
