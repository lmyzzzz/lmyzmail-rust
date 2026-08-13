from __future__ import annotations

from pathlib import Path

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner
from lmyzmail_blackbox.runtime import JavaOracleRuntime
from lmyzmail_blackbox.xdp_contract import XDP_SCENARIOS


def _verify_java(
    runner: DifferentialRunner,
    *,
    record: bool,
) -> None:
    with JavaOracleRuntime() as oracle:
        if record:
            runner.record_from_java(XDP_SCENARIOS, oracle)
        else:
            runner.verify_java(XDP_SCENARIOS, oracle)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(240)
def test_frozen_java_xdp_disabled_golden(
    record_java_golden: bool,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    runner = DifferentialRunner(
        repository,
        repository / "blackbox/golden/java/managed-xdp-disabled-v7",
        "managed-xdp-disabled",
        record_java=record_java_golden,
    )
    if record_java_golden:
        _verify_java(runner, record=True)
    _verify_java(runner, record=False)
