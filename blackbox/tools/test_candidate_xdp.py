from __future__ import annotations

import os
from pathlib import Path

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner
from lmyzmail_blackbox.runtime import CandidateRuntime
from lmyzmail_blackbox.xdp_contract import XDP_SCENARIOS


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(120)
def test_rust_candidate_xdp_disabled_matches_frozen_java() -> None:
    repository = Path(__file__).resolve().parents[2]
    candidate = (
        CandidateRuntime.from_environment()
        if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None
        else CandidateRuntime(
            command_template=(
                str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
                "--config",
                "{config}",
            )
        )
    )
    with candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java/managed-xdp-disabled-v5",
            "managed-xdp-disabled",
        ).verify_candidate(XDP_SCENARIOS, candidate)
