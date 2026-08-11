from __future__ import annotations

import os
from pathlib import Path

import pytest

from lmyzmail_blackbox.golden import GoldenAttestation, GoldenStore
from lmyzmail_blackbox.runtime import CandidateRuntime, JavaOracleRuntime
from lmyzmail_blackbox.web_ui_contract import WEB_UI_CONTRACT, WebUiCapture, capture_web_ui

_PROFILE = "managed-web-ui"
_GOLDEN_VERSION = "managed-web-ui-v5"
_NORMALIZERS = (
    "playwright:chromium-1181",
    "locale:zh-CN",
    "timezone:UTC",
    "animations:disabled",
    "focus:blurred",
    "password-fields:cleared-after-validation",
    "css-transitions:disabled",
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


def _assert_capture(repository: Path, capture: WebUiCapture, *, record: bool) -> None:
    store = GoldenStore(
        repository / f"blackbox/golden/java/{_GOLDEN_VERSION}",
        GoldenAttestation.from_repository(
            repository,
            profile=_PROFILE,
            normalizers=_NORMALIZERS,
        ),
        record=record,
    )
    store.assert_observation(
        "suite.json",
        {
            "profile": _PROFILE,
            "normalizers": list(_NORMALIZERS),
            "contract": WEB_UI_CONTRACT,
        },
    )
    store.assert_observation("observations/http/ui/states.json", capture.observation)
    for name, screenshot in capture.artifacts:
        store.assert_artifact(f"pixels/http/ui/{name}", screenshot)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.playwright
@pytest.mark.timeout(180)
def test_managed_java_web_ui_golden(record_java_golden: bool) -> None:
    paths = JavaOracleRuntime().paths
    with JavaOracleRuntime(paths=paths) as oracle:
        _assert_capture(
            paths.repository,
            capture_web_ui(oracle),
            record=record_java_golden,
        )


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.playwright
@pytest.mark.timeout(180)
def test_rust_candidate_web_ui_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        _assert_capture(repository, capture_web_ui(candidate), record=False)
