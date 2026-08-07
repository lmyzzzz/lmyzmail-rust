from __future__ import annotations

import json
from pathlib import Path

import pytest

from lmyzmail_blackbox.errors import HarnessError
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.runtime import CandidateRuntime


def test_candidate_command_is_shell_free_and_receives_semantic_config(tmp_path: Path) -> None:
    runtime = CandidateRuntime(
        command_template=("/bin/echo", "--config", "{config}", "--http", "{http_port}")
    )
    runtime.workspace = tmp_path
    runtime.ports = PortSet(15432, 16379, 18080, 1025, 18888, 25575, tuple(range(20000, 20008)))

    command = runtime._application_arguments()

    assert command == [
        "/bin/echo",
        "--config",
        str(tmp_path / "candidate-runtime.json"),
        "--http",
        "18080",
    ]
    config = json.loads((tmp_path / "candidate-runtime.json").read_text(encoding="utf-8"))
    assert config["schema_version"] == 1
    assert config["listen"]["smtp"] == 1025
    assert config["postgres"]["port"] == 15432
    assert config["features"]["smtp_skibidi_mode"] == "AUTO_SAFE"
    assert config["htcpcp"]["enabled"] is True
    assert config["htcpcp"]["default_brew_time_seconds"] == 1
    assert [pot["id"] for pot in config["htcpcp"]["pots"]] == [
        f"pot-{index}" for index in range(8)
    ]
    assert config["limits"]["max_honeypot_connections_per_trap"] == 4
    assert config["limits"]["max_honeypot_read_bytes"] == 1024


def test_candidate_command_environment_requires_json_string_array(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LMYZMAIL_CANDIDATE_COMMAND_JSON", "not-json")
    with pytest.raises(HarnessError, match="valid JSON"):
        CandidateRuntime.from_environment()

    monkeypatch.setenv("LMYZMAIL_CANDIDATE_COMMAND_JSON", '["/bin/echo", "{unknown}"]')
    runtime = CandidateRuntime.from_environment()
    runtime.workspace = tmp_path
    runtime.ports = PortSet(1, 2, 3, 4, 5, 6, tuple(range(10, 18)))
    with pytest.raises(HarnessError, match="unknown candidate command template field"):
        runtime._application_arguments()
