"""Exercise the packaged model through the real candidate SMTP/DB boundary."""
from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "blackbox/tests"))

from test_oracle_smtp_self_spoof import _ProfileCandidateRuntime
from lmyzmail_blackbox.smtp_self_spoof_contract import SMTP_SELF_SPOOF_INFERX_SCENARIOS


class CompactRuntime(_ProfileCandidateRuntime):
    backend = "auto"

    def _candidate_configuration(self) -> Path:
        path = super()._candidate_configuration()
        config = json.loads(path.read_text(encoding="utf-8"))
        assets = ROOT / "models/skibidi-inferx-compact-20261022"
        config["skibidi_inferx"]["model_path"] = str(assets / "skibidi_ai.safetensors")
        config["skibidi_inferx"]["tokenizer_path"] = str(assets / "tokenizer.json")
        config["skibidi_inferx"]["simd_level"] = self.backend
        path.write_text(json.dumps(config), encoding="utf-8")
        return path


@pytest.mark.parametrize("backend", ("scalar", "auto"))
def test_compact_release_generates_smtp_rejection_and_persists_exact_activity(backend):
    binary = Path(os.environ["LMYZMAIL_COMPACT_RELEASE_BINARY"]).resolve(strict=True)
    assets = ROOT / "models/skibidi-inferx-compact-20261022"
    manifest = json.loads((assets / "SOURCE.json").read_text())
    for artifact in manifest["artifacts"]:
        with (assets / artifact["path"]).open("rb") as stream:
            assert hashlib.file_digest(stream, "sha256").hexdigest() == artifact["sha256"]
    runtime = CompactRuntime(command_template=(str(binary), "--config", "{config}"), profile="inferx")
    runtime.backend = backend
    with runtime:
        assert runtime._application is not None
        assert runtime.ports is not None
        # HTTP health can become ready before the SMTP task has bound its port.
        # Wait only for startup; protocol or persistence failures are never retried.
        deadline = time.monotonic() + 5
        while True:
            try:
                with socket.create_connection(("127.0.0.1", runtime.ports.smtp), timeout=1):
                    break
            except ConnectionRefusedError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)
        maps = Path(f"/proc/{runtime._application.pid}/maps").read_text()
        assert str(assets / "skibidi_ai.safetensors") in maps
        assert "libjvm" not in maps and "libskibidi_inferx_native" not in maps
        for scenario in SMTP_SELF_SPOOF_INFERX_SCENARIOS:
            scenario.capture(runtime)
