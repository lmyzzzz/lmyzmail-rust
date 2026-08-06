from __future__ import annotations

from pathlib import Path


def _launcher() -> Path:
    return Path(__file__).resolve().parents[2] / "blackbox/bin/run-outbound-probe.sh"


def test_outbound_launcher_does_not_trust_inherited_namespace_marker() -> None:
    source = _launcher().read_text(encoding="ascii")

    assert "LMYZMAIL_OUTBOUND_NETNS" not in source
    assert '"${1:-}" == "__inside-outbound-netns" && "$#" == 1' in source
    assert '"$script_path" __inside-outbound-netns' in source
