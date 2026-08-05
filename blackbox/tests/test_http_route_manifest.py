from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


def test_frozen_http_route_manifest_is_complete_and_unique() -> None:
    repository = Path(__file__).resolve().parents[2]
    manifest: dict[str, Any] = json.loads(
        (repository / "blackbox/manifests/http-routes.json").read_text(encoding="utf-8")
    )
    routes = manifest["routes"]

    assert manifest["oracle_commit"] == "5dac2ab2922c30c726c4a83d7626c95ad4e231c8"
    assert manifest["declared_count"] == 72
    assert len(routes) == 72
    assert len({(route["method"], route["path"]) for route in routes}) == 72
    assert {route["auth"] for route in routes} == {
        "public",
        "session",
        "api_read",
        "api_write",
    }
    assert Counter(route["controller"] for route in routes) == {
        "LoginController": 5,
        "WebMailController": 13,
        "UserDataController": 15,
        "ApiStatusController": 3,
        "MailboxController": 2,
        "MailPollController": 3,
        "MailSendController": 4,
        "ReportController": 5,
        "StressTestController": 4,
        "XdpFirewallController": 8,
        "SkibidiCringeIPController": 10,
    }


def test_frozen_skibidi_lore_manifest_has_all_unique_members() -> None:
    repository = Path(__file__).resolve().parents[2]
    manifest: dict[str, Any] = json.loads(
        (repository / "blackbox/manifests/skibidi-lore.json").read_text(encoding="utf-8")
    )

    assert manifest["oracle_commit"] == "5dac2ab2922c30c726c4a83d7626c95ad4e231c8"
    assert manifest["count"] == 233
    assert len(manifest["lore"]) == 233
    assert len(set(manifest["lore"])) == 233
