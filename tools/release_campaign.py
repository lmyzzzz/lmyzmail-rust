"""Pytest plugin for create-once Java re-attestation without editing old goldens.

Usage: LMYZMAIL_GOLDEN_CAMPAIGN=20261022 PYTHONPATH=tools:blackbox/src
       .blackbox/venv/bin/python -m pytest -p release_campaign ...

Only GoldenStore's storage location changes. Its complete attestation,
observation and binary-artifact comparisons remain untouched. A fresh oracle
replay is required before comparing the candidate with the new generation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from lmyzmail_blackbox.golden import GoldenStore, _sha256_definition_tree

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / "blackbox/golden/java"
_resolve = GoldenStore._resolve
_before: dict[str, str] = {}
_definition = ""
_campaign: Path | None = None


def inventory(root: Path) -> dict[str, str]:
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RuntimeError(f"symlink in golden tree: {path}")
        if path.is_file():
            with path.open("rb") as stream:
                result[path.relative_to(root).as_posix()] = hashlib.file_digest(stream, "sha256").hexdigest()
    return result


def resolve(self: GoldenStore, relative_path: str) -> Path:
    original = _resolve(self, relative_path)
    if not original.is_relative_to(ORIGINAL):
        return original
    assert _campaign is not None
    path = _campaign / original.relative_to(ORIGINAL)
    if not path.resolve().is_relative_to(_campaign.resolve()):
        raise ValueError("campaign golden path escaped its root")
    return path


def pytest_configure(config) -> None:
    global _before, _definition, _campaign
    name = os.environ.get("LMYZMAIL_GOLDEN_CAMPAIGN", "")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", name):
        raise ValueError("LMYZMAIL_GOLDEN_CAMPAIGN must be a short lowercase campaign name")
    _campaign = ROOT / "blackbox/golden/campaigns" / name / "java"
    if _campaign.is_symlink():
        raise ValueError("campaign root must not be a symlink")
    _before = inventory(ORIGINAL)
    _definition = _sha256_definition_tree(ROOT)
    GoldenStore._resolve = resolve


def pytest_sessionfinish(session, exitstatus) -> None:
    if inventory(ORIGINAL) != _before:
        raise AssertionError("immutable original goldens changed during campaign")
    if _sha256_definition_tree(ROOT) != _definition:
        raise AssertionError("harness definition changed during campaign")
    # Check semantic drift separately from the unchanged exact GoldenStore
    # assertions. Only the harness-definition attestation is expected to differ.
    assert _campaign is not None
    matched = 0
    differences = []
    for relative in inventory(_campaign):
        before, after = ORIGINAL / relative, _campaign / relative
        if not before.is_file():
            differences.append({"path": relative, "reason": "no historical observation"})
            continue
        old, new = before.read_bytes(), after.read_bytes()
        if relative.endswith(".json"):
            left, right = json.loads(old), json.loads(new)
            if isinstance(left, dict) and "attestation" in left and isinstance(right, dict) and "attestation" in right:
                left["attestation"]["harness"].pop("definition_tree_sha256")
                right["attestation"]["harness"].pop("definition_tree_sha256")
                equal = left == right
            else:
                equal = old == new
        else:
            equal = old == new
        if equal:
            matched += 1
        else:
            differences.append({"path": relative, "reason": "semantic or artifact difference"})
    print("\nCampaign audit:", json.dumps({
        "harness_definition_sha256": _definition,
        "old_golden_files_unchanged": len(_before),
        "historical_observations_equal": matched,
        "differences_requiring_review": differences,
        "pytest_exitstatus": int(exitstatus),
    }, ensure_ascii=False, sort_keys=True))
    if differences:
        session.exitstatus = 1


def pytest_unconfigure(config) -> None:
    GoldenStore._resolve = _resolve
