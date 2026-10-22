#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "blackbox/tests"))
from test_candidate_mail_read_golden import _candidate, _capture_delete_email
import test_candidate_web_multipart_golden as multipart


def differences(left, right, path=""):
    if isinstance(left, dict) and isinstance(right, dict):
        for key in sorted(left.keys() | right.keys()):
            differences(left.get(key), right.get(key), path + "/" + key)
    elif isinstance(left, list) and isinstance(right, list) and len(left) == len(right):
        for index, (a, b) in enumerate(zip(left, right, strict=True)):
            differences(a, b, f"{path}/{index}")
    elif left != right:
        print(json.dumps({"path": path, "java": left, "rust": right}, ensure_ascii=False))


if sys.argv[1] == "delete":
    with _candidate(ROOT) as candidate:
        actual = _capture_delete_email(candidate)
    original = json.loads((ROOT / "blackbox/golden/java/managed-mail-delete-v28/observations/http/mail/delete-email.json").read_text())["observation"]
    differences(original, actual)
else:
    with multipart._candidate(ROOT) as candidate:
        try:
            for scenario in multipart.WEB_MULTIPART_SCENARIOS:
                scenario.capture(candidate)
        finally:
            for path in sorted(candidate.workspace.rglob("*.eml")):
                print("maildir:", path.relative_to(candidate.workspace))
            for path in sorted(candidate.workspace.glob("*candidate*.log")):
                print(path.name, path.read_text()[-12000:])
