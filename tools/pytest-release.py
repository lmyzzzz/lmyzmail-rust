#!/usr/bin/env python3
"""Run unchanged tests after a pinned ELF has been staged at their normal path.

The original per-profile command templates must remain intact. A global
LMYZMAIL_CANDIDATE_COMMAND_JSON replaces those templates and drops their flags.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

binary = Path(sys.argv[1]).resolve(strict=True)
with binary.open("rb") as stream:
    before = hashlib.file_digest(stream, "sha256").hexdigest()
default = Path(__file__).resolve().parents[1] / "target/x86_64-unknown-linux-gnu/release/lmyzmail"
with default.open("rb") as stream:
    staged_before = hashlib.file_digest(stream, "sha256").hexdigest()
if staged_before != before:
    raise SystemExit("stage the pinned ELF at the tests' normal target path before running")
if "LMYZMAIL_CANDIDATE_COMMAND_JSON" in os.environ:
    raise SystemExit("unset the global candidate command to preserve per-profile launch arguments")
os.environ["LMYZMAIL_TAKEOVER_BINARY"] = str(binary)
os.environ["LMYZMAIL_COMPACT_RELEASE_BINARY"] = str(binary)
print(json.dumps({"external_candidate_binary": str(binary), "sha256_before": before}), flush=True)
result = pytest.main(sys.argv[2:])
with binary.open("rb") as stream:
    after = hashlib.file_digest(stream, "sha256").hexdigest()
with default.open("rb") as stream:
    staged_after = hashlib.file_digest(stream, "sha256").hexdigest()
print(json.dumps({"sha256_after": after, "staged_sha256_after": staged_after,
                  "unchanged": before == after == staged_after}), flush=True)
if before != after or before != staged_after:
    raise SystemExit("candidate executable changed during acceptance")
raise SystemExit(result)
