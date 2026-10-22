#!/usr/bin/env python3
"""Run unchanged black-box tests against a pinned external release executable."""
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

binary = Path(sys.argv[1]).resolve(strict=True)
with binary.open("rb") as stream:
    before = hashlib.file_digest(stream, "sha256").hexdigest()
os.environ["LMYZMAIL_CANDIDATE_COMMAND_JSON"] = json.dumps([str(binary), "--config", "{config}"])
os.environ["LMYZMAIL_TAKEOVER_BINARY"] = str(binary)
os.environ["LMYZMAIL_COMPACT_RELEASE_BINARY"] = str(binary)
print(json.dumps({"external_candidate_binary": str(binary), "sha256_before": before}), flush=True)
result = pytest.main(sys.argv[2:])
with binary.open("rb") as stream:
    after = hashlib.file_digest(stream, "sha256").hexdigest()
print(json.dumps({"sha256_after": after, "unchanged": before == after}), flush=True)
if before != after:
    raise SystemExit("candidate executable changed during acceptance")
raise SystemExit(result)
