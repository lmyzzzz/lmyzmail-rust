#!/usr/bin/env bash
set -euo pipefail
cd /home/lmyzzz/lmyzmail-rust

# The prior run overlapped oracle/candidate processes and package installations.
# Preserve its disk-gate failure. Await the full replay and renderer follow-up
# before measuring the same unchanged half-hour policy again.
while [[ ! -f evidence/compatibility/renderer-local-22dae7d0/result-v2.xml ]]; do
    sleep 5
done
while [[ ! -f .blackbox/release-22dae7d0-isolated-soak-ready ]]; do
    sleep 5
done
.blackbox/venv/bin/python - <<'PY'
import xml.etree.ElementTree as ET
from pathlib import Path

paths = (
    Path("evidence/compatibility/release-22dae7d0-candidate-v2.xml"),
    Path("evidence/compatibility/renderer-local-22dae7d0/result-v2.xml"),
)
for path in paths:
    suites = list(ET.parse(path).getroot().iter("testsuite"))
    assert suites and not sum(int(s.get(key, 0)) for s in suites
                              for key in ("failures", "errors", "skipped")), path
print("Complete pinned replay and local rendering passed; starting isolated soak", flush=True)
PY
.blackbox/venv/bin/python evidence/compatibility/candidate-soak-v6.py \
    --duration 1800 --workers 16 \
    --output evidence/compatibility/candidate-soak-22dae7d0-20261023-v2.json \
    2>&1 | tee evidence/compatibility/candidate-soak-22dae7d0-20261023-v2.log
