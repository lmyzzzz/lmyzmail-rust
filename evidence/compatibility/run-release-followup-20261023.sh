#!/usr/bin/env bash
set -euo pipefail
cd /home/lmyzzz/lmyzmail-rust

# Do not let candidate verification overtake the create-once oracle recording.
while kill -0 2112917 2>/dev/null; do
    sleep 5
done
.blackbox/venv/bin/python - <<'PY'
import json
import xml.etree.ElementTree as ET
from pathlib import Path

root = Path("evidence/compatibility/release-oracle-20261023-full-v3")
suites = list(ET.parse(root.with_suffix(".xml")).getroot().iter("testsuite"))
assert suites and sum(int(s.get("tests", 0)) for s in suites) == 107
assert not sum(int(s.get(key, 0)) for s in suites
               for key in ("failures", "errors", "skipped"))
audit = json.loads(root.with_suffix(".log").read_text().split("Campaign audit: ")[-1].splitlines()[0])
assert audit["pytest_exitstatus"] == 0 and not audit["differences_requiring_review"]
print("Full oracle gate passed; starting complete pinned candidate replay", flush=True)
PY
export PYTHONPATH=tools:blackbox/src
export LMYZMAIL_GOLDEN_CAMPAIGN=release-20261023-v3
.blackbox/venv/bin/python tools/pytest-release.py \
    .blackbox/release-artifacts-22dae7d0/lmyzmail \
    -c blackbox/pyproject.toml -p release_campaign -m candidate \
    -k 'not smtp_content_filter_rbl' blackbox/tests blackbox/tools -q \
    --junitxml=evidence/compatibility/release-22dae7d0-candidate-v2.xml \
    2>&1 | tee evidence/compatibility/release-22dae7d0-candidate-v2.log

export LMYZMAIL_LOCAL_RENDER_BINARY="$PWD/.blackbox/release-artifacts-22dae7d0/lmyzmail"
export LMYZMAIL_LOCAL_RENDER_CAPABILITIES="$PWD/evidence/compatibility/renderer-local-22dae7d0/capabilities.json"
export LMYZMAIL_LOCAL_RENDER_OUTPUT="$PWD/evidence/compatibility/renderer-local-22dae7d0"
.blackbox/venv/bin/python -m pytest -c blackbox/pyproject.toml \
    -p release_campaign tools/test_renderer_local_release.py -q \
    --junitxml=evidence/compatibility/renderer-local-22dae7d0/result-v2.xml \
    2>&1 | tee evidence/compatibility/renderer-local-22dae7d0/result-v2.log
