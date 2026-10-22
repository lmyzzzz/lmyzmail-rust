#!/usr/bin/env bash
set -euo pipefail
cd /home/lmyzzz/lmyzmail-rust
[[ ${EUID} -eq 0 ]] || { echo 'run as root via the isolated launcher' >&2; exit 2; }

# This orchestration changes no profile, count, assertion or resource ceiling.
# Keep the packaged ELF, completed replay and independent soak as prerequisites.
.blackbox/venv/bin/python - <<'PY'
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path

binary = Path("target/x86_64-unknown-linux-gnu/release/lmyzmail")
with binary.open("rb") as stream:
    assert hashlib.file_digest(stream, "sha256").hexdigest() == (
        "78a4c31145010e479ec64a9e0a2f3ac767b2860e32180100cad699a155c37790")
for name, count in (("release-oracle-20261023-full-v3.xml", 107),
                    ("release-22dae7d0-candidate-v2.xml", 126)):
    suites = list(ET.parse(Path("evidence/compatibility") / name).getroot().iter("testsuite"))
    assert sum(int(s.get("tests", 0)) for s in suites) == count
    assert not sum(int(s.get(key, 0)) for s in suites
                   for key in ("failures", "errors", "skipped"))
soak = json.loads(Path("evidence/compatibility/candidate-soak-22dae7d0-20261023-v2.json").read_text())
assert soak["status"] == "passed" and soak["qualification"]["qualified_half_hour"]
PY

for mode in off on; do
    # 10 MiB uses the original runner's disk-budgeted count. It is never Java.
    # Each small tier invokes 250,000 then 100,000 more in the same process.
    for tier in 10mb 1kb 10kb; do
        output="evidence/performance/release-22dae7d0-formal-${mode}-${tier}.json"
        console="evidence/performance/release-22dae7d0-formal-${mode}-${tier}.console.log"
        [[ ! -e "$output" && ! -e "$console" ]] || {
            echo "refusing to overwrite existing formal evidence: $output" >&2
            exit 2
        }
        bash evidence/performance/run-smtp-endpoint-throughput-v1.sh \
            --profile candidate-stability --target rust --tier "$tier" \
            --rust-filesystem-fsync "$mode" --disk-budget-gib 20 \
            --output "$output" 2>&1 | tee "$console"
    done
done
