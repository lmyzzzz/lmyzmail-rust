from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from lmyzmail_blackbox.golden import GoldenAttestation, GoldenStore

repository = Path("/home/lmyzzz/lmyzmail-rust")
source = repository / "evidence/compatibility/report-trigger-concurrency-v1/test_report_trigger_concurrency.py"
spec = importlib.util.spec_from_file_location("report_concurrency", source)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
with module.report_dns_server() as dns:
    with module._candidate(repository, dns) as runtime:
        observed = module._capture_concurrent_trigger(runtime)
attestation = GoldenAttestation.from_repository(
    repository,
    profile="report-trigger-concurrency-v2",
    normalizers=module._NORMALIZERS,
)
store = GoldenStore(repository / "evidence/compatibility/report-trigger-concurrency-v2/golden", attestation)
path = store.root / "observation.json"
path.parent.mkdir(parents=True, exist_ok=True)
path.write_bytes(store._envelope(observed))
metadata = {
    "schema_version": 1,
    "profile": "report-trigger-concurrency-v2",
    "definition_tree_sha256": attestation.harness_definition_sha256,
    "observation_sha256": __import__("hashlib").sha256(path.read_bytes()).hexdigest(),
    "source": "candidate replay with v1 business observation matched; v2 refreshes only stale harness attestation",
    "oracle_golden_modified": False,
}
(repository / "evidence/compatibility/report-trigger-concurrency-v2/evidence.json").write_text(
    json.dumps(metadata, sort_keys=True, indent=2) + "\n", encoding="utf-8"
)
print(json.dumps(metadata, sort_keys=True, indent=2))
