from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
from pathlib import Path

from lmyzmail_blackbox.golden import GoldenAttestation, GoldenStore, canonical_json


repository = Path(__file__).resolve().parents[2]
source = (
    repository
    / "evidence/compatibility/report-trigger-concurrency-v1/test_report_trigger_concurrency.py"
)
generation = repository / "evidence/compatibility/report-trigger-concurrency-v3"
if generation.exists():
    raise FileExistsError(f"report concurrency v3 already exists: {generation}")

spec = importlib.util.spec_from_file_location("report_concurrency", source)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory(prefix="lmyzmail-report-concurrency-v3-") as temporary:
    temporary_root = Path(temporary)
    with module.report_dns_server() as dns:
        with module._ConcurrencyJavaRuntime(temporary_root / "java", dns) as runtime:
            java_observation = module._capture_concurrent_trigger(runtime)
    with module.report_dns_server() as dns:
        with module._candidate(repository, dns) as runtime:
            candidate_observation = module._capture_concurrent_trigger(runtime)

java_bytes = canonical_json(java_observation)
candidate_bytes = canonical_json(candidate_observation)
if candidate_bytes != java_bytes:
    raise AssertionError(
        "report concurrency Java/Rust observation mismatch: "
        f"java={hashlib.sha256(java_bytes).hexdigest()}, "
        f"candidate={hashlib.sha256(candidate_bytes).hexdigest()}"
    )

attestation = GoldenAttestation.from_repository(
    repository,
    profile="report-trigger-concurrency-v3",
    normalizers=module._NORMALIZERS,
)
generation.mkdir(parents=True, exist_ok=False)
store = GoldenStore(generation / "golden", attestation, record=True)
store.assert_observation("observation.json", java_observation)
GoldenStore(generation / "golden", attestation).assert_observation(
    "observation.json",
    candidate_observation,
)

golden_path = generation / "golden/observation.json"
release_path = repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"
metadata = {
    "schema_version": 1,
    "profile": "report-trigger-concurrency-v3",
    "definition_tree_sha256": attestation.harness_definition_sha256,
    "oracle": {
        "commit": attestation.oracle_commit,
        "jar_sha256": attestation.oracle_jar_sha256,
    },
    "candidate_release_sha256": hashlib.sha256(release_path.read_bytes()).hexdigest(),
    "normalizers": list(module._NORMALIZERS),
    "java_observation_sha256": hashlib.sha256(java_bytes).hexdigest(),
    "candidate_observation_sha256": hashlib.sha256(candidate_bytes).hexdigest(),
    "golden_envelope_sha256": hashlib.sha256(golden_path.read_bytes()).hexdigest(),
    "java_candidate_observations_equal": True,
    "older_generations_modified": False,
    "source": "fresh Java oracle capture and independent locked Rust release capture",
}
with (generation / "evidence.json").open("x", encoding="utf-8", newline="\n") as stream:
    json.dump(metadata, stream, ensure_ascii=False, sort_keys=True, indent=2)
    stream.write("\n")
print(json.dumps(metadata, ensure_ascii=False, sort_keys=True, indent=2))
