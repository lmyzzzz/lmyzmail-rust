#!/usr/bin/env python3
"""Record available Scalar/AVX2 performance without relaxing the full SIMD gate."""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "renderer_verifier", ROOT / "evidence/performance/renderer_simd_runner_v2.py"
)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cpu", type=int)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(exist_ok=False)
    binary = args.binary.resolve(strict=True)
    asset = ROOT / "crates/lmyzmail/assets/skibidi_toilet_episode_1.mp4"
    cpu, _, _ = VERIFIER.select_cpu(args.cpu)
    identity = {"binary": VERIFIER.sha256_file(binary), "asset": VERIFIER.sha256_file(asset)}
    before = VERIFIER.source_snapshot(ROOT)
    records, reports, hashes, telemetry = [], [], {}, []
    for round_index in range(VERIFIER.FORMAL_ROUNDS):
        backends = ("scalar", "avx2+fma") if round_index % 2 == 0 else ("avx2+fma", "scalar")
        for dither in VERIFIER.DITHERS:
            for backend in backends:
                report_path = output / f"round-{round_index}-{dither}-{backend}.json"
                command = ["taskset", "-c", str(cpu), str(binary), "--input", str(asset),
                           "--backend", backend, "--dither", str(dither), "--warmup", "5",
                           "--iterations", "30", "--output", str(report_path)]
                telemetry.append(VERIFIER.capture_telemetry(cpu, report_path.stem))
                subprocess.run(command, check=True, timeout=300, cwd=ROOT)
                report = json.loads(report_path.read_text())
                VERIFIER.verify_benchmark_report(
                    report, expected_backend=backend,
                    expected_dither=dither, expected_input=str(asset),
                    expected_warmup=5, expected_iterations=30, require_timed=True,
                )
                observed = VERIFIER.output_hashes(report)
                if dither in hashes:
                    assert hashes[dither] == observed, (dither, backend, round_index)
                else:
                    hashes[dither] = observed
                records.append({"round_index": round_index, "path": str(report_path),
                                "sha256": VERIFIER.sha256_file(report_path), "command": command})
                reports.append(report)
    after = VERIFIER.source_snapshot(ROOT)
    assert before["head"] == after["head"]
    assert before["source_files"] == after["source_files"]
    assert identity == {"binary": VERIFIER.sha256_file(binary), "asset": VERIFIER.sha256_file(asset)}
    aggregate = VERIFIER.aggregate_medians(records, reports, VERIFIER.FORMAL_ROUNDS)
    by_case = {(entry["backend"], entry["dither"], entry["edge"], entry["stage"]): entry
               for entry in aggregate}
    comparisons = []
    for entry in aggregate:
        if entry["backend"] != "scalar":
            continue
        accelerated = by_case[("avx2+fma", entry["dither"], entry["edge"], entry["stage"])]
        comparisons.append({"dither": entry["dither"], "edge": entry["edge"], "stage": entry["stage"],
                            "median_speedup": entry["cross_round_median_ns"] / accelerated["cross_round_median_ns"],
                            "p95_speedup": entry["cross_round_p95_ns"] / accelerated["cross_round_p95_ns"]})
    VERIFIER.atomic_publish(output / "summary.json", {
        "schema": "lmyzmail.renderer-local-performance.v1", "status": "recorded",
        "generated_utc": dt.datetime.now(dt.UTC).isoformat(), "full_simd_acceptance": False,
        "unverified_backend": "avx512f", "host_sharing": "Other acceptance processes may be active; local comparative evidence only",
        "cpu": cpu, "git_head": before["head"], "source_sha256": before["source_sha256"],
        "source_files": before["source_files"], "binary_sha256": identity["binary"],
        "asset_sha256": identity["asset"], "rounds": VERIFIER.FORMAL_ROUNDS,
        "host_capabilities": reports[0]["host_capabilities"], "correctness": "all measured output hashes identical across rounds/backends",
        "records": records, "aggregate": aggregate, "comparisons": comparisons, "telemetry": telemetry,
    })


if __name__ == "__main__":
    main()
