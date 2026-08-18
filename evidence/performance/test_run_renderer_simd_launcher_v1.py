from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
from pathlib import Path
from types import ModuleType

import pytest


REPOSITORY = Path(__file__).resolve().parents[2]


def _load(relative: str, name: str) -> ModuleType:
    path = REPOSITORY / relative
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


RUNNER = _load(
    "evidence/performance/renderer_simd_runner_v2.py", "renderer_simd_runner_v2_test"
)
E2E = _load(
    "evidence/performance/run-renderer-e2e-matrix-v1.py", "renderer_e2e_runner_v1_test"
)


def _formal_contract() -> dict[str, object]:
    return {
        "input": "crates/lmyzmail/assets/skibidi_toilet_episode_1.mp4",
        "frame_index": 0,
        "sizes": [64, 128, 256, 512],
        "contrast": 1.2,
        "dithers": [0, 1, 2],
        "warmup": 5,
        "iterations": 30,
        "rounds": 6,
    }


def _report(backend: str, dither: int) -> dict[str, object]:
    timing = {"scalar": 1_000, "avx2+fma": 700, "avx512f": 600}[backend]
    sizes = []
    for edge in RUNNER.SIZES:
        stages = []
        for stage in RUNNER.STAGES:
            if stage == "block_states" and edge * edge > RUNNER.BLOCK_STATES_LIMIT:
                stages.append(
                    {
                        "stage": stage,
                        "status": "not_applicable",
                        "reason": "pixel count exceeds MAX_BLOCK_PIXELS=4096; production does not chunk block frames",
                    }
                )
                continue
            stages.append(
                {
                    "stage": stage,
                    "status": "timed",
                    "output_sha256": "b" * 64,
                    "measured_output_hash_validation": "passed",
                    "measured_iterations_hashed": 30,
                    "median_ns": timing,
                    "p95_ns": timing,
                    "samples_ns": [timing] * 30,
                }
            )
        sizes.append({"edge": edge, "pixels": edge * edge, "stages": stages})
    return {
        "schema": RUNNER.BENCHMARK_SCHEMA,
        "status": "ok",
        "requested_backend": backend,
        "resolved_backend": backend,
        "fallback_used": False,
        "host_capabilities": {"avx2": True, "fma": True, "avx512f": True},
        "unsupported_reason": None,
        "input": "/tmp/pinned-asset",
        "frame_index": 0,
        "frame": {"width": 1920, "height": 1080, "rgb24_sha256": "a" * 64},
        "parameters": {
            "contrast": 1.2,
            "dither": dither,
            "warmup": 5,
            "iterations": 30,
            "timing_unit": "nanoseconds",
            "p95_method": "nearest-rank",
        },
        "sizes": sizes,
    }


def _formal_evidence() -> dict[str, object]:
    reports = []
    records = []
    rounds = []
    for round_index in range(6):
        orders = []
        for dither_index, dither in enumerate(RUNNER.DITHERS):
            rotation = (round_index + dither_index) % len(RUNNER.BACKENDS)
            order = RUNNER.BACKENDS[rotation:] + RUNNER.BACKENDS[:rotation]
            orders.append({"dither": dither, "backend_order": list(order)})
            for position, backend in enumerate(order):
                records.append(
                    {
                        "report_index": len(reports),
                        "round_index": round_index,
                        "dither": dither,
                        "position": position,
                        "backend": backend,
                    }
                )
                reports.append(_report(backend, dither))
        rounds.append(
            {
                "round_index": round_index,
                "orders": orders,
                "telemetry_pre": {},
                "telemetry_post": {},
            }
        )
    aggregate = RUNNER.aggregate_medians(records, reports, 6)
    performance = RUNNER.evaluate_performance(aggregate)
    scalar_hashes = {
        dither: RUNNER.output_hashes(_report("scalar", dither)) for dither in RUNNER.DITHERS
    }
    return {
        "schema": RUNNER.SCHEMA,
        "profile": "formal",
        "status": "passed",
        "formal_contract": _formal_contract(),
        "round_count": 6,
        "benchmark_reports": reports,
        "run_records": records,
        "benchmark_rounds": rounds,
        "cross_round_medians": aggregate,
        "performance_gate": performance,
        "cross_backend_hashes": {
            "status": "passed",
            "baseline": "scalar",
            "hashes_by_dither": scalar_hashes,
            "mismatches": [],
        },
        "artifacts": {
            "asset": {"path": "/tmp/asset", "benchmark_input": "/tmp/pinned-asset", "sha256": "c" * 64}
        },
    }


def test_formal_matrix_is_fixed_and_not_cli_shrinkable() -> None:
    assert RUNNER.DITHERS == (0, 1, 2)
    assert RUNNER.SIZES == (64, 128, 256, 512)
    assert RUNNER.FORMAL_WARMUP == 5
    assert RUNNER.FORMAL_ITERATIONS == 30
    assert RUNNER.FORMAL_ROUNDS == 6
    source = (REPOSITORY / "evidence/performance/renderer_simd_runner_v2.py").read_text(
        encoding="utf-8"
    )
    parser_section = source[source.index("def run()") : source.index("arguments = parser.parse_args()")]
    for forbidden in (
        "--input",
        "--frame-index",
        "--sizes",
        "--contrast",
        "--dither",
        "--warmup",
        "--iterations",
        "--rounds",
    ):
        assert forbidden not in parser_section


def test_shell_entrypoint_only_execs_qualified_runner() -> None:
    source = (REPOSITORY / "evidence/performance/run-renderer-simd-v1.sh").read_text(
        encoding="utf-8"
    )
    assert "set -euo pipefail" in source
    assert 'exec python3 "${script_dir}/renderer_simd_runner_v2.py" "$@"' in source


def _aggregate(candidate_avx2: int, candidate_avx512: int) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    keys = [(0, 64, stage) for stage in (
        "resize",
        "contrast",
        "block_palette_rgb",
        "map_palette",
        "block_states",
    )]
    keys.extend(((1, 64, "map_palette"), (2, 64, "map_palette")))
    for backend, value in (
        ("scalar", 1_000),
        ("avx2+fma", candidate_avx2),
        ("avx512f", candidate_avx512),
    ):
        for dither, edge, stage in keys:
            rows.append(
                {
                    "backend": backend,
                    "dither": dither,
                    "edge": edge,
                    "stage": stage,
                    "cross_round_median_ns": value,
                    "cross_round_p95_ns": value + 50,
                }
            )
    return rows


def test_performance_gate_requires_case_family_palette_and_overall_results() -> None:
    passed = RUNNER.evaluate_performance(_aggregate(700, 600))
    assert passed["status"] == "passed"
    assert all(result["overall"]["status"] == "passed" for result in passed["backends"])
    assert all(result["palette"]["status"] == "passed" for result in passed["backends"])

    failed = RUNNER.evaluate_performance(_aggregate(1_400, 1_400))
    assert failed["status"] == "failed"
    scopes = {failure["scope"] for failure in failed["failures"]}
    assert {"case", "family", "overall", "palette"}.issubset(scopes)


def test_atomic_publish_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "renderer.json"
    RUNNER.atomic_publish(output, {"schema": "test", "status": "passed"})
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "passed"
    with pytest.raises(RUNNER.RunnerError, match="overwrite"):
        RUNNER.atomic_publish(output, {"status": "changed"})
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "passed"

    e2e_output = tmp_path / "renderer-e2e.json"
    E2E.atomic_publish(e2e_output, {"schema": "e2e", "status": "passed"})
    with pytest.raises(E2E.EvidenceError, match="overwrite"):
        E2E.atomic_publish(e2e_output, {"status": "changed"})


def test_unsupported_probe_has_separate_nonpassing_contract() -> None:
    source = (REPOSITORY / "evidence/performance/renderer_simd_runner_v2.py").read_text(
        encoding="utf-8"
    )
    assert RUNNER.PROBE_SCHEMA != RUNNER.SCHEMA
    assert 'status = "unsupported_observed"' in source
    assert "formal evidence requires real Scalar, AVX2+FMA, and AVX-512F" in source


def test_e2e_validator_requires_every_real_backend_and_dither() -> None:
    evidence = _formal_evidence()
    assert E2E.validate_renderer_evidence(evidence) == {
        "SCALAR": "scalar",
        "AVX2": "avx2+fma",
        "AVX512": "avx512f",
    }
    evidence["benchmark_reports"][-1]["status"] = "unsupported"
    with pytest.raises(E2E.EvidenceError, match="formal report did not truly execute"):
        E2E.validate_renderer_evidence(evidence)


@pytest.mark.parametrize("constant", ("NaN", "Infinity", "-Infinity"))
def test_strict_json_rejects_non_finite_numbers(constant: str) -> None:
    with pytest.raises(RUNNER.RunnerError, match="non-finite"):
        RUNNER.strict_json_bytes(f'{{"value":{constant}}}'.encode(), label="forged")


def test_strict_json_rejects_duplicate_object_keys() -> None:
    with pytest.raises(RUNNER.RunnerError, match="duplicate JSON object key"):
        RUNNER.strict_json_bytes(b'{"value":1,"value":2}', label="forged")


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (lambda report: report["parameters"].__setitem__("iterations", True), "booleans"),
        (lambda report: report["sizes"][0]["stages"][0]["samples_ns"].__setitem__(0, 0), "positive"),
        (lambda report: report["sizes"][0]["stages"][0]["samples_ns"].__setitem__(0, -1), "positive"),
        (lambda report: report["sizes"][0]["stages"][0].__setitem__("median_ns", 999), "median/P95"),
        (lambda report: report["sizes"][0]["stages"][0].pop("p95_ns"), "object fields changed"),
        (lambda report: report["sizes"][0].__setitem__("pixels", 63), "pixel count"),
        (lambda report: report["sizes"][0]["stages"][0].__setitem__("stage", "forged"), "stage"),
    ),
)
def test_raw_report_recomputation_rejects_forged_fields(mutation: object, message: str) -> None:
    evidence = _formal_evidence()
    report = evidence["benchmark_reports"][0]
    mutation(report)
    with pytest.raises(E2E.EvidenceError, match=message):
        E2E.validate_renderer_evidence(evidence)


def test_formal_matrix_rejects_selective_missing_and_duplicate_cases() -> None:
    missing = _formal_evidence()
    missing["benchmark_reports"].pop()
    with pytest.raises(E2E.EvidenceError, match="missing or duplicate"):
        E2E.validate_renderer_evidence(missing)

    duplicate = _formal_evidence()
    duplicate["run_records"][1] = copy.deepcopy(duplicate["run_records"][0])
    with pytest.raises(E2E.EvidenceError, match="selective, duplicate, or reordered"):
        E2E.validate_renderer_evidence(duplicate)

    forged_gate = _formal_evidence()
    forged_gate["performance_gate"]["status"] = "failed"
    with pytest.raises(E2E.EvidenceError, match="disagrees with recomputation"):
        E2E.validate_renderer_evidence(forged_gate)


def test_performance_gate_rejects_large_case_masking_small_regressions() -> None:
    aggregate = _aggregate(700, 600)
    for row in aggregate:
        if row["backend"] != "scalar" and row["edge"] == 64:
            row["cross_round_median_ns"] = 1_001
            row["cross_round_p95_ns"] = 1_051
    for backend in RUNNER.BACKENDS:
        value = 1_000_000 if backend == "scalar" else 1
        aggregate.append(
            {
                "backend": backend,
                "dither": 0,
                "edge": 512,
                "stage": "resize",
                "cross_round_median_ns": value,
                "cross_round_p95_ns": value,
            }
        )
    result = RUNNER.evaluate_performance(aggregate)
    assert result["status"] == "failed"
    assert any(failure["scope"] == "case" for failure in result["failures"])


def test_pinned_file_rejects_symlink_and_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}\n", encoding="utf-8")
    link = tmp_path / "link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pass
    else:
        with pytest.raises(RUNNER.RunnerError, match="symbolic"):
            RUNNER.PinnedFile(link, label="artifact")

    with RUNNER.PinnedFile(target, label="artifact") as pinned:
        original_stat = RUNNER.os.stat

        def replaced(path: object, *args: object, **kwargs: object) -> object:
            value = original_stat(path, *args, **kwargs)
            if Path(path) == target:
                values = list(value)
                values[1] += 1
                return os.stat_result(values)
            return value

        monkeypatch.setattr(RUNNER.os, "stat", replaced)
        with pytest.raises(RUNNER.RunnerError, match="replaced"):
            pinned.verify("post-run")


@pytest.mark.parametrize("relative", ("../secret", "/etc/passwd", "a/../secret", "./file"))
def test_source_snapshot_rejects_repository_path_escape(relative: str, tmp_path: Path) -> None:
    with pytest.raises(RUNNER.RunnerError, match="repository-relative"):
        RUNNER.repository_file_path(tmp_path, relative, label="forged source")


def _observer_event(component: str, sequence: int = 1) -> dict[str, object]:
    return {
        "schema": E2E.OBSERVER_SCHEMA,
        "sequence": sequence,
        "component": component,
        "requested_mode": "SCALAR",
        "requested_backend": "scalar",
        "resolved_backend": "scalar",
        "host_capabilities": {"avx2": True, "fma": True, "avx512f": True},
        "source_sha256": "a" * 64,
        "build_sha256": "b" * 64,
        "session": "c" * 64,
    }


def _observer_bytes(events: list[dict[str, object]]) -> bytes:
    return b"".join(json.dumps(event, separators=(",", ":")).encode() + b"\n" for event in events)


def test_observer_rejects_partial_duplicate_and_forged_components() -> None:
    components = sorted(E2E.EXPECTED_COMPONENTS["minecraft-video"])
    events = [_observer_event(component, index + 1) for index, component in enumerate(components)]
    common = {
        "scenario": "minecraft-video",
        "expected_mode": "SCALAR",
        "expected_backend": "scalar",
        "expected_capabilities": {"avx2": True, "fma": True, "avx512f": True},
        "source_sha256": "a" * 64,
        "build_sha256": "b" * 64,
        "session": "c" * 64,
    }
    assert len(E2E.validate_observer_events(_observer_bytes(events), **common)) == len(components)

    with pytest.raises(E2E.EvidenceError, match="event count"):
        E2E.validate_observer_events(_observer_bytes(events[:-1]), **common)
    duplicated = copy.deepcopy(events)
    duplicated[1]["component"] = duplicated[0]["component"]
    with pytest.raises(E2E.EvidenceError, match="duplicate"):
        E2E.validate_observer_events(_observer_bytes(duplicated), **common)
    forged = copy.deepcopy(events)
    forged[0]["component"] = "forged.component"
    with pytest.raises(E2E.EvidenceError, match="forged"):
        E2E.validate_observer_events(_observer_bytes(forged), **common)
    reordered = copy.deepcopy(events)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    with pytest.raises(E2E.EvidenceError, match="out of order"):
        E2E.validate_observer_events(_observer_bytes(reordered), **common)


def test_observer_backpressure_and_default_dormancy_are_fail_closed() -> None:
    source = (REPOSITORY / "crates/lmyzmail/src/dispatch_observer.rs").read_text(
        encoding="utf-8"
    )
    assert "O_NONBLOCK" in source
    assert "fetch_or(component.bit()" in source
    assert "LMYZMAIL_RENDER_OBSERVER_FD" in source
    assert "get_or_init(Observer::from_environment)" in source
    assert "paths are deliberately unsupported" in source
    with pytest.raises(E2E.EvidenceError, match="empty"):
        E2E.validate_observer_events(
            b"",
            scenario="minecraft-mail-view",
            expected_mode="SCALAR",
            expected_backend="scalar",
            expected_capabilities={"avx2": True, "fma": True, "avx512f": True},
            source_sha256="a" * 64,
            build_sha256="b" * 64,
            session="c" * 64,
        )


def test_e2e_digest_collection_keeps_pixels_frames_and_histograms() -> None:
    observation = {
        "frame": {"length": 32, "sha256": "a" * 64},
        "page": {
            "pixels": {"length": 16384, "sha256": "b" * 64},
            "palette_counts": [[4, 10], [34, 20]],
        },
    }
    collected = E2E.collect_render_digests(observation)
    paths = {item["path"] for item in collected}
    assert "$.frame" in paths
    assert "$.page.pixels" in paths
    assert "$.page.palette_counts" in paths


def test_e2e_status_normalization_removes_only_published_renderer_artifact(
    tmp_path: Path,
) -> None:
    subprocess.check_call(("git", "init", "-q"), cwd=tmp_path)
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("frozen\n", encoding="utf-8")
    subprocess.check_call(("git", "add", "tracked.txt"), cwd=tmp_path)
    evidence = tmp_path / "renderer.json"
    evidence.write_text("{}\n", encoding="utf-8")
    assert E2E.normalized_status_bytes(tmp_path, (evidence,)) == b"A  tracked.txt\0"
    unrelated = tmp_path / "other.txt"
    unrelated.write_text("unexpected\n", encoding="utf-8")
    normalized = E2E.normalized_status_bytes(tmp_path, (evidence,))
    assert b"?? other.txt\0" in normalized


def test_e2e_wrapper_forces_backends_without_mutating_golden_definitions() -> None:
    mail = (REPOSITORY / "blackbox/tools/test_minecraft_mail_view.py").read_text(
        encoding="utf-8"
    )
    video = (REPOSITORY / "blackbox/tools/test_minecraft_video.py").read_text(
        encoding="utf-8"
    )
    assert "LMYZMAIL_RENDERER_SIMD_MATRIX" not in mail + video
    source = (REPOSITORY / "evidence/performance/run-renderer-e2e-matrix-v1.py").read_text(
        encoding="utf-8"
    )
    assert 'f"--lmyzmail.mailrender.simd-mode={mode}"' in source
    assert "original_scenario.capture(target)" in source
    assert ").verify_candidate((wrapped,), candidate)" in source
