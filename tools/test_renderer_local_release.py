"""Local Scalar/AVX2 wire and pixel checks; does not qualify the full SIMD gate."""
from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import secrets
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "renderer_e2e", ROOT / "evidence/performance/run-renderer-e2e-matrix-v1.py"
)
assert SPEC is not None and SPEC.loader is not None
E2E = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(E2E)


@pytest.mark.parametrize("scenario,profile", E2E.TESTS)
def test_local_renderer_matches_java_and_scalar(scenario, profile):
    binary = Path(os.environ["LMYZMAIL_LOCAL_RENDER_BINARY"]).resolve(strict=True)
    capabilities_path = Path(os.environ["LMYZMAIL_LOCAL_RENDER_CAPABILITIES"])
    capabilities = json.loads(capabilities_path.read_text())["host_capabilities"]
    assert capabilities["avx2"] and capabilities["fma"]
    output = Path(os.environ["LMYZMAIL_LOCAL_RENDER_OUTPUT"]) / f"{scenario}.json"
    assert not output.exists()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    assert not subprocess.check_output(["git", "diff", "HEAD", "--", "crates", "Cargo.lock", ".cargo"], cwd=ROOT)
    source_digest = E2E.sha256_bytes(head.encode() + (ROOT / "Cargo.lock").read_bytes())
    mail_view, video, runner, scenario_type, candidate_runtime, runtime_module = E2E._load_blackbox()
    module = video if scenario == "minecraft-video" else mail_view
    original = module.SCENARIOS[0]
    observations = {}
    runs = []
    with contextlib.ExitStack() as resources:
        binary_pin = E2E.RENDERER_VERIFIER.PinnedFile(binary, label="local candidate", executable=True)
        resources.callback(binary_pin.close)
        for mode, backend in (("SCALAR", "scalar"), ("AVX2", "avx2+fma")):
            captured = {}

            def capture(target):
                captured["observation"] = original.capture(target)
                return captured["observation"]

            wrapped = scenario_type(original.name, capture, normalizers=original.normalizers, contract=original.contract)
            observer = E2E.ObserverPipe()
            session = secrets.token_hex(32)
            runtime = E2E._candidate_runtime(
                scenario, binary_pin, mode, candidate_runtime, observer,
                source_sha256=source_digest, session=session,
            )
            lock = mail_view._renderer_capture_lock() if scenario == "minecraft-mail-view" else contextlib.nullcontext()
            try:
                with E2E.candidate_process_with_fds(runtime_module, observer, binary_pin.descriptor):
                    with E2E.scenario_deadline(1800), lock, runtime as candidate:
                        runner(ROOT, ROOT / "blackbox/golden/java" / profile, profile).verify_candidate((wrapped,), candidate)
                events = E2E.validate_observer_events(
                    observer.finish(), scenario=scenario, expected_mode=mode,
                    expected_backend=backend, expected_capabilities=capabilities,
                    source_sha256=source_digest, build_sha256=binary_pin.sha256, session=session,
                )
            finally:
                observer.close()
            observations[mode] = captured["observation"]
            runs.append({"mode": mode, "backend": backend, "dispatch": events,
                         "observation_sha256": E2E.sha256_bytes(E2E.canonical_bytes(observations[mode])),
                         "render_digests": E2E.collect_render_digests(observations[mode])})
            binary_pin.verify(mode)
        assert observations["SCALAR"] == observations["AVX2"]
        assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() == head
        assert not subprocess.check_output(["git", "diff", "HEAD", "--", "crates", "Cargo.lock", ".cargo"], cwd=ROOT)
        E2E.atomic_publish(output, {
            "schema": "lmyzmail.renderer-local-e2e.v1", "status": "passed",
            "full_simd_acceptance": False, "unverified_backend": "avx512f",
            "git_head": head, "binary_sha256": binary_pin.sha256,
            "capabilities": capabilities, "scenario": scenario,
            "attribution_digest_basis": "Git HEAD and Cargo.lock; tracked source verified unchanged",
            "source_sha256": source_digest, "runs": runs,
        })
