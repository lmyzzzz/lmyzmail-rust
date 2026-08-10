from __future__ import annotations

# All subprocess argv values are the pinned local compiler, frozen sources, or
# executables built into pytest's private temporary directory.
# ruff: noqa: S603
import json
import os
import platform
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = ROOT / "native/lmyzmail-skibidi/upstream"
SOURCE = SOURCE_ROOT / "skibidi_avx.c"
UPSTREAM_TEST = SOURCE_ROOT / "tests/test_skibidi.c"
PROBE = ROOT / "native/lmyzmail-skibidi/tests/abi_probe.c"
GOLDEN = ROOT / "blackbox/golden/native/skibidi-1.8.0-v1/contract.json"


def _cpu_flags() -> frozenset[str]:
    flags: set[str] = set()
    for line in Path("/proc/cpuinfo").read_text(encoding="ascii").splitlines():
        if line.startswith("flags"):
            flags.update(line.partition(":")[2].split())
            break
    return frozenset(flags)


def _compile(
    output: Path,
    extra_flags: tuple[str, ...],
    *sources: Path,
) -> None:
    command = [
        os.environ.get("CC", "cc"),
        "-std=c11",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        f"-I{SOURCE_ROOT}",
        *extra_flags,
        *(str(source) for source in sources),
        "-lm",
        "-pthread",
        "-o",
        str(output),
    ]
    subprocess.run(command, check=True, timeout=60)


def _run_json(executable: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [str(executable)],
        check=True,
        capture_output=True,
        text=True,
        encoding="ascii",
        timeout=30,
    )
    payload = json.loads(completed.stdout)
    if not isinstance(payload, dict):
        raise AssertionError("native Skibidi probe did not return a JSON object")
    return cast(dict[str, Any], payload)


def _assert_contract(payload: dict[str, Any], expected_simd: str) -> None:
    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["version"] == expected["abi"]["version"]
    assert payload["layout"] == {
        "rng_size": expected["abi"]["rng_size"],
        "context_size": expected["abi"]["context_size"],
        "context_alignment": expected["abi"]["context_alignment"],
    }
    assert payload["runtime"]["active_simd"] == expected_simd
    assert isinstance(payload["runtime"]["capabilities"], int)
    assert payload["configuration"]["configure_result"] == 0
    assert payload["configuration"]["get_result"] == 0
    assert (
        payload["configuration"]["enable_avx512"]
        == expected["configuration"]["enable_avx512_by_backend"][expected_simd]
    )
    assert payload["configuration"]["enable_simd_rng"] == 1
    assert payload["allocation"] == expected["allocation"]
    assert payload["errors"] == expected["errors"]
    assert payload["single_seed_0"] == expected["single_seed_0"]
    assert payload["single_seed_123456789abcdef0"] == expected["single_seed_123456789abcdef0"]
    assert payload["variant_seed_fedcba9876543210"] == expected["variant_seed_fedcba9876543210"]
    assert payload["batch_scalar_seed_42"] == expected["batch_scalar_seed_42"]
    expected_simd_batch = (
        expected["batch_scalar_seed_42"]
        if expected_simd == "Scalar"
        else expected["batch_vector_seed_42"]
    )
    assert payload["batch_simd_seed_42"] == expected_simd_batch
    assert payload["destroy_zeroed"] is expected["destroy_zeroed"]


def _run_sanitized_distribution(executable: Path) -> None:
    environment = {
        **os.environ,
        "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=1:strict_string_checks=1",
        "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
        "SKIBIDI_DISTRIBUTION_SAMPLES": "1000000",
    }
    completed = subprocess.run(
        [str(executable)],
        check=True,
        capture_output=True,
        text=True,
        encoding="ascii",
        env=environment,
        timeout=120,
    )
    assert completed.stdout == (
        "PASS: API, RNG lifetime, distributions, and batch paths distribution_samples=1000000\n"
    )


def test_frozen_skibidi_scalar_abi_seed_and_batch_contract(tmp_path: Path) -> None:
    assert platform.machine() == "x86_64"
    executable = tmp_path / "probe-scalar"
    _compile(executable, (), SOURCE, PROBE)
    _assert_contract(_run_json(executable), "Scalar")


def test_frozen_skibidi_avx2_abi_seed_and_batch_contract(tmp_path: Path) -> None:
    assert platform.machine() == "x86_64"
    executable = tmp_path / "probe-avx2"
    _compile(executable, ("-mavx2",), SOURCE, PROBE)
    if "avx2" not in _cpu_flags():
        assert executable.is_file()
        return
    payload = _run_json(executable)
    assert payload["runtime"]["has_avx2"] is True
    _assert_contract(payload, "AVX2")


def test_frozen_skibidi_avx512_is_never_executed_without_os_support(
    tmp_path: Path,
) -> None:
    assert platform.machine() == "x86_64"
    executable = tmp_path / "probe-avx512"
    _compile(executable, ("-mavx2", "-mavx512f"), SOURCE, PROBE)
    if not {"avx2", "avx512f"}.issubset(_cpu_flags()):
        assert executable.is_file()
        return
    payload = _run_json(executable)
    assert payload["runtime"]["has_avx512"] is True
    _assert_contract(payload, "AVX-512")


@pytest.mark.integration
def test_frozen_skibidi_scalar_asan_ubsan_and_distribution(tmp_path: Path) -> None:
    executable = tmp_path / "test-sanitized"
    _compile(
        executable,
        (
            "-O1",
            "-g",
            "-fno-omit-frame-pointer",
            "-fsanitize=address,undefined",
        ),
        SOURCE,
        UPSTREAM_TEST,
    )
    _run_sanitized_distribution(executable)


@pytest.mark.integration
def test_frozen_skibidi_avx2_asan_ubsan_and_distribution(tmp_path: Path) -> None:
    assert platform.machine() == "x86_64"
    executable = tmp_path / "test-avx2-sanitized"
    _compile(
        executable,
        (
            "-O1",
            "-g",
            "-fno-omit-frame-pointer",
            "-fsanitize=address,undefined",
            "-mavx2",
        ),
        SOURCE,
        UPSTREAM_TEST,
    )
    if "avx2" not in _cpu_flags():
        assert executable.is_file()
        return
    _run_sanitized_distribution(executable)
