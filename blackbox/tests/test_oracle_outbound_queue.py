from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from lmyzmail_blackbox.golden import GoldenAttestation, GoldenStore


def _repository() -> Path:
    return Path(__file__).resolve().parents[2]


def _run_probe(repository: Path, *, target: str) -> dict[str, object]:
    result = subprocess.run(  # noqa: S603,S607
        [
            "/bin/bash",
            str(repository / "blackbox/bin/run-outbound-probe.sh"),
        ],
        cwd=repository,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "LMYZMAIL_BLACKBOX_PYTHON": sys.executable,
            "LMYZMAIL_OUTBOUND_TARGET": target,
        },
        timeout=170,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            "outbound probe failed with "
            f"{result.returncode}:\nstdout={result.stdout}\nstderr={result.stderr}"
        )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise AssertionError(f"outbound probe returned a non-object: {value!r}")
    return value


def _assert_golden(
    repository: Path,
    observed: dict[str, object],
    *,
    record_java: bool,
) -> None:
    path = repository / "blackbox/golden/java/managed-outbound-queue-v40.json"
    attestation = GoldenAttestation.from_repository(
        repository,
        profile="managed-outbound-queue",
        normalizers=(
            "outbound:generated-sent-filename",
            "outbound:redis-seven-day-ttl-observation-window",
        ),
    )
    store = GoldenStore(path.parent, attestation, record=record_java)
    store.assert_observation(path.name, observed)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_managed_java_outbound_queue_golden(record_java_golden: bool) -> None:
    repository = _repository()
    observed = _run_probe(repository, target="java")
    _assert_golden(repository, observed, record_java=record_java_golden)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_outbound_queue_matches_frozen_java_golden() -> None:
    repository = _repository()
    observed = _run_probe(repository, target="candidate")
    _assert_golden(repository, observed, record_java=False)
