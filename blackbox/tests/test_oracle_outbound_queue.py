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


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_managed_java_outbound_queue_golden(record_java_golden: bool) -> None:
    repository = _repository()
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
        },
        timeout=170,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            "outbound probe failed with "
            f"{result.returncode}:\nstdout={result.stdout}\nstderr={result.stderr}"
        )
    observed = json.loads(result.stdout)
    path = repository / "blackbox/golden/java/managed-outbound-queue-v25.json"
    attestation = GoldenAttestation.from_repository(
        repository,
        profile="managed-outbound-queue",
        normalizers=("outbound:generated-sent-filename",),
    )
    store = GoldenStore(path.parent, attestation, record=record_java_golden)
    relative_path = path.name
    if record_java_golden:
        store.assert_observation(relative_path, observed)
    else:
        store.assert_observation(relative_path, observed)
