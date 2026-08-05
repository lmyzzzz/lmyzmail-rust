from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner, Scenario
from lmyzmail_blackbox.errors import GoldenMismatch, HarnessError
from lmyzmail_blackbox.golden import _ATTESTED_INPUTS
from lmyzmail_blackbox.ports import PortSet


@dataclass
class FakeTarget:
    target_kind: str
    workspace: Path | None
    ports: PortSet | None
    value: str


def _repository_fixture(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    (repository / "evidence/freeze/java-oracle").mkdir(parents=True)
    (repository / "blackbox").mkdir()
    (repository / "evidence/freeze/java-oracle/baseline.json").write_text(
        '{"commit":"' + "a" * 40 + '","oracle_jar":{"selected_sha256":"' + "b" * 64 + '"}}',
        encoding="utf-8",
    )
    for relative_path in _ATTESTED_INPUTS:
        path = repository / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"fixture:{relative_path}\n", encoding="utf-8")
    return repository


def _ports() -> PortSet:
    return PortSet(1, 2, 3, 4, 5, 6, ())


def test_same_scenario_records_only_java_and_verifies_candidate(tmp_path: Path) -> None:
    repository = _repository_fixture(tmp_path)
    golden_root = repository / "blackbox/golden/java/managed-basic"
    scenario = Scenario(
        "http/health",
        lambda target: {"value": target.value},  # type: ignore[attr-defined]
        contract={"protocol": "unit", "operation": "health"},
    )
    oracle = FakeTarget("java-oracle", tmp_path / "oracle", _ports(), "same")
    candidate = FakeTarget("rust-candidate", tmp_path / "candidate", _ports(), "same")

    DifferentialRunner(repository, golden_root, "managed-basic", record_java=True).record_from_java(
        [scenario], oracle
    )
    DifferentialRunner(repository, golden_root, "managed-basic").verify_candidate(
        [scenario], candidate
    )
    DifferentialRunner(repository, golden_root, "managed-basic").verify_java([scenario], oracle)

    candidate.value = "different"
    with pytest.raises(GoldenMismatch, match="golden mismatch"):
        DifferentialRunner(repository, golden_root, "managed-basic").verify_candidate(
            [scenario], candidate
        )


def test_candidate_cannot_record_and_oracle_cannot_be_candidate(tmp_path: Path) -> None:
    repository = _repository_fixture(tmp_path)
    runner = DifferentialRunner(
        repository,
        repository / "golden",
        "managed-basic",
        record_java=True,
    )
    scenario = Scenario("probe", lambda _: {}, contract={"protocol": "unit"})
    candidate = FakeTarget("rust-candidate", tmp_path, _ports(), "value")
    oracle = FakeTarget("java-oracle", tmp_path, _ports(), "value")

    with pytest.raises(HarnessError, match="only be recorded"):
        runner.record_from_java([scenario], candidate)
    with pytest.raises(HarnessError, match="non-oracle"):
        runner.verify_candidate([scenario], oracle)
