from __future__ import annotations

import threading
from pathlib import Path

import pytest

from lmyzmail_blackbox.errors import GoldenMismatch
from lmyzmail_blackbox.golden import (
    _ATTESTED_INPUTS,
    GoldenAttestation,
    GoldenStore,
)


def _attestation() -> GoldenAttestation:
    return GoldenAttestation(
        oracle_commit="a" * 40,
        oracle_jar_sha256="b" * 64,
        input_sha256=(("blackbox/requirements.lock", "c" * 64),),
        harness_definition_sha256="d" * 64,
        profile="unit",
        normalizers=("http-date",),
    )


def test_golden_is_attested_create_once_and_cannot_be_overwritten(tmp_path: Path) -> None:
    recorder = GoldenStore(tmp_path, _attestation(), record=True)
    verifier = GoldenStore(tmp_path, _attestation())
    recorder.assert_observation("http/health.json", {"status": "ok"})
    verifier.assert_observation("http/health.json", {"status": "ok"})

    with pytest.raises(GoldenMismatch, match="golden mismatch"):
        recorder.assert_observation("http/health.json", {"status": "changed"})


def test_concurrent_recorders_cannot_replace_first_golden(tmp_path: Path) -> None:
    store = GoldenStore(tmp_path, _attestation(), record=True)
    barrier = threading.Barrier(2)
    mismatches: list[GoldenMismatch] = []

    def record(value: str) -> None:
        barrier.wait()
        try:
            store.assert_observation("race.json", {"value": value})
        except GoldenMismatch as error:
            mismatches.append(error)

    threads = [threading.Thread(target=record, args=(value,)) for value in ("one", "two")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2.0)

    assert all(not thread.is_alive() for thread in threads)
    assert len(mismatches) == 1


def test_binary_artifact_is_immutable_and_has_attested_sidecar(tmp_path: Path) -> None:
    store = GoldenStore(tmp_path, _attestation(), record=True)
    store.assert_artifact("pixels/frame.png", b"not-a-real-png")

    assert (tmp_path / "pixels/frame.png").read_bytes() == b"not-a-real-png"
    assert (tmp_path / "pixels/frame.png.golden.json").is_file()
    with pytest.raises(GoldenMismatch, match="artifact mismatch"):
        store.assert_artifact("pixels/frame.png", b"changed")


def test_golden_path_cannot_escape_root(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="escaped"):
        GoldenStore(tmp_path, _attestation(), record=True).assert_observation("../outside.json", {})


def test_repository_attestation_binds_every_lock_and_definition_file(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    manifest = repository / "evidence/freeze/java-oracle/baseline.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        '{"commit":"' + "a" * 40 + '","oracle_jar":{"selected_sha256":"' + "b" * 64 + '"}}',
        encoding="utf-8",
    )
    for relative_path in _ATTESTED_INPUTS:
        path = repository / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"fixture:{relative_path}\n", encoding="utf-8")
    definition = repository / "blackbox/bin/probe.sh"
    definition.parent.mkdir(parents=True, exist_ok=True)
    definition.write_text("version=one\n", encoding="utf-8")

    before = GoldenAttestation.from_repository(
        repository,
        profile="unit",
        normalizers=(),
    )
    assert tuple(path for path, _ in before.input_sha256) == _ATTESTED_INPUTS

    definition.write_text("version=two\n", encoding="utf-8")
    after = GoldenAttestation.from_repository(
        repository,
        profile="unit",
        normalizers=(),
    )

    assert before.input_sha256 == after.input_sha256
    assert before.harness_definition_sha256 != after.harness_definition_sha256
