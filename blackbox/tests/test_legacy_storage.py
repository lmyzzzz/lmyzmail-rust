from __future__ import annotations

import json
from pathlib import Path

import pytest
import sqlglot

from lmyzmail_blackbox.errors import HarnessError
from lmyzmail_blackbox.legacy_storage import (
    install_maildir_fixture,
    load_redis_seed,
    verify_maildir_fixture,
)


def _repository() -> Path:
    return Path(__file__).resolve().parents[2]


def test_frozen_maildir_fixture_has_exact_crlf_bytes_and_hashes() -> None:
    fixture = verify_maildir_fixture(_repository())

    assert fixture.total_bytes == 1997
    assert [entry.subdirectory for entry in fixture.files] == [0, 1, 2]


def test_maildir_fixture_installs_atomically_with_private_modes(tmp_path: Path) -> None:
    target = tmp_path / "maildir"

    fixture = install_maildir_fixture(_repository(), target)

    assert sum(path.stat().st_size for path in target.rglob("*.eml")) == fixture.total_bytes
    assert target.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in target.rglob("*.eml"))


def test_maildir_fixture_rejects_nonempty_target(tmp_path: Path) -> None:
    target = tmp_path / "maildir"
    target.mkdir()
    (target / "existing").write_text("owned by caller", encoding="utf-8")

    with pytest.raises(HarnessError, match="not empty"):
        install_maildir_fixture(_repository(), target)


def test_redis_seed_has_real_legacy_types_and_ttl_contracts() -> None:
    fixture = load_redis_seed(_repository())

    assert fixture.database == 0
    assert {entry.type for entry in fixture.keys} == {"string", "hash", "zset"}
    assert {entry.ttl_seconds for entry in fixture.keys} == {None, 604800}


def test_storage_manifests_are_strict_json_and_bind_frozen_sources() -> None:
    repository = _repository()
    contract = json.loads(
        (repository / "blackbox/manifests/legacy-storage-contract.json").read_text(encoding="utf-8")
    )
    differences = json.loads(
        (repository / "blackbox/manifests/behavior-differences.json").read_text(encoding="utf-8")
    )

    assert contract["schema_version"] == 1
    assert contract["postgres"]["table_count"] == 13
    assert contract["maildir"]["source"]["commit"] == ("5dac2ab2922c30c726c4a83d7626c95ad4e231c8")
    assert {entry["id"] for entry in differences["differences"]} == {
        "maildir-atomic-publication",
        "starttls-buffered-plaintext-command",
        "smtp-data-terminator-command-loss",
        "smtp-bdat-coalesced-prerequisite-state-stall",
        "smtp-command-control-byte-reflection",
        "smtp-fragmented-overlong-double-error",
    }
    starttls = next(
        entry
        for entry in differences["differences"]
        if entry["id"] == "starttls-buffered-plaintext-command"
    )
    assert starttls["evidence"]["commit"] == "5dac2ab2922c30c726c4a83d7626c95ad4e231c8"
    assert starttls["candidate_requirement"].startswith("After sending the 220 STARTTLS")
    by_id = {entry["id"]: entry for entry in differences["differences"]}
    data_tail = by_id["smtp-data-terminator-command-loss"]
    assert data_tail["evidence"]["source_sha256"] == (
        "bccb53816f461a247df9072cfe1e75c383e37291529e478ea43c242fa15e735a"
    )
    bdat_stall = by_id["smtp-bdat-coalesced-prerequisite-state-stall"]
    assert bdat_stall["candidate_requirement"].startswith(
        "For a valid EHLO session receiving coalesced MAIL"
    )


def test_postgres_seed_is_structurally_valid_postgres_sql() -> None:
    seed = (_repository() / "blackbox/fixtures/legacy/postgres-seed.sql").read_text(
        encoding="utf-8"
    )

    statements = tuple(
        statement for statement in sqlglot.parse(seed, read="postgres") if statement is not None
    )

    assert len(statements) == 25
