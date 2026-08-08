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
        "outbound-starttls-hostname-verification",
        "outbound-smtp-commit-ambiguity-no-retry",
        "outbound-null-mx-rejection",
        "outbound-route-dns-answer-budgets",
        "mta-sts-negative-cache-restart",
        "outbound-http-redis-outage-deadline",
        "userdata-malformed-write-rejection",
        "userdata-contact-admission-race",
        "userdata-contact-list-bound",
        "auth-postgres-cancellation-and-pool-health",
        "htcpcp-connection-close-lifecycle",
        "htcpcp-absolute-request-deadline",
        "htcpcp-ambiguous-http-framing",
        "honeypot-incremental-protocol-framing",
        "honeypot-bounded-admission-and-client-state",
        "honeypot-durable-cringe-write",
        "minecraft-absolute-connection-deadline",
        "minecraft-bounded-connection-admission",
        "minecraft-duplicate-session-removal-fencing",
        "minecraft-online-verify-token-hardening",
        "minecraft-sessionserver-bounded-lifecycle",
        "minecraft-sessionserver-query-encoding",
        "minecraft-sessionserver-response-validation",
        "minecraft-strict-compression-envelope",
        "minecraft-logout-flush-before-close",
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
    commit_ambiguity = by_id["outbound-smtp-commit-ambiguity-no-retry"]
    assert commit_ambiguity["evidence"]["sender_source_sha256"] == (
        "c7f10f2416ae308335e9f6f77ffe00140b64904b0b2e8dc7eb04ed74394c603e"
    )
    assert commit_ambiguity["evidence"]["recovery_source_sha256"] == (
        "f9abffe3fbc98e314db34fcf38d894fd200d93ad74ff933f2c0f57e2717f1bf4"
    )
    assert "stale pre-upgrade PROCESSING row" in commit_ambiguity["candidate_requirement"]

    htcpcp_close = by_id["htcpcp-connection-close-lifecycle"]
    assert htcpcp_close["evidence"]["oracle_golden"].startswith(
        "blackbox/golden/java/managed-htcpcp-oracle-evidence-"
    )
    assert "actively close" in htcpcp_close["candidate_requirement"]
    assert by_id["outbound-null-mx-rejection"]["evidence"]["source_sha256"] == (
        "0de7fa1c7999f9d6ce7e583a0d5d6be38c9f3619f7b319d564d933f48186b181"
    )
    assert (
        by_id["outbound-route-dns-answer-budgets"]["evidence"]["network_source_sha256"]
        == "1a46e5938bdfdc4b0f7cd6d8e2377ea157b7181768a392c954e037f04442e063"
    )
    assert by_id["mta-sts-negative-cache-restart"]["evidence"]["source_sha256"] == (
        "31f8a4d250152c4626bea26f6a5e3fea6f3359fc5ac42daaa205b55a46200d46"
    )
    assert by_id["outbound-http-redis-outage-deadline"]["evidence"]["source_sha256"] == (
        "f9abffe3fbc98e314db34fcf38d894fd200d93ad74ff933f2c0f57e2717f1bf4"
    )
    assert by_id["userdata-malformed-write-rejection"]["evidence"]["source_sha256"] == (
        "eb6985f2eafec9a65a518c7c2bc8e46de61393761bad0981053561fcdeb21aaf"
    )
    assert by_id["userdata-contact-admission-race"]["evidence"]["source_sha256"] == (
        "17ca3b701d24d40d971ab1f51410caf7db33c6d5f33dafd62682f731e35dfb01"
    )
    assert by_id["userdata-contact-list-bound"]["candidate_requirement"].startswith(
        "Within one repeatable-read snapshot"
    )
    auth_cancellation = by_id["auth-postgres-cancellation-and-pool-health"]
    assert auth_cancellation["evidence"]["mailbox_source_sha256"] == (
        "209077c4223ef8f3351211decf0aa8633043a3f97ccf017cc8462ba71c57fcbe"
    )
    assert auth_cancellation["evidence"]["session_source_sha256"] == (
        "a68edfb3beab48e8b43fa8951f56cf266d43540aa6fe13d3dd4b9df6b24e49b8"
    )
    assert (
        by_id["minecraft-absolute-connection-deadline"]["evidence"]["source_sha256"]
        == "fed5b8de13b875d549a6cf706cb9def4422b7fd3b09eabfa7b7d6017e4c52a52"
    )
    assert (
        by_id["minecraft-bounded-connection-admission"]["evidence"]["source_sha256"]
        == "3c997b4d378a6f1b57935ec1f2138b7bd770fb5d84daa0cdbc69f9d71b5f30d3"
    )
    assert by_id["minecraft-strict-compression-envelope"]["evidence"][
        "source_sha256"
    ] == "57ded840303dba8df6356246d8ad30f5ee98b6cce6a258d0883bc652d3e652f0"
    assert by_id["minecraft-duplicate-session-removal-fencing"]["evidence"][
        "source_sha256"
    ] == "422f57ef731635adcce19f1162dbb9bada1a2a8bc1373a4b6ef91c71023fec5a"
    assert by_id["minecraft-online-verify-token-hardening"]["evidence"][
        "source_sha256"
    ] == "4325f6517ccffa9b94ee1b8fa274b1a9cf51d94c32a0e4ac9976003dd8c1d52c"
    assert by_id["minecraft-sessionserver-query-encoding"]["evidence"][
        "source_sha256"
    ] == "c6077c703f848f5b357325dbde62b491d81cf09550289a7dedf98d78e0f3f00a"
    assert by_id["minecraft-sessionserver-response-validation"]["evidence"][
        "source_sha256"
    ] == "c6077c703f848f5b357325dbde62b491d81cf09550289a7dedf98d78e0f3f00a"
    assert by_id["minecraft-sessionserver-bounded-lifecycle"]["evidence"][
        "server_source_sha256"
    ] == "3c997b4d378a6f1b57935ec1f2138b7bd770fb5d84daa0cdbc69f9d71b5f30d3"


def test_postgres_seed_is_structurally_valid_postgres_sql() -> None:
    seed = (_repository() / "blackbox/fixtures/legacy/postgres-seed.sql").read_text(
        encoding="utf-8"
    )

    statements = tuple(
        statement for statement in sqlglot.parse(seed, read="postgres") if statement is not None
    )

    assert len(statements) == 25
