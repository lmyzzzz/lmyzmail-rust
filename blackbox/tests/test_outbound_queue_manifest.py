from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _repository() -> Path:
    return Path(__file__).resolve().parents[2]


def _manifest() -> dict[str, Any]:
    path = _repository() / "blackbox/manifests/outbound-queue-contract.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_outbound_manifest_binds_frozen_oracle_and_legacy_key_surface() -> None:
    manifest = _manifest()
    assert manifest["schema_version"] == 1
    assert manifest["oracle_commit"] == "5dac2ab2922c30c726c4a83d7626c95ad4e231c8"
    assert {name: source["sha256"] for name, source in manifest["sources"].items()} == {
        "scheduler": "06b64256a19e0f8589ca12599181ee5a2b2b2176005c13c213d32e5e19b2ee02",
        "redis": "f9abffe3fbc98e314db34fcf38d894fd200d93ad74ff933f2c0f57e2717f1bf4",
        "persister": "f5ba8596cf36f2fdb8af7bbde2133f9f352e9db2c073eacbf5bb8277e87b6360",
        "sender": "c7f10f2416ae308335e9f6f77ffe00140b64904b0b2e8dc7eb04ed74394c603e",
        "service": "4364488928d307a31e5bdabaa7355db3f0d146607cace085f8900faa364b99ba",
        "smtp_client": "49b380ceee47c23f70cd2bcd953507378ba70f457c22d0bccb2c62b9fd0c7754",
        "network_validator": "1a46e5938bdfdc4b0f7cd6d8e2377ea157b7181768a392c954e037f04442e063",
    }
    assert manifest["redis"]["prefix"] == "botmail:mail:queue:"
    keys = manifest["redis"]["keys"]
    assert {entry["name"] for entry in keys} == {
        "pending",
        "processing",
        "retry",
        "processing_time",
        "task:<id>",
        "domains:<id>",
        "sentfile_index",
        "status_updates",
        "archive",
    }
    by_name = {entry["name"]: entry for entry in keys}
    assert by_name["task:<id>"]["ttl_seconds"] == 604800
    assert by_name["domains:<id>"]["ttl_seconds"] == 604800
    assert by_name["sentfile_index"]["ttl_seconds"] is None
    assert manifest["redis"]["claim"] == [
        "lpop:pending",
        "sadd:processing",
        "hset:processing_time",
    ]
    lease = manifest["redis"]["candidate_lease"]
    assert lease["key"] == "lmyzmail:mail:queue:lease:<id>"
    assert lease["attempt_key"] == "lmyzmail:mail:queue:attempt:<token>"
    assert lease["attempt_value"] == "task-id"
    assert lease["type"] == "string-token"
    assert lease["ttl"] == "per-claim"
    assert lease["claim"] == [
        "reject-reused-attempt",
        "lpop:pending",
        "set:nx:px",
        "set:attempt-to-task:px",
        "sadd:processing",
        "hset:processing_time",
    ]
    assert lease["reconcile"] == [
        "bounded-attempt-task",
        "compare-token",
        "verify:processing",
        "bounded-processing-time",
        "bounded-task-json",
        "compare-lease-ttls",
    ]
    assert lease["post_send_mutation_failure"] == "outcome-unknown"
    fenced_operations = ("renew", "release", "retry", "acknowledge")
    assert all("compare-token" in lease[operation] for operation in fenced_operations)
    assert lease["expired_recovery"][0] == "verify-lease-absent"
    smtp = manifest["smtp_adapter"]
    assert smtp["connect_target"] == "validated-pinned-socket-address"
    assert smtp["dns_resolution_inside_adapter"] is False
    assert smtp["public_mx_rejects_special_addresses"] is True
    assert smtp["tls_name_verification"] == "all-starttls-modes"
    assert smtp["reply_total_bytes"] == 65536
    assert smtp["pipeline_bytes"] == 524288
    assert smtp["message_chunk_bytes"] == 16384
    assert smtp["post_terminator_failures"] == "ambiguous"
    assert smtp["structured_error_fields"] == ["stage", "smtp_code", "recipients"]
    assert smtp["unknown_file_errors"] == "temporary"
    database_fence = manifest["postgres_delivery_fence"]
    assert database_fence == {
        "table": "outbound_mail_queue",
        "owner_column": "processor_id",
        "heartbeat_column": "processing_started_at",
        "claim_transition": "PENDING->PROCESSING",
        "claim_nonce_bits": 128,
        "caller_generated_attempt_token": True,
        "claim_unknown_snapshot_by_attempt": True,
        "claim_unknown_reconcile": "owner-token-row-read",
        "owner_compared_operations": ["heartbeat", "release", "retry", "terminal"],
        "terminal_statuses": ["SENT", "PARTIAL_SUCCESS", "FAILED"],
        "operation_timeout_seconds": 8,
        "retry_increment_atomic": True,
        "invalid_retry_state": "atomic-failed-quarantine",
        "stale_owner_mutation_rejected": True,
        "mutation_timeout": "outcome-unknown-requires-snapshot",
        "mutation_fault_injection": ["claim", "retry", "terminal"],
        "null_legacy_heartbeat_recoverable": True,
        "sidecarless_expired_recovery": "ambiguous-terminal",
        "commit_barrier_corruption": "fail-closed",
        "last_error_truncation": "1000-utf16-code-units-plus-ellipsis",
        "legacy_schema_integration_test": True,
    }
    assert manifest["postgres_recipient_ledger"] == {
        "migration": "crates/lmyzmail/migrations/001_outbound_delivery_ledger.sql",
        "legacy_columns_changed": False,
        "tables": [
            "lmyzmail_outbound_delivery_attempt",
            "lmyzmail_outbound_delivery_recipient",
        ],
        "recipient_identity": ["task_id", "recipient_ordinal", "recipient_address"],
        "states": [
            "PENDING",
            "RETRYABLE",
            "PERMANENT",
            "COMMIT_ARMED",
            "DELIVERED",
            "AMBIGUOUS",
        ],
        "terminal_states": ["PERMANENT", "DELIVERED", "AMBIGUOUS"],
        "attempt_fence": ["owner_token", "generation"],
        "roster_integrity": ["recipient_count", "sha256"],
        "migration_lock": "postgres-advisory-xact-lock",
        "commit_barrier": "accepted-recipients-to-commit-armed-before-smtp-terminator",
        "armed_recovery": "ambiguous",
        "sidecarless_takeover": "ambiguous",
        "commit_barrier_corruption": "fail-closed",
        "partial_rcpt_retry": "retryable-recipients-only",
        "ambiguous_auto_retry": False,
        "ambiguous_dsn": False,
        "legacy_projection": ["SENT", "PARTIAL_SUCCESS", "FAILED"],
    }


def test_outbound_manifest_requires_durable_candidate_boundaries() -> None:
    manifest = _manifest()
    requirements = manifest["requirements"]
    assert requirements == {
        "legacy_key_interop": True,
        "ack_archive_only_after_postgres_commit": True,
        "recoverable_archive_inflight": True,
        "renewable_processing_lease": True,
        "fenced_domain_status_updates": True,
        "domain_status_read_before_size_check": False,
        "bounded_status_update_drain": True,
        "active_references_must_not_expire": True,
        "stable_message_id_on_ambiguous_smtp_result": True,
        "dsn_on_permanent_failure": True,
        "pinned_and_filtered_mx_address": True,
        "bounded_incremental_smtp_io": True,
        "post_data_ambiguity_preserved": True,
        "durable_recipient_ledger": True,
        "ambiguous_auto_retry_disabled": True,
        "ambiguous_dsn_disabled": True,
        "redis_mutations_classify_outcome_unknown": True,
        "sidecarless_processing_recovery_ambiguous": True,
    }
    assert manifest["observed_legacy_gaps"] == [
        "archive-lpop-before-postgres-commit",
        "processing-timeout-without-send-heartbeat",
        "task-detail-ttl-shorter-than-queue-reference",
        "status-updates-write-only-in-production",
        "permanent-failure-without-dsn",
    ]
