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
    assert lease["mutation_preflight"] == {
        "operations": [
            "claim",
            "renew",
            "release",
            "retry",
            "acknowledge",
            "expired-recovery",
            "reconcile",
        ],
        "before_first_write": True,
        "claim_pending_head_preview": "lindex-before-lpop",
        "claim_dynamic_keys": ["lease", "task", "domains"],
        "failure_effect": "all-values-and-ttls-unchanged",
    }
    fenced_operations = ("renew", "release", "retry", "acknowledge")
    assert all("compare-token" in lease[operation] for operation in fenced_operations)
    assert lease["expired_recovery"][0] == "verify-lease-absent"
    assert manifest["redis"]["candidate_receipts"] == {
        "claim_result": {
            "index": "lmyzmail:mail:queue:claim-result-index",
            "ttl": "lease-duration",
            "index_score_clock": "redis-server-epoch-milliseconds",
            "max_index_entries": 4096,
            "empty_claim_receipt": False,
        },
        "settlement": {
            "index": "lmyzmail:mail:queue:settlement-index",
            "ttl_seconds": 300,
            "index_score_clock": "redis-server-epoch-seconds",
            "max_index_entries": 4096,
        },
        "migration_done": {
            "index": "lmyzmail:mail:queue:migration:<namespace>:done-index",
            "ttl_seconds": 300,
            "index_score_clock": "redis-server-epoch-seconds",
            "max_index_entries": 4096,
            "scope": "per-archive-or-status-namespace",
        },
        "terminal_cleanup": {
            "index": "lmyzmail:mail:queue:migration:cleanup-index",
            "ttl_seconds": 300,
            "index_score_clock": "redis-server-epoch-seconds",
            "max_index_entries": 4096,
            "receipt": "CLEANED:sha256(sent-file-name)",
        },
    }
    assert manifest["redis"]["candidate_active_reference_bound"] == {
        "config_keys": [
            "lmyzmail.outbound.max-pending-tasks",
            "botmail.outbound.max-pending-tasks",
        ],
        "new_key_precedence": True,
        "default": 10000,
        "hard_maximum": 1000000,
        "references": ["pending:llen", "processing:scard", "retry:zcard"],
        "admission": "atomic-before-publication",
        "idempotent_existing_reference_bypasses_capacity": True,
        "durable_backlog_over_capacity": "postgres-retained-for-bounded-replay",
    }
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
    assert manifest["postgres_admission_commit"] == {
        "response_loss_reconciliation": "same-ordered-connection",
        "committed_proof": [
            "exact-queue-row",
            "exact-email-index-row",
            "exact-spool-sidecar",
        ],
        "not_committed_proof": [
            "queue-identity-absent",
            "email-index-identity-absent",
            "spool-identity-absent",
        ],
        "partial_or_conflicting_state": "outcome-unknown",
        "outcome_unknown_materialized_files": "preserved",
    }
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
    assert manifest["postgres_spool_ownership"] == {
        "migration": "crates/lmyzmail/migrations/002_outbound_spool_ownership.sql",
        "legacy_columns_changed": False,
        "table": "lmyzmail_outbound_spool",
        "states": ["OWNED", "REMOVED"],
        "terminal_scan_limit": 10000,
        "terminal_scan_source": "postgres-independent-of-redis-task",
        "path_policy": "canonical-configured-spool-root-and-task-bound-name",
        "legacy_java_delete_guard": "byte-equal-sent-maildir-copy",
        "directory_fsync_after_unlink": True,
        "missing_file_reconciliation": "mark-removed",
        "removed_scan_cursor": "bounded-wrapping-task-id",
        "sidecar_delete_redis_proof": [
            "task-absent",
            "pending-absent",
            "processing-absent",
            "processing-time-absent",
            "retry-absent",
            "lease-absent",
            "sent-file-index-absent",
        ],
        "sidecar_delete_postgres_identity": [
            "task-id",
            "spool-path",
            "removed-state",
            "terminal-legacy-row",
        ],
        "delete_response_loss": "exact-sidecar-readback",
    }
    assert manifest["postgres_dsn"] == {
        "migration": "crates/lmyzmail/migrations/003_outbound_dsn.sql",
        "table": "lmyzmail_outbound_dsn",
        "states": ["PENDING", "LEASED", "ADMITTING", "ADMITTED", "SUPPRESSED"],
        "lease_seconds": 120,
        "admission_work_budget_seconds": 90,
        "lease_fence": ["original_task_id", "lease_token", "lease_until"],
        "task_id_binding": "LEASED->ADMITTING before materialization",
        "digest": "sha256(final prepared bytes)",
        "checkpoint": "token-fenced COALESCE(expected_sha256,prepared_bytes)",
        "recovery_image": {
            "column": "prepared_bytes",
            "max_bytes": 4194304,
            "lifecycle": "ADMITTING only; cleared in the ADMITTED queue transaction",
        },
        "admitted_replay": "PENDING PostgreSQL queue rows are recovered to legacy Redis after restart",
        "processing_replay": "never automatic; coordinator fence owns PROCESSING rows",
        "renderer": ["RFC3464 ASCII", "RFC6533 EAI global-delivery-status"],
        "smtp_utf8": "8bit for EAI envelope; quoted-printable global parts for ASCII envelope",
    }
    assert manifest["worker_dispatch"] == {
        "failure_state": "closed-to-backoff",
        "backoff": "capped-equal-jitter",
        "backoff_expiry": "half-open-waiting",
        "half_open_max_inflight": 1,
        "success": "restore-full-concurrency",
        "failure": "return-to-backoff",
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
