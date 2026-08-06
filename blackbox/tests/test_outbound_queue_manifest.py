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
    assert lease["type"] == "string-token"
    assert lease["ttl"] == "per-claim"
    assert lease["claim"] == [
        "lpop:pending",
        "set:nx:px",
        "sadd:processing",
        "hset:processing_time",
    ]
    fenced_operations = ("renew", "retry", "acknowledge")
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


def test_outbound_manifest_requires_durable_candidate_boundaries() -> None:
    manifest = _manifest()
    requirements = manifest["requirements"]
    assert all(requirements.values())
    assert manifest["observed_legacy_gaps"] == [
        "archive-lpop-before-postgres-commit",
        "processing-timeout-without-send-heartbeat",
        "task-detail-ttl-shorter-than-queue-reference",
        "status-updates-write-only-in-production",
        "permanent-failure-without-dsn",
    ]
