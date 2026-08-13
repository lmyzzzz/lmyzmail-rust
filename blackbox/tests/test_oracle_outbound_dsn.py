from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from lmyzmail_blackbox.golden import GoldenAttestation, GoldenStore
from lmyzmail_blackbox.runtime import QA_ADDRESS


def _repository() -> Path:
    return Path(__file__).resolve().parents[2]


def _run_probe(repository: Path, *, target: str) -> dict[str, Any]:
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
            "LMYZMAIL_OUTBOUND_ORACLE_MODE": "DSN",
            "LMYZMAIL_OUTBOUND_TARGET": target,
        },
        timeout=180,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            "outbound DSN probe failed with "
            f"{result.returncode}:\nstdout={result.stdout}\nstderr={result.stderr}"
        )
    observed = json.loads(result.stdout)
    if not isinstance(observed, dict):
        raise AssertionError(f"outbound DSN probe returned a non-object: {observed!r}")
    return observed


def _assert_common_failure(observed: dict[str, Any]) -> None:
    failure = observed["failure"]
    assert failure["phase"] == "RCPT"
    assert failure["code"] == 550
    assert failure["response"]["status_code"] == 202
    assert failure["response"]["queued"] is True
    assert failure["wire"] == {
        "data_observed": False,
        "data_event_count": 0,
        "data_bytes": 0,
    }
    assert failure["db"]["status"] == "FAILED"
    assert failure["db"]["retry_count"] == 0
    assert "550" in failure["db"]["last_error"]
    assert failure["redis"]["task"] is None
    assert failure["redis"]["task_present_after_archive"] is False
    assert failure["redis"]["aggregate_status"] == "FAILED"


def _assert_java_gap(observed: dict[str, Any]) -> None:
    _assert_common_failure(observed)
    dsn = observed["dsn"]
    assert dsn["absence_observation_seconds"] == 8
    assert dsn["wire_message_count"] == 0
    assert dsn["null_reverse_path_command_count"] == 0
    assert dsn["wire"] is None
    assert dsn["database"] is None
    assert dsn["maildir_owner_counts"] == {QA_ADDRESS: 1}
    expected_worklists = {
        "pending": 0,
        "processing": 0,
        "retry": 1,
        "archive": 0,
        "status_updates": 0,
    }
    assert dsn["redis_worklists_before"] == expected_worklists
    assert dsn["redis_worklists_after"] == expected_worklists


def _assert_candidate_dsn(observed: dict[str, Any]) -> None:
    _assert_common_failure(observed)
    dsn = observed["dsn"]
    assert dsn["absence_observation_seconds"] is None
    assert dsn["wire_message_count"] == 1
    assert dsn["null_reverse_path_command_count"] == 1
    expected_worklists = {
        "pending": 0,
        "processing": 0,
        "retry": 0,
        "archive": 0,
        "status_updates": 0,
    }
    assert dsn["redis_worklists_before"] == expected_worklists
    assert dsn["redis_worklists_after"] == expected_worklists

    wire = dsn["wire"]
    assert wire["envelope_from"] == ""
    assert wire["recipients"] == [QA_ADDRESS]
    assert wire["accepted"] is True
    assert wire["crlf_only"] is True
    assert wire["content_type"] == "multipart/report"
    assert wire["report_type"] == "delivery-status"
    assert wire["headers"] == {
        "from": "Mail Delivery Subsystem <mailer-daemon@example.test>",
        "to": QA_ADDRESS,
        "subject": "Delivery Status Notification (Failure)",
        "auto_submitted": "auto-replied",
        "message_id_present": True,
    }
    assert wire["part_types"] == [
        "text/plain",
        "message/delivery-status",
        "text/rfc822-headers",
    ]
    assert wire["original_body_returned"] is False
    assert 500 < wire["bytes"] < 8192
    assert wire["delivery_blocks"] == [
        {
            "reporting_mta": "dns; example.test",
            "arrival_date_present": True,
            "final_recipient": None,
            "action": None,
            "status": None,
            "diagnostic_code": None,
        },
        {
            "reporting_mta": None,
            "arrival_date_present": False,
            "final_recipient": "rfc822; recipient-rcpt-550-1@outbound.fixture.test",
            "action": "failed",
            "status": "5.1.1",
            "diagnostic_code": (
                "smtp; 550 RCPT TO failed: 550 5.1.1 fixture scripted recipient failure"
            ),
        },
    ]
    assert wire["returned_headers"] == {
        "message_id_present": True,
        "subject": "blackbox 5xx RCPT 550 1",
        "from": QA_ADDRESS,
    }

    database = dsn["database"]
    assert database["dsn_task_id_present"] is True
    assert database["state"] == "ADMITTED"
    assert database["expected_sha256_present"] is True
    assert database["prepared_bytes_present"] is False
    assert database["suppress_reason"] is None
    assert database["payload"] == {
        "sender_address": QA_ADDRESS,
        "subject": "blackbox 5xx RCPT 550 1",
        "message_id_present": True,
        "recipients": [
            {
                "recipient": "recipient-rcpt-550-1@outbound.fixture.test",
                "state": "PERMANENT",
                "smtp_code": 550,
                "detail": "RCPT TO failed: 550 5.1.1 fixture scripted recipient failure",
            }
        ],
    }
    assert database["queue"] == {
        "status": "SENT",
        "sender_address": "mailer-daemon@example.test",
        "recipients_json": '{"to":["qa@example.test"],"cc":[],"bcc":[]}',
        "subject": "Delivery Status Notification (Failure)",
        "message_id_present": True,
        "retry_count": 0,
        "last_error": None,
    }
    assert dsn["maildir_owner_counts"] == {
        QA_ADDRESS: 1,
        "mailer-daemon@example.test": 1,
    }


def _assert_golden(
    repository: Path,
    observed: dict[str, Any],
    *,
    record_java: bool,
) -> None:
    path = repository / "blackbox/golden/java/managed-outbound-dsn-oracle-evidence-v6.json"
    attestation = GoldenAttestation.from_repository(
        repository,
        profile="managed-outbound-dsn-oracle-evidence",
        normalizers=("outbound:queue-id",),
    )
    store = GoldenStore(path.parent, attestation, record=record_java)
    store.assert_observation(path.name, observed)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(190)
def test_managed_java_outbound_dsn_gap_golden(record_java_golden: bool) -> None:
    repository = _repository()
    observed = _run_probe(repository, target="java")
    _assert_java_gap(observed)
    _assert_golden(repository, observed, record_java=record_java_golden)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(190)
def test_rust_candidate_emits_durable_rfc3464_dsn() -> None:
    repository = _repository()
    frozen = json.loads(
        (
            repository / "blackbox/golden/java/managed-outbound-dsn-oracle-evidence-v6.json"
        ).read_text(encoding="utf-8")
    )
    _assert_java_gap(frozen["observation"])
    observed = _run_probe(repository, target="candidate")
    _assert_candidate_dsn(observed)
