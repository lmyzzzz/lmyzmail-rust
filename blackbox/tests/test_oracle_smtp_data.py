from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner
from lmyzmail_blackbox.protocols import (
    http_exchange,
    json_http_exchange,
    smtp_data_transaction,
)
from lmyzmail_blackbox.runtime import CandidateRuntime, JavaOracleRuntime
from lmyzmail_blackbox.smtp_contract import _connect_postgres, _redis_state
from lmyzmail_blackbox.smtp_data_contract import (
    SMTP_DATA_ORACLE_EVIDENCE_SCENARIOS,
    SMTP_DATA_SCENARIOS,
)


def _candidate(repository: Path) -> CandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        return CandidateRuntime.from_environment()
    return CandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        )
    )


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(360)
def test_managed_java_smtp_data_goldens(record_java_golden: bool) -> None:
    paths = JavaOracleRuntime().paths
    differential = DifferentialRunner(
        paths.repository,
        paths.repository / "blackbox/golden/java/managed-smtp-data-v45",
        "managed-smtp-data",
        record_java=record_java_golden,
    )
    oracle_evidence = DifferentialRunner(
        paths.repository,
        paths.repository / "blackbox/golden/java/managed-smtp-data-oracle-evidence-v45",
        "managed-smtp-data-oracle-evidence",
        record_java=record_java_golden,
    )

    with JavaOracleRuntime(paths=paths) as oracle:
        if record_java_golden:
            differential.record_from_java(SMTP_DATA_SCENARIOS, oracle)
            oracle_evidence.record_from_java(
                SMTP_DATA_ORACLE_EVIDENCE_SCENARIOS,
                oracle,
            )
        else:
            differential.verify_java(SMTP_DATA_SCENARIOS, oracle)
            oracle_evidence.verify_java(
                SMTP_DATA_ORACLE_EVIDENCE_SCENARIOS,
                oracle,
            )


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(360)
def test_rust_candidate_smtp_data_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    differential = DifferentialRunner(
        repository,
        repository / "blackbox/golden/java/managed-smtp-data-v45",
        "managed-smtp-data",
    )
    with _candidate(repository) as candidate:
        differential.verify_candidate(SMTP_DATA_SCENARIOS, candidate)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(360)
def test_rust_candidate_exact_count_survives_parallel_inserts_and_deletes() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        assert candidate.ports is not None
        login = json_http_exchange(
            "127.0.0.1",
            candidate.ports.http,
            "POST",
            "/web/login",
            value={"address": "qa@example.test", "password": "BlackboxPass123!"},
            timeout=10.0,
        )
        assert login.status_code == 200
        session_token = str(json.loads(login.body)["token"])
        postgres_deadline = time.monotonic() + 10.0
        with _connect_postgres(candidate, deadline=postgres_deadline) as connection:
            baseline_row = connection.execute(
                "SELECT count(*) FROM email_index "
                "WHERE mailbox_address=%s AND folder=%s",
                ("qa@example.test", "spam"),
            ).fetchone()
        assert baseline_row is not None
        baseline = int(baseline_row[0])

        def send_message(phase: str, index: int) -> None:
            subject = f"parallel-count-{phase}-{index:03d}"
            message = (
                f"From: load@example.test\r\n"
                f"To: qa@example.test\r\n"
                f"Subject: {subject}\r\n"
                f"Message-ID: <{subject}@example.test>\r\n"
                "MIME-Version: 1.0\r\n"
                "Content-Type: text/plain; charset=us-ascii\r\n"
                "\r\n"
                f"{subject}\r\n"
            ).encode("ascii")
            transcript = smtp_data_transaction(
                "127.0.0.1",
                candidate.ports.smtp,
                sender="",
                recipient="qa@example.test",
                message=message,
                timeout=30.0,
            )
            log_path = candidate.workspace / "rust-candidate.log"
            log_tail = log_path.read_text(encoding="utf-8", errors="replace")[-4096:]
            postgres_log = candidate.workspace / "postgres.log"
            postgres_tail = postgres_log.read_text(
                encoding="utf-8", errors="replace"
            )[-4096:]
            assert transcript.accepted[0].startswith(b"250 "), (
                transcript.accepted,
                log_tail,
                postgres_tail,
            )

        with ThreadPoolExecutor(max_workers=16) as executor:
            list(executor.map(lambda index: send_message("initial", index), range(32)))

        postgres_deadline = time.monotonic() + 10.0
        with _connect_postgres(candidate, deadline=postgres_deadline) as connection:
            rows = connection.execute(
                "SELECT file_name FROM email_index "
                "WHERE mailbox_address=%s AND folder=%s "
                "AND subject LIKE %s "
                "ORDER BY subject LIMIT 16",
                ("qa@example.test", "spam", "parallel-count-initial-%"),
            ).fetchall()
        assert len(rows) == 16
        filenames = [str(row[0]) for row in rows]

        def delete_message(file_name: str) -> None:
            response = http_exchange(
                "127.0.0.1",
                candidate.ports.http,
                "DELETE",
                f"/web/mail/spam/{quote(file_name, safe='')}",
                headers=(("X-Session-Token", session_token),),
                timeout=30.0,
            )
            assert response.status_code == 200

        with ThreadPoolExecutor(max_workers=24) as executor:
            futures = [
                executor.submit(send_message, "concurrent", index) for index in range(32)
            ]
            futures.extend(executor.submit(delete_message, name) for name in filenames)
            for future in futures:
                future.result()

        expected = baseline + 48
        deadline = time.monotonic() + 15.0
        last_observed: tuple[int, int | None, int | None, int, int | None] | None = None
        while time.monotonic() < deadline:
            postgres_deadline = time.monotonic() + 5.0
            with _connect_postgres(candidate, deadline=postgres_deadline) as connection:
                row = connection.execute(
                    "SELECT "
                    "(SELECT count(*) FROM email_index "
                    " WHERE mailbox_address=%s AND folder=%s),"
                    "(SELECT exact_count FROM lmyzmail_inbound_mail_count_state "
                    " WHERE mailbox_address=%s AND folder=%s),"
                    "(SELECT desired_count FROM lmyzmail_inbound_mail_count_projection "
                    " WHERE mailbox_address=%s AND folder=%s),"
                    "(SELECT count(*) FROM lmyzmail_inbound_delivery_intent)",
                    (
                        "qa@example.test",
                        "spam",
                        "qa@example.test",
                        "spam",
                        "qa@example.test",
                        "spam",
                    ),
                ).fetchone()
            assert row is not None
            redis_count = _redis_state(
                candidate,
                "mail:count:qa@example.test:spam",
                deadline=time.monotonic() + 5.0,
            )[0]
            last_observed = (int(row[0]), row[1], row[2], int(row[3]), redis_count)
            if last_observed == (expected, expected, None, 0, expected):
                break
            time.sleep(0.05)
        assert last_observed == (expected, expected, None, 0, expected)
