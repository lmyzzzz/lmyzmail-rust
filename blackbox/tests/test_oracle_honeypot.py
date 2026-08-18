from __future__ import annotations

import json
import os
import time
from pathlib import Path

import psycopg
import pytest

from lmyzmail_blackbox.differential import DifferentialRunner
from lmyzmail_blackbox.honeypot_contract import (
    HONEYPOT_ORACLE_EVIDENCE_SCENARIOS,
    HONEYPOT_SCENARIOS,
    _connect,
    _exchange,
    _read_to_eof,
)
from lmyzmail_blackbox.runtime import CandidateRuntime, JavaOracleRuntime

_PROFILE = "managed-honeypot"
_GOLDEN = "blackbox/golden/java/managed-honeypot-v18"
_ORACLE_EVIDENCE_GOLDEN = "blackbox/golden/java/managed-honeypot-oracle-evidence-v18"


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
@pytest.mark.timeout(300)
def test_frozen_java_honeypot_golden(record_java_golden: bool) -> None:
    repository = Path(__file__).resolve().parents[2]
    runner = DifferentialRunner(
        repository,
        repository / _GOLDEN,
        _PROFILE,
        record_java=record_java_golden,
    )
    evidence = DifferentialRunner(
        repository,
        repository / _ORACLE_EVIDENCE_GOLDEN,
        f"{_PROFILE}-oracle-evidence",
        record_java=record_java_golden,
    )
    with JavaOracleRuntime() as oracle:
        if record_java_golden:
            runner.record_from_java(HONEYPOT_SCENARIOS, oracle)
            evidence.record_from_java(HONEYPOT_ORACLE_EVIDENCE_SCENARIOS, oracle)
        else:
            runner.verify_java(HONEYPOT_SCENARIOS, oracle)
            evidence.verify_java(HONEYPOT_ORACLE_EVIDENCE_SCENARIOS, oracle)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(300)
def test_rust_candidate_honeypot_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(
            repository,
            repository / _GOLDEN,
            _PROFILE,
        ).verify_candidate(HONEYPOT_SCENARIOS, candidate)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(150)
def test_rust_candidate_honeypot_classifies_fragmented_input_incrementally() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        stream = _connect(candidate, 3, timeout=2.0)
        try:
            stream.sendall(b"P")
            time.sleep(0.005)
            stream.sendall(b"ING\r\n")
            fragmented = _read_to_eof(stream)
        finally:
            stream.sock.close()

        complete = _connect(candidate, 3, timeout=2.0)
        try:
            complete.sendall(b"PING\r\n")
            expected = _read_to_eof(complete)
        finally:
            complete.sock.close()
        assert fragmented == expected


def _restart_candidate_postgres(candidate: CandidateRuntime) -> None:
    assert candidate.workspace is not None
    assert candidate.ports is not None
    assert candidate._postgres is not None
    bin_dir = candidate.paths.runtime / "postgres-root/usr/lib/postgresql/16/bin"
    candidate._postgres.start()
    candidate._wait_for_postgres_ready(
        bin_dir,
        candidate.ports.postgres,
        env=candidate._postgres_env(),
        log_path=candidate.workspace / "postgres.log",
    )


def _wait_for_honeypot_event(candidate: CandidateRuntime, event_id: str) -> None:
    assert candidate.ports is not None
    deadline = time.monotonic() + 10.0
    last_error: Exception | None = None
    last_state: tuple[object, object, object] | None = None
    while time.monotonic() < deadline:
        try:
            with psycopg.connect(
                host="127.0.0.1",
                port=candidate.ports.postgres,
                dbname="lmyzmail",
                user="lmyzmail_test",
            ) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT count(*) FROM lmyzmail_honeypot_event_receipt "
                        "WHERE event_id = %s",
                        (event_id,),
                    )
                    receipt_count = cursor.fetchone()
                    cursor.execute(
                        "SELECT count(*) FROM skibidi_cringe_ip_activity "
                        "WHERE ip_address = '127.0.0.2' AND activity_type = 'HONEYPOT_HIT'"
                    )
                    activity_count = cursor.fetchone()
                    cursor.execute(
                        "SELECT current_score, total_score, activity_count, honeypot_hit_count "
                        "FROM skibidi_cringe_ip WHERE ip_address = '127.0.0.2'"
                    )
                    aggregate = cursor.fetchone()
            last_state = (receipt_count, activity_count, aggregate)
            if receipt_count == (1,) and activity_count == (1,) and aggregate == (8, 8, 1, 1):
                return
        except psycopg.Error as error:
            last_error = error
        time.sleep(0.05)
    raise AssertionError(
        "honeypot event was not reconciled exactly once: "
        f"state={last_state}, error={last_error}, "
        f"candidate_log={candidate._application.log_tail() if candidate._application else None}"
    )


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_honeypot_replays_after_database_outage_and_restart() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        assert candidate.workspace is not None
        assert candidate._postgres is not None
        assert candidate._application is not None
        candidate._postgres.stop()

        response = _exchange(candidate, 3, b"PING\r\n", source="127.0.0.2")
        assert response
        candidate._application.kill()

        journal = candidate.workspace / "maildir/.lmyzmail/honeypot-replay"
        records = list(journal.glob("*.json"))
        assert len(records) == 1
        record_path = records[0]
        record_bytes = record_path.read_bytes()
        event = json.loads(record_bytes)
        event_id = str(event["event_id"])
        assert record_path.name == f"{event_id}.json"

        _restart_candidate_postgres(candidate)
        candidate._start_application()
        _wait_for_honeypot_event(candidate, event_id)
        deadline = time.monotonic() + 5.0
        while record_path.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not record_path.exists()

        assert candidate._application is not None
        candidate._application.kill()
        descriptor = os.open(
            record_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(record_bytes)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(record_path, 0o600)
        directory_descriptor = os.open(journal, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)

        candidate._start_application()
        deadline = time.monotonic() + 10.0
        while record_path.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not record_path.exists()
        _wait_for_honeypot_event(candidate, event_id)
