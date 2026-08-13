from __future__ import annotations

import json
import os
import signal
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import psycopg
import pytest
import redis

from lmyzmail_blackbox.differential import DifferentialRunner, Scenario
from lmyzmail_blackbox.protocols import http_exchange
from lmyzmail_blackbox.runtime import API_KEY, CandidateRuntime, JavaOracleRuntime
from lmyzmail_blackbox.stress_contract import (
    STRESS_CLEANUP_ORACLE_SCENARIOS,
    STRESS_CONCURRENT_ORACLE_SCENARIOS,
    STRESS_DISABLED_SCENARIOS,
    STRESS_ENABLED_SCENARIOS,
    STRESS_STREAMING_SCENARIOS,
    capture_stress_cleanup_during_run_candidate,
    capture_stress_concurrent_start_candidate,
)


@dataclass(slots=True)
class _StressJavaRuntime(JavaOracleRuntime):
    stress_enabled: bool = False
    email_size_kb: int = 1

    def _application_arguments(self) -> list[str]:
        arguments = JavaOracleRuntime._application_arguments(self)
        arguments.extend(
            (
                f"--botmail.stress-test-enabled={str(self.stress_enabled).lower()}",
                "--botmail.stress-test-sender-prefix=stress-sender",
                "--botmail.stress-test-receiver-prefix=stress-receiver",
                "--botmail.stress-test-password=StressBlackboxPass123!",
                "--botmail.stress-test-count=2",
                "--botmail.stress-test-warmup-count=1",
                "--botmail.stress-test-warmup-rounds=1",
                f"--botmail.stress-test-email-size-kb={self.email_size_kb}",
                "--botmail.queue.poll-interval-ms=60000",
            )
        )
        return arguments


@dataclass(slots=True)
class _StressCandidateRuntime(CandidateRuntime):
    stress_enabled: bool = False
    email_size_kb: int = 1
    production_count: int = 2
    warmup_count: int = 1

    def _candidate_configuration(self) -> Path:
        path = CandidateRuntime._candidate_configuration(self)
        value = json.loads(path.read_text(encoding="utf-8"))
        value["stress"] = {
            "enabled": self.stress_enabled,
            "sender_prefix": "stress-sender",
            "receiver_prefix": "stress-receiver",
            "password": "StressBlackboxPass123!",
            "production_count": self.production_count,
            "warmup_count": self.warmup_count,
            "warmup_rounds": 1,
            "email_size_kb": self.email_size_kb,
        }
        value["limits"]["outbound_poll_interval_ms"] = 60_000
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return path


def _candidate(
    repository: Path,
    enabled: bool,
    email_size_kb: int = 1,
    *,
    production_count: int = 2,
    warmup_count: int = 1,
) -> CandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        runtime = cast(_StressCandidateRuntime, _StressCandidateRuntime.from_environment())
        runtime.stress_enabled = enabled
        runtime.email_size_kb = email_size_kb
        runtime.production_count = production_count
        runtime.warmup_count = warmup_count
        runtime.shutdown_timeout = 30.0
        return runtime
    runtime = _StressCandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        ),
        stress_enabled=enabled,
        email_size_kb=email_size_kb,
        production_count=production_count,
        warmup_count=warmup_count,
        shutdown_timeout=30.0,
    )
    return runtime


_STRESS_SENDER = "stress-sender@example.test"
_STRESS_RECEIVER = "stress-receiver@example.test"
_QUEUE_PREFIX = "botmail:mail:queue:"


def _start_stress(candidate: CandidateRuntime) -> None:
    assert candidate.ports is not None
    response = http_exchange(
        "127.0.0.1",
        candidate.ports.http,
        "POST",
        "/api/stress/start",
        headers=(("X-API-Key", API_KEY),),
    )
    assert response.status_code == 200, response.body


def _wait_for(
    predicate: Any,
    description: str,
    *,
    timeout: float = 15.0,
) -> Any:
    deadline = time.monotonic() + timeout
    last_value: Any = None
    while time.monotonic() < deadline:
        last_value = predicate()
        if last_value:
            return last_value
        time.sleep(0.01)
    raise AssertionError(f"timed out waiting for {description}; last={last_value!r}")


def _stress_temp_files(candidate: CandidateRuntime) -> list[Path]:
    assert candidate.workspace is not None
    root = candidate.workspace / "maildir/.lmyzmail-stress"
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*") if path.is_file() or path.is_symlink())


def _stop_application(candidate: CandidateRuntime, *, hard: bool = False) -> None:
    application = candidate._application
    assert application is not None
    pid = application.pid
    if hard:
        application.kill(timeout=5.0)
    else:
        application.stop(timeout=30.0, kill_timeout=3.0)
    with pytest.raises(ProcessLookupError):
        os.killpg(pid, 0)


def _postgres_connection(candidate: CandidateRuntime) -> psycopg.Connection[Any]:
    assert candidate.ports is not None
    return psycopg.connect(
        host="127.0.0.1",
        port=candidate.ports.postgres,
        dbname="lmyzmail",
        user="lmyzmail_test",
        password="",
        connect_timeout=3,
    )


def _stress_queue_rows(candidate: CandidateRuntime) -> list[tuple[int, str]]:
    with _postgres_connection(candidate) as connection:
        return [
            (cast(int, row[0]), cast(str, row[1]))
            for row in connection.execute(
                "SELECT id,status FROM outbound_mail_queue "
                "WHERE sender_address=%s ORDER BY id",
                (_STRESS_SENDER,),
            ).fetchall()
        ]


def _redis_client(candidate: CandidateRuntime) -> redis.Redis:
    assert candidate.ports is not None
    client: redis.Redis = redis.Redis(
        host="127.0.0.1",
        port=candidate.ports.redis,
        db=0,
        socket_connect_timeout=1.0,
        socket_timeout=1.0,
    )
    return client


def _pending_stress_ids(candidate: CandidateRuntime) -> list[int]:
    client = _redis_client(candidate)
    try:
        values = cast(list[bytes], client.lrange(_QUEUE_PREFIX + "pending", 0, -1))
        return [
            int(value)
            for value in values
            if value.isdigit()
            and (
                raw := cast(bytes | None, client.get(f"{_QUEUE_PREFIX}task:{int(value)}"))
            )
            is not None
            and json.loads(raw).get("senderAddress") == _STRESS_SENDER
        ]
    finally:
        client.close()


def _outbound_spool_files(candidate: CandidateRuntime) -> list[Path]:
    assert candidate.workspace is not None
    root = candidate.workspace / "maildir/.lmyzmail-outbound"
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*") if path.is_file() or path.is_symlink())


def _assert_stress_storage_clean(candidate: CandidateRuntime) -> None:
    assert candidate.workspace is not None
    assert _stress_temp_files(candidate) == []
    maildir = candidate.workspace / "maildir"
    leftovers = [
        path.relative_to(maildir).as_posix()
        for address in (_STRESS_SENDER, _STRESS_RECEIVER)
        if (root := maildir / address).exists()
        for path in (root, *root.rglob("*"))
    ]
    application_log = (
        candidate._application.log_tail() if candidate._application is not None else "<none>"
    )
    assert leftovers == [], f"stress Maildir leftovers={leftovers!r}; log={application_log}"
    with _postgres_connection(candidate) as connection:
        row = connection.execute(
            "SELECT count(*) FROM email_index WHERE mailbox_address IN (%s,%s)",
            (_STRESS_SENDER, _STRESS_RECEIVER),
        ).fetchone()
    assert row == (0,)


def _assert_queue_recoverable(candidate: CandidateRuntime) -> None:
    assert candidate.workspace is not None
    rows = _stress_queue_rows(candidate)
    client = _redis_client(candidate)
    try:
        pending = {
            int(value)
            for value in cast(list[bytes], client.lrange(_QUEUE_PREFIX + "pending", 0, -1))
            if value.isdigit()
        }
        for task_id, _status in rows:
            raw = cast(bytes | None, client.get(f"{_QUEUE_PREFIX}task:{task_id}"))
            if raw is not None:
                task = json.loads(raw)
                assert task["senderAddress"] == _STRESS_SENDER
                assert task_id in pending
                message_path = task.get("messageFilePath")
                if isinstance(message_path, str):
                    path = Path(message_path)
                    path.relative_to(candidate.workspace / "maildir/.lmyzmail-outbound")
                    assert path.is_file() and not path.is_symlink()
                else:
                    assert isinstance(task.get("signedContentBase64"), str)
                continue
            assert task_id not in pending
            with _postgres_connection(candidate) as connection:
                spool = connection.execute(
                    "SELECT spool_path,cleanup_state FROM lmyzmail_outbound_spool "
                    "WHERE task_id=%s",
                    (task_id,),
                ).fetchone()
            assert spool is not None
            path = Path(cast(str, spool[0]))
            path.relative_to(candidate.workspace / "maildir/.lmyzmail-outbound")
            assert spool[1] == "OWNED"
            assert path.is_file() and not path.is_symlink()
    finally:
        client.close()


def _profile(enabled: bool) -> tuple[str, tuple[Scenario, ...]]:
    if enabled:
        return "managed-stress-enabled-v7", STRESS_ENABLED_SCENARIOS
    return "managed-stress-disabled-v7", STRESS_DISABLED_SCENARIOS


def _runner(
    repository: Path,
    enabled: bool,
    *,
    record_java: bool = False,
) -> tuple[DifferentialRunner, tuple[Scenario, ...]]:
    name, scenarios = _profile(enabled)
    return (
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java" / name,
            name.rsplit("-v", maxsplit=1)[0],
            record_java=record_java,
        ),
        scenarios,
    )


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.parametrize("enabled", (False, True))
@pytest.mark.timeout(180)
def test_managed_java_stress_golden(
    record_java_golden: bool,
    enabled: bool,
) -> None:
    paths = JavaOracleRuntime().paths
    runner, scenarios = _runner(paths.repository, enabled, record_java=record_java_golden)
    with _StressJavaRuntime(paths=paths, stress_enabled=enabled) as oracle:
        if record_java_golden:
            runner.record_from_java(scenarios, oracle)
        else:
            runner.verify_java(scenarios, oracle)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.parametrize("enabled", (False, True))
@pytest.mark.timeout(180)
def test_rust_candidate_stress_matches_frozen_java_golden(enabled: bool) -> None:
    repository = Path(__file__).resolve().parents[2]
    runner, scenarios = _runner(repository, enabled)
    with _candidate(repository, enabled) as candidate:
        runner.verify_candidate(scenarios, candidate)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_managed_java_stress_streaming_golden(record_java_golden: bool) -> None:
    paths = JavaOracleRuntime().paths
    runner = DifferentialRunner(
        paths.repository,
        paths.repository / "blackbox/golden/java/managed-stress-streaming-v5",
        "managed-stress-streaming",
        record_java=record_java_golden,
    )
    with _StressJavaRuntime(
        paths=paths,
        stress_enabled=True,
        email_size_kb=32,
    ) as oracle:
        if record_java_golden:
            runner.record_from_java(STRESS_STREAMING_SCENARIOS, oracle)
        else:
            runner.verify_java(STRESS_STREAMING_SCENARIOS, oracle)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_stress_streaming_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    runner = DifferentialRunner(
        repository,
        repository / "blackbox/golden/java/managed-stress-streaming-v5",
        "managed-stress-streaming",
    )
    with _candidate(repository, True, 32) as candidate:
        runner.verify_candidate(STRESS_STREAMING_SCENARIOS, candidate)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_managed_java_stress_concurrent_start_evidence(
    record_java_golden: bool,
) -> None:
    paths = JavaOracleRuntime().paths
    runner = DifferentialRunner(
        paths.repository,
        paths.repository
        / "blackbox/golden/java/managed-stress-oracle-evidence-v6",
        "managed-stress-oracle-evidence",
        record_java=record_java_golden,
    )
    with _StressJavaRuntime(paths=paths, stress_enabled=True) as oracle:
        if record_java_golden:
            runner.record_from_java(STRESS_CONCURRENT_ORACLE_SCENARIOS, oracle)
        else:
            runner.verify_java(STRESS_CONCURRENT_ORACLE_SCENARIOS, oracle)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_managed_java_stress_cleanup_race_evidence(
    record_java_golden: bool,
) -> None:
    paths = JavaOracleRuntime().paths
    runner = DifferentialRunner(
        paths.repository,
        paths.repository
        / "blackbox/golden/java/managed-stress-cleanup-oracle-evidence-v5",
        "managed-stress-cleanup-oracle-evidence",
        record_java=record_java_golden,
    )
    with _StressJavaRuntime(paths=paths, stress_enabled=True) as oracle:
        if record_java_golden:
            runner.record_from_java(STRESS_CLEANUP_ORACLE_SCENARIOS, oracle)
        else:
            runner.verify_java(STRESS_CLEANUP_ORACLE_SCENARIOS, oracle)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_bounds_overlapping_stress_runs() -> None:
    repository = Path(__file__).resolve().parents[2]
    differences = json.loads(
        (repository / "blackbox/manifests/behavior-differences.json").read_text(
            encoding="utf-8"
        )
    )
    entry = next(
        item
        for item in differences["differences"]
        if item["id"] == "stress-bounded-run-admission"
    )
    assert entry["evidence"]["oracle_golden"].endswith(
        "/observations/http/stress/oracle-concurrent-start.json"
    )

    with _candidate(repository, True) as candidate:
        observed = capture_stress_concurrent_start_candidate(candidate)
    assert observed["first"]["body_json"]["round"] == 1
    assert observed["second"]["body_json"] == {
        "error": "busy",
        "message": "A stress test is already running.",
    }


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_serializes_cleanup_with_active_run() -> None:
    repository = Path(__file__).resolve().parents[2]
    differences = json.loads(
        (repository / "blackbox/manifests/behavior-differences.json").read_text(
            encoding="utf-8"
        )
    )
    entry = next(
        item
        for item in differences["differences"]
        if item["id"] == "stress-cleanup-run-serialization"
    )
    assert entry["evidence"]["oracle_golden"].endswith(
        "/observations/http/stress/oracle-cleanup-during-run.json"
    )

    with _candidate(repository, True) as candidate:
        observed = capture_stress_cleanup_during_run_candidate(candidate)
    assert observed["started"]["body_json"]["round"] == 1
    assert observed["cleanup"]["body_json"] == {
        "error": "busy",
        "message": "A stress test is already running.",
    }


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(240)
def test_rust_candidate_sigterm_during_stress_generation_cleans_owned_state() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(
        repository,
        True,
        10_240,
        production_count=128,
        warmup_count=128,
    ) as candidate:
        _start_stress(candidate)
        files = cast(
            list[Path],
            _wait_for(
                lambda: _stress_temp_files(candidate),
                "streaming stress body generation",
            ),
        )
        assert files

        _stop_application(candidate)

        _assert_stress_storage_clean(candidate)
        _assert_queue_recoverable(candidate)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(240)
def test_rust_candidate_sigterm_during_stress_enqueue_preserves_recovery() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository, True, 32) as candidate:
        blocker = _postgres_connection(candidate)
        try:
            blocker.execute(
                "SELECT pg_advisory_lock(hashtextextended(%s::text, 0))",
                ("lmyzmail:outbound:queue",),
            )
            _start_stress(candidate)
            files = cast(
                list[Path],
                _wait_for(
                    lambda: _outbound_spool_files(candidate),
                    "materialized stress enqueue blocked before commit",
                ),
            )
            assert files
            assert _stress_queue_rows(candidate) == []
            assert _pending_stress_ids(candidate) == []
            _stop_application(candidate)
        finally:
            blocker.close()

        _assert_stress_storage_clean(candidate)
        assert _outbound_spool_files(candidate) == []
        _assert_queue_recoverable(candidate)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(240)
def test_rust_candidate_sigterm_during_stress_delivery_keeps_queue_consistent() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository, True, 32) as candidate:
        _start_stress(candidate)
        pending = cast(
            list[int],
            _wait_for(
                lambda: _pending_stress_ids(candidate),
                "published stress delivery task",
            ),
        )
        assert pending

        _stop_application(candidate)

        _assert_stress_storage_clean(candidate)
        _assert_queue_recoverable(candidate)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(240)
def test_rust_candidate_restart_recovers_sigkill_stress_state() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(
        repository,
        True,
        10_240,
        production_count=128,
        warmup_count=128,
    ) as candidate:
        _start_stress(candidate)
        _wait_for(
            lambda: _stress_temp_files(candidate),
            "streaming stress body before hard crash",
        )
        application = candidate._application
        assert application is not None
        os.killpg(application.pid, signal.SIGSTOP)
        assert _stress_temp_files(candidate)
        _stop_application(candidate, hard=True)
        assert _stress_temp_files(candidate)

        candidate._start_application()

        _assert_stress_storage_clean(candidate)
        _assert_queue_recoverable(candidate)
        _stop_application(candidate)
