from __future__ import annotations

import json
import os
import socket
import struct
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast

import psycopg
import pytest
import redis

from lmyzmail_blackbox.differential import RuntimeTarget
from lmyzmail_blackbox.golden import GoldenAttestation, GoldenStore, canonical_json
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.protocols import build_http_request
from lmyzmail_blackbox.report_contract import (
    _drain_report_dns_queries,
    _expect_json,
    _redis_pending,
    _report_database_state,
    _request,
    _sent_files,
    report_dns_server,
)
from lmyzmail_blackbox.runtime import API_KEY, CandidateRuntime
from lmyzmail_blackbox.scripted_dns import DnsQuery, ScriptedDnsServer

_HOST = "127.0.0.1"
_NO_DATA_DATE = "2024-01-02"
_FROZEN_DEFINITION_TREE_SHA256 = (
    "f4747bee86575a8f59725e02829a459ceb88961dadfbf858113b63a517b99d4c"
)
_GOLDEN_NORMALIZERS = ("header:date:http-date", "json-object-order:reports-contract")


class _DisconnectJavaRuntime(PersistentJavaOracleRuntime):
    def __init__(self, workspace: Path, dns: ScriptedDnsServer) -> None:
        super().__init__(workspace)
        self.report_dns = dns

    def _application_arguments(self) -> list[str]:
        arguments = super()._application_arguments()
        jar_index = arguments.index("-jar")
        arguments[jar_index:jar_index] = [
            f"-Ddns.server={self.report_dns.host}:{self.report_dns.port}",
            "-Dbotmail.reporting.dmarc-report-sender-address=qa@example.test",
            "-Dbotmail.reporting.tls-report-sender-address=qa@example.test",
            "-Dbotmail.reporting.organization-name=Blackbox Reports",
            "-Dbotmail.reporting.organization-email=reports@example.test",
            "-Dbotmail.queue.poll-interval-ms=60000",
        ]
        return arguments

    def drain_report_dns_queries(self) -> tuple[DnsQuery, ...]:
        return self.report_dns.drain_queries()


class _DisconnectCandidateRuntime(CandidateRuntime):
    def __init__(
        self,
        *,
        command_template: tuple[str, ...],
        dns: ScriptedDnsServer,
    ) -> None:
        super().__init__(command_template=command_template)
        self.report_dns = dns

    @property
    def requires_qa_account(self) -> bool:
        return False

    def _candidate_configuration(self) -> Path:
        path = super()._candidate_configuration()
        value = json.loads(path.read_text(encoding="utf-8"))
        value["reporting"] = {
            "enabled": True,
            "auto_send_enabled": False,
            "dns_server": f"{self.report_dns.host}:{self.report_dns.port}",
            "dmarc_report_sender_address": "qa@example.test",
            "tls_report_sender_address": "qa@example.test",
            "organization_name": "Blackbox Reports",
            "organization_email": "reports@example.test",
            "http_delivery_enabled": False,
        }
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def _application_arguments(self) -> list[str]:
        return [
            *super()._application_arguments(),
            "--lmyzmail.reporting.enabled=true",
            "--lmyzmail.queue.poll-interval-ms=60000",
            "--lmyzmail.maildir.max-files-per-directory=1",
        ]

    def _start_postgres(self) -> None:
        super()._start_postgres()
        workspace, ports = self._require_state()
        psql = self.paths.runtime / "postgres-root/usr/lib/postgresql/16/bin/psql"
        seed = self.paths.repository / "blackbox/fixtures/legacy/postgres-seed.sql"
        self._run_checked(
            [
                str(psql),
                "--host=127.0.0.1",
                f"--port={ports.postgres}",
                "--username=lmyzmail_test",
                "--dbname=lmyzmail",
                "--single-transaction",
                "--set=ON_ERROR_STOP=1",
                f"--file={seed}",
            ],
            env=self._postgres_env(),
            log_path=workspace / "postgres-seed.log",
        )

    def drain_report_dns_queries(self) -> tuple[DnsQuery, ...]:
        return self.report_dns.drain_queries()


def _candidate(repository: Path, dns: ScriptedDnsServer) -> _DisconnectCandidateRuntime:
    configured = os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON")
    command_template = (
        CandidateRuntime.from_environment().command_template
        if configured is not None
        else (
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        )
    )
    return _DisconnectCandidateRuntime(command_template=command_template, dns=dns)


def _connect_postgres(
    target: RuntimeTarget,
) -> psycopg.Connection[tuple[Any, ...]]:
    if target.ports is None:
        raise AssertionError("report disconnect target is not started")
    connection = psycopg.connect(
        host=_HOST,
        port=target.ports.postgres,
        user="lmyzmail_test",
        dbname="lmyzmail",
        connect_timeout=5,
        autocommit=False,
    )
    connection.execute("SET statement_timeout = '10s'")
    connection.execute("SET lock_timeout = '5s'")
    return connection


def _blocked_domain_query_count(
    connection: psycopg.Connection[tuple[Any, ...]],
) -> int:
    row = connection.execute(
        """
        SELECT count(*)
        FROM pg_locks AS lock
        WHERE lock.database = (SELECT oid FROM pg_database WHERE datname = current_database())
          AND lock.relation = 'inbound_dmarc_log'::regclass
          AND lock.mode = 'AccessShareLock'
          AND lock.granted = false
        """
    ).fetchone()
    if row is None:
        raise AssertionError("blocked report query count returned no row")
    return cast(int, row[0])


def _wait_for_blocked_count(
    connection: psycopg.Connection[tuple[Any, ...]],
    expected: int,
    *,
    request: Future[Any] | None = None,
    timeout_seconds: float = 5.0,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        actual = _blocked_domain_query_count(connection)
        if actual == expected:
            return
        if request is not None and request.done():
            raise AssertionError(
                f"report request completed before blocked query count became {expected}: "
                f"{request.result()!r}"
            )
        time.sleep(0.025)
    raise AssertionError(
        f"blocked report query count did not become {expected}; "
        f"actual={_blocked_domain_query_count(connection)}"
    )


def _open_trigger_socket(target: RuntimeTarget) -> socket.socket:
    if target.ports is None:
        raise AssertionError("report disconnect target ports are unavailable")
    request = build_http_request(
        "POST",
        f"/api/reports/trigger?date={_NO_DATA_DATE}",
        host=f"{_HOST}:{target.ports.http}",
        headers=(("X-API-Key", API_KEY),),
    )
    client = socket.create_connection((_HOST, target.ports.http), timeout=5.0)
    try:
        client.sendall(request)
        return client
    except BaseException:
        client.close()
        raise


def _reset_close(client: socket.socket) -> None:
    client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    client.close()


def _state_before(target: RuntimeTarget) -> tuple[dict[str, Any], list[int], dict[str, Path]]:
    if target.ports is None:
        raise AssertionError("report disconnect target ports are unavailable")
    client: redis.Redis = redis.Redis(
        host=_HOST,
        port=target.ports.redis,
        decode_responses=False,
    )
    try:
        return _report_database_state(target), _redis_pending(client), _sent_files(target)
    finally:
        client.close()


def _assert_state_unchanged(
    target: RuntimeTarget,
    before: tuple[dict[str, Any], list[int], dict[str, Path]],
) -> None:
    if target.ports is None:
        raise AssertionError("report disconnect target ports are unavailable")
    client: redis.Redis = redis.Redis(
        host=_HOST,
        port=target.ports.redis,
        decode_responses=False,
    )
    try:
        if _report_database_state(target) != before[0]:
            raise AssertionError("disconnected report trigger mutated source rows")
        if _redis_pending(client) != before[1]:
            raise AssertionError("disconnected report trigger mutated the Redis queue")
        if _sent_files(target) != before[2]:
            raise AssertionError("disconnected report trigger wrote a Sent Maildir file")
    finally:
        client.close()


def _capture_java_disconnect(target: RuntimeTarget) -> dict[str, Any]:
    if _drain_report_dns_queries(target):
        raise AssertionError("Java disconnect DNS trace was not initially empty")
    before = _state_before(target)
    with _connect_postgres(target) as blocker:
        blocker.execute("LOCK TABLE inbound_dmarc_log IN ACCESS EXCLUSIVE MODE")
        first = _open_trigger_socket(target)
        _wait_for_blocked_count(blocker, 1)
        _reset_close(first)
        time.sleep(0.25)
        if _blocked_domain_query_count(blocker) != 1:
            raise AssertionError("Java cancelled the blocked report query after client RST")
        overlap = _expect_json(
            _request(target, "POST", f"/api/reports/trigger?date={_NO_DATA_DATE}"),
            status=200,
            body={
                "date": _NO_DATA_DATE,
                "dmarcSent": 0,
                "dmarcFailed": 0,
                "tlsSent": 0,
                "tlsFailed": 0,
                "error": "Already running",
            },
        )
        if _blocked_domain_query_count(blocker) != 1:
            raise AssertionError("Java overlap changed the retained blocked query count")
    _wait_for_no_active_report_query(target)
    _assert_state_unchanged(target, before)
    queries = _drain_report_dns_queries(target)
    if queries:
        raise AssertionError(f"no-data Java disconnect reached DNS: {queries!r}")
    return {
        "transport": "TCP RST after complete authenticated request",
        "blockedBeforeDisconnect": True,
        "blockedQueryRetainedAfterDisconnect": True,
        "overlapResponse": overlap,
        "state": {
            "dnsQueries": [],
            "redisQueueUnchanged": True,
            "maildirUnchanged": True,
            "sourceDatabaseUnchanged": True,
        },
    }


def _wait_for_no_active_report_query(target: RuntimeTarget) -> None:
    with _connect_postgres(target) as observer:
        _wait_for_blocked_count(observer, 0)


def _capture_rust_disconnect(target: RuntimeTarget) -> dict[str, Any]:
    if _drain_report_dns_queries(target):
        raise AssertionError("Rust disconnect DNS trace was not initially empty")
    before = _state_before(target)
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="report-retry") as executor:
        with _connect_postgres(target) as blocker:
            blocker.execute("LOCK TABLE inbound_dmarc_log IN ACCESS EXCLUSIVE MODE")
            first = _open_trigger_socket(target)
            _wait_for_blocked_count(blocker, 1)
            _reset_close(first)
            _wait_for_blocked_count(blocker, 0, timeout_seconds=3.0)
            retry = executor.submit(
                _request,
                target,
                "POST",
                f"/api/reports/trigger?date={_NO_DATA_DATE}",
            )
            _wait_for_blocked_count(blocker, 1, request=retry)
        retry_response = _expect_json(
            retry.result(timeout=10.0),
            status=200,
            body={
                "date": _NO_DATA_DATE,
                "dmarcSent": 0,
                "dmarcFailed": 0,
                "tlsSent": 0,
                "tlsFailed": 0,
                "error": "none",
            },
        )
    _assert_state_unchanged(target, before)
    queries = _drain_report_dns_queries(target)
    if queries:
        raise AssertionError(f"no-data Rust disconnect reached DNS: {queries!r}")
    return {
        "transport": "TCP RST after complete authenticated request",
        "blockedBeforeDisconnect": True,
        "blockedQueryCancelledAfterDisconnect": True,
        "guardReleasedBeforeRetry": True,
        "retryReachedDatabaseBeforeLockRelease": True,
        "retryResponse": retry_response,
        "state": {
            "dnsQueries": [],
            "redisQueueUnchanged": True,
            "maildirUnchanged": True,
            "sourceDatabaseUnchanged": True,
        },
    }


def _assert_java_golden(repository: Path, observed: dict[str, Any], *, record: bool) -> None:
    attestation = GoldenAttestation.from_repository(
        repository,
        profile="report-trigger-disconnect-java-v1",
        normalizers=_GOLDEN_NORMALIZERS,
    )
    if attestation.harness_definition_sha256 != _FROZEN_DEFINITION_TREE_SHA256:
        raise AssertionError(
            "report disconnect supplemental definition tree changed: "
            f"expected={_FROZEN_DEFINITION_TREE_SHA256}, "
            f"actual={attestation.harness_definition_sha256}"
        )
    GoldenStore(
        repository / "evidence/compatibility/report-trigger-disconnect-v1/java-golden",
        attestation,
        record=record,
    ).assert_observation("observation.json", observed)


def _assert_candidate_evidence(repository: Path, observed: dict[str, Any]) -> None:
    path = (
        repository
        / "evidence/compatibility/report-trigger-disconnect-v1/candidate-observation.json"
    )
    actual = canonical_json(observed)
    if not path.exists() and os.environ.get("LMYZMAIL_RECORD_CANDIDATE_EVIDENCE") == "1":
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(actual)
            stream.flush()
            os.fsync(stream.fileno())
    if not path.is_file():
        raise AssertionError("candidate disconnect evidence is missing")
    expected = path.read_bytes()
    if expected != actual:
        raise AssertionError("candidate disconnect observation changed")


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(120)
def test_java_report_trigger_retains_work_after_disconnect(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[3]
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    if record:
        with report_dns_server() as dns:
            with _DisconnectJavaRuntime(tmp_path / "java-record", dns) as runtime:
                _assert_java_golden(repository, _capture_java_disconnect(runtime), record=True)
    with report_dns_server() as dns:
        with _DisconnectJavaRuntime(tmp_path / "java-verify", dns) as runtime:
            _assert_java_golden(repository, _capture_java_disconnect(runtime), record=False)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(120)
def test_rust_report_trigger_cancels_work_after_disconnect() -> None:
    repository = Path(__file__).resolve().parents[3]
    with report_dns_server() as dns:
        with _candidate(repository, dns) as runtime:
            _assert_candidate_evidence(repository, _capture_rust_disconnect(runtime))
