from __future__ import annotations

import json
import os
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast

import psycopg
import pytest
import redis

from lmyzmail_blackbox.differential import RuntimeTarget
from lmyzmail_blackbox.golden import GoldenAttestation, GoldenStore
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.report_contract import (
    _capture_report_publications,
    _drain_report_dns_queries,
    _expect_json,
    _redis_pending,
    _report_database_state,
    _request,
    _restore_volume_threshold,
    _seed_volume_threshold,
    _sent_files,
    report_dns_server,
)
from lmyzmail_blackbox.runtime import CandidateRuntime
from lmyzmail_blackbox.scripted_dns import DnsQuery, ScriptedDnsServer

_HOST = "127.0.0.1"
_REPORT_DATE = "2024-01-01"
_NORMALIZERS = (
    "header:date:http-date",
    "json-object-order:reports-contract",
    "report-id:uuid-v4",
    "rfc5322:parsed-message",
    "report-body:wall-clock-period",
    "redis-domain-status:updated-at",
    "maildir:generated-filename",
)


class _ConcurrencyJavaRuntime(PersistentJavaOracleRuntime):
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


class _ConcurrencyCandidateRuntime(CandidateRuntime):
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


def _candidate(repository: Path, dns: ScriptedDnsServer) -> _ConcurrencyCandidateRuntime:
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
    return _ConcurrencyCandidateRuntime(
        command_template=command_template,
        dns=dns,
    )


def _connect_postgres(
    target: RuntimeTarget,
) -> psycopg.Connection[tuple[Any, ...]]:
    if target.ports is None:
        raise AssertionError("report concurrency target is not started")
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


def _wait_for_blocked_domain_query(
    connection: psycopg.Connection[tuple[Any, ...]],
    request: Future[Any],
) -> dict[str, str]:
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        row = connection.execute(
            """
            SELECT activity.wait_event_type, activity.wait_event
            FROM pg_locks AS lock
            JOIN pg_stat_activity AS activity ON activity.pid = lock.pid
            WHERE lock.database = (SELECT oid FROM pg_database WHERE datname = current_database())
              AND lock.relation = 'inbound_dmarc_log'::regclass
              AND lock.mode = 'AccessShareLock'
              AND lock.granted = false
            ORDER BY activity.query_start
            LIMIT 1
            """
        ).fetchone()
        if row is not None:
            wait_event_type = cast(str, row[0])
            wait_event = cast(str, row[1])
            return {
                "queryClass": "DMARC domain discovery",
                "waitEventType": wait_event_type,
                "waitEvent": wait_event,
            }
        if request.done():
            response = request.result()
            raise AssertionError(
                "first report trigger completed before its domain query was blocked: "
                f"{response!r}"
            )
        time.sleep(0.05)
    raise AssertionError("first report trigger did not reach the blocked domain query")


def _capture_concurrent_trigger(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise AssertionError("report concurrency target ports are unavailable")
    if _drain_report_dns_queries(target):
        raise AssertionError("report concurrency DNS trace was not initially empty")
    baseline_database = _report_database_state(target)
    original = _seed_volume_threshold(target)
    client: redis.Redis = redis.Redis(
        host=_HOST,
        port=target.ports.redis,
        decode_responses=False,
    )
    try:
        before_database = _report_database_state(target)
        before_pending = _redis_pending(client)
        before_files = _sent_files(target)
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="report-trigger") as executor:
            with _connect_postgres(target) as blocker:
                blocker.execute("LOCK TABLE inbound_dmarc_log IN ACCESS EXCLUSIVE MODE")
                first = executor.submit(
                    _request,
                    target,
                    "POST",
                    f"/api/reports/trigger?date={_REPORT_DATE}",
                )
                blocked_query = _wait_for_blocked_domain_query(blocker, first)
                second_response = _expect_json(
                    _request(
                        target,
                        "POST",
                        f"/api/reports/trigger?date={_REPORT_DATE}",
                    ),
                    status=200,
                    body={
                        "date": _REPORT_DATE,
                        "dmarcSent": 0,
                        "dmarcFailed": 0,
                        "tlsSent": 0,
                        "tlsFailed": 0,
                        "error": "Already running",
                    },
                )
                if _redis_pending(client) != before_pending:
                    raise AssertionError("overlapping report trigger mutated the Redis queue")
                if _sent_files(target) != before_files:
                    raise AssertionError("overlapping report trigger wrote a Sent Maildir file")
                if _drain_report_dns_queries(target):
                    raise AssertionError("blocked report trigger reached DNS before lock release")
            first_response = _expect_json(
                first.result(timeout=15.0),
                status=200,
                body={
                    "date": _REPORT_DATE,
                    "dmarcSent": 1,
                    "dmarcFailed": 0,
                    "tlsSent": 1,
                    "tlsFailed": 0,
                    "error": "none",
                },
            )

        pending_order, tasks, messages, added_files = _capture_report_publications(
            target,
            client,
            before_pending,
            before_files,
        )
        after_database = _report_database_state(target)
        if after_database != before_database:
            raise AssertionError("concurrent report triggers mutated their source rows")
        queries = _drain_report_dns_queries(target)
        expected_queries = (
            "_dmarc.sender.example",
            "sender.example._report._dmarc.example.test",
            "_smtp._tls.recipient.example",
        )
        if tuple(query.qname for query in queries) != expected_queries:
            raise AssertionError(f"concurrent report DNS trace changed: {queries!r}")
    finally:
        client.close()
        _restore_volume_threshold(target, original)

    if _report_database_state(target) != baseline_database:
        raise AssertionError("report concurrency threshold fixture was not restored")
    return {
        "blockedFirstRequest": blocked_query,
        "overlappingResponse": second_response,
        "stateWhileFirstBlocked": {
            "redisQueueUnchanged": True,
            "maildirUnchanged": True,
            "dnsQueries": [],
        },
        "admittedResponse": first_response,
        "dnsQueries": [query.qname for query in queries],
        "queue": {"pendingOrder": pending_order, "tasks": tasks},
        "maildir": {
            "addedCount": len(added_files),
            "messages": messages,
            "noTemporaryFiles": not any(".tmp" in key for key in added_files),
        },
        "sourceDatabaseUnchanged": True,
        "thresholdCountsRestored": True,
        "singleAdmission": True,
    }


def _assert_golden(repository: Path, observed: dict[str, Any], *, record: bool) -> None:
    attestation = GoldenAttestation.from_repository(
        repository,
        profile="report-trigger-concurrency-v1",
        normalizers=_NORMALIZERS,
    )
    GoldenStore(
        repository
        / "evidence/compatibility/report-trigger-concurrency-v1/golden",
        attestation,
        record=record,
    ).assert_observation("observation.json", observed)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(120)
def test_java_report_trigger_single_admission(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[3]
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    if record:
        with report_dns_server() as dns:
            with _ConcurrencyJavaRuntime(tmp_path / "java-record", dns) as runtime:
                _assert_golden(
                    repository,
                    _capture_concurrent_trigger(runtime),
                    record=True,
                )
    with report_dns_server() as dns:
        with _ConcurrencyJavaRuntime(tmp_path / "java-verify", dns) as runtime:
            _assert_golden(
                repository,
                _capture_concurrent_trigger(runtime),
                record=False,
            )


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(120)
def test_rust_report_trigger_single_admission() -> None:
    repository = Path(__file__).resolve().parents[3]
    with report_dns_server() as dns:
        with _candidate(repository, dns) as runtime:
            _assert_golden(
                repository,
                _capture_concurrent_trigger(runtime),
                record=False,
            )
