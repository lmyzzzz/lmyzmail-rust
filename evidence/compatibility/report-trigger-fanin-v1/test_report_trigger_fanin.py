from __future__ import annotations

import json
import os
import threading
import time
from concurrent.futures import ALL_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import psycopg
import pytest
import redis

from lmyzmail_blackbox.differential import RuntimeTarget
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.report_contract import (
    _drain_report_dns_queries,
    _expect_json,
    _redis_pending,
    _report_database_state,
    _request,
    _sent_files,
    report_dns_server,
)
from lmyzmail_blackbox.runtime import CandidateRuntime
from lmyzmail_blackbox.scripted_dns import DnsQuery, ScriptedDnsServer

_HOST = "127.0.0.1"
_NO_DATA_DATE = "2024-01-02"
_OVERLAP_COUNT = 32
_OVERLAP_COMPLETION_SECONDS = 5.0


class _FaninJavaRuntime(PersistentJavaOracleRuntime):
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


class _FaninCandidateRuntime(CandidateRuntime):
    def __init__(self, *, command_template: tuple[str, ...], dns: ScriptedDnsServer) -> None:
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


@dataclass(frozen=True, slots=True)
class _OracleTarget:
    runtime: _FaninJavaRuntime

    @property
    def target_kind(self) -> str:
        return "java-oracle"

    @property
    def workspace(self) -> Path | None:
        return self.runtime.workspace

    @property
    def ports(self) -> PortSet | None:
        return self.runtime.ports

    def drain_report_dns_queries(self) -> tuple[DnsQuery, ...]:
        return self.runtime.drain_report_dns_queries()


def _candidate(repository: Path, dns: ScriptedDnsServer) -> _FaninCandidateRuntime:
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
    return _FaninCandidateRuntime(command_template=command_template, dns=dns)


def _connect_postgres(
    target: RuntimeTarget,
) -> psycopg.Connection[tuple[Any, ...]]:
    if target.ports is None:
        raise AssertionError("report fan-in target is not started")
    connection = psycopg.connect(
        host=_HOST,
        port=target.ports.postgres,
        user="lmyzmail_test",
        dbname="lmyzmail",
        connect_timeout=5,
        autocommit=False,
    )
    connection.execute("SET statement_timeout = '30s'")
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
            return {
                "queryClass": "DMARC domain discovery",
                "waitEventType": cast(str, row[0]),
                "waitEvent": cast(str, row[1]),
            }
        if request.done():
            raise AssertionError(
                "admitted report trigger completed before its domain query was blocked: "
                f"{request.result()!r}"
            )
        time.sleep(0.025)
    raise AssertionError("admitted report trigger did not reach the blocked domain query")


def _storage_state(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise AssertionError("report fan-in target is not started")
    client: redis.Redis = redis.Redis(
        host=_HOST,
        port=target.ports.redis,
        decode_responses=False,
    )
    try:
        return {
            "database": _report_database_state(target),
            "redis": _redis_pending(client),
            "maildir": sorted(_sent_files(target)),
        }
    finally:
        client.close()


def _non_database_state(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise AssertionError("report fan-in target is not started")
    client: redis.Redis = redis.Redis(
        host=_HOST,
        port=target.ports.redis,
        decode_responses=False,
    )
    try:
        return {
            "redis": _redis_pending(client),
            "maildir": sorted(_sent_files(target)),
        }
    finally:
        client.close()


def _overlap_request(
    target: RuntimeTarget,
    barrier: threading.Barrier,
) -> dict[str, Any]:
    barrier.wait(timeout=5.0)
    return _expect_json(
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


def _capture(target: RuntimeTarget) -> dict[str, Any]:
    if _drain_report_dns_queries(target):
        raise AssertionError("report fan-in DNS trace was not initially empty")
    before = _storage_state(target)
    barrier = threading.Barrier(_OVERLAP_COUNT + 1)
    with ThreadPoolExecutor(
        max_workers=_OVERLAP_COUNT + 1,
        thread_name_prefix="report-trigger-fanin",
    ) as executor:
        with _connect_postgres(target) as blocker:
            blocker.execute("LOCK TABLE inbound_dmarc_log IN ACCESS EXCLUSIVE MODE")
            first = executor.submit(
                _request,
                target,
                "POST",
                f"/api/reports/trigger?date={_NO_DATA_DATE}",
            )
            blocked = _wait_for_blocked_domain_query(blocker, first)
            overlaps = [
                executor.submit(_overlap_request, target, barrier)
                for _ in range(_OVERLAP_COUNT)
            ]
            barrier.wait(timeout=5.0)
            done, pending = wait(
                overlaps,
                timeout=_OVERLAP_COMPLETION_SECONDS,
                return_when=ALL_COMPLETED,
            )
            if pending:
                raise AssertionError(
                    f"{len(pending)} overlapping report triggers queued behind the guard"
                )
            overlap_responses = [future.result() for future in overlaps]
            if len(done) != _OVERLAP_COUNT:
                raise AssertionError("report fan-in completion count changed")
            if any(response != overlap_responses[0] for response in overlap_responses[1:]):
                raise AssertionError("report fan-in responses were not byte-equivalent")
            while_blocked = _non_database_state(target)
            if while_blocked["redis"] != before["redis"]:
                raise AssertionError("report fan-in mutated Redis while the first query blocked")
            if while_blocked["maildir"] != before["maildir"]:
                raise AssertionError("report fan-in mutated Maildir while the first query blocked")
            queries_while_blocked = _drain_report_dns_queries(target)
            if queries_while_blocked:
                raise AssertionError(
                    f"report fan-in reached DNS while blocked: {queries_while_blocked!r}"
                )
        admitted = _expect_json(
            first.result(timeout=15.0),
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
    after = _storage_state(target)
    if after != before:
        raise AssertionError("report fan-in mutated storage after the admitted request completed")
    queries = _drain_report_dns_queries(target)
    if queries:
        raise AssertionError(f"no-data report fan-in reached DNS: {queries!r}")
    return {
        "blockedFirstRequest": blocked,
        "fanIn": {
            "count": _OVERLAP_COUNT,
            "allCompletedWhileLockHeld": True,
            "completionBudgetSeconds": _OVERLAP_COMPLETION_SECONDS,
            "uniformResponse": overlap_responses[0],
        },
        "admittedResponse": admitted,
        "state": {
            "dnsQueries": [],
            "redisQueueUnchanged": True,
            "maildirUnchanged": True,
            "sourceDatabaseUnchanged": True,
        },
    }


def _assert_frozen_observation(name: str, observation: dict[str, Any]) -> None:
    path = Path(__file__).with_name(name)
    expected = json.loads(path.read_text(encoding="utf-8"))
    if observation != expected:
        raise AssertionError(
            f"report trigger fan-in observation changed: "
            f"actual={observation!r}, expected={expected!r}"
        )


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(120)
def test_observe_java_report_trigger_fanin(tmp_path: Path) -> None:
    with report_dns_server() as dns:
        with _FaninJavaRuntime(tmp_path / "java-report-fanin", dns) as runtime:
            observation = _capture(_OracleTarget(runtime))
    _assert_frozen_observation("java-observation.json", observation)
    print(json.dumps(observation, ensure_ascii=False, sort_keys=True, indent=2))


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(120)
def test_observe_rust_report_trigger_fanin() -> None:
    repository = Path(__file__).resolve().parents[3]
    with report_dns_server() as dns:
        with _candidate(repository, dns) as runtime:
            observation = _capture(runtime)
    _assert_frozen_observation("candidate-observation.json", observation)
    print(json.dumps(observation, ensure_ascii=False, sort_keys=True, indent=2))
