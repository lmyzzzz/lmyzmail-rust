from __future__ import annotations

import json
import os
import signal
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import psycopg
import pytest
import redis

from lmyzmail_blackbox.differential import RuntimeTarget
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.protocols import RawHttpResponse, http_exchange
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

_NO_DATA_DATE = "2024-01-02"
_PAUSED_OBSERVATION_SECONDS = 12.0
_FIRST_RESPONSE_TIMEOUT_SECONDS = 30.0


class _PostgresOutageMixin:
    report_dns: ScriptedDnsServer
    workspace: Path | None
    ports: PortSet | None
    _postgres: Any

    def pause_postgres_for_test(self) -> None:
        if self._postgres is None:
            raise RuntimeError("PostgreSQL is not running")
        os.killpg(self._postgres.pid, signal.SIGSTOP)

    def resume_postgres_for_test(self) -> None:
        if self._postgres is None:
            raise RuntimeError("PostgreSQL is not running")
        os.killpg(self._postgres.pid, signal.SIGCONT)

    def drain_report_dns_queries(self) -> tuple[DnsQuery, ...]:
        return self.report_dns.drain_queries()


class _OutageJavaRuntime(_PostgresOutageMixin, PersistentJavaOracleRuntime):
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


class _OutageCandidateRuntime(_PostgresOutageMixin, CandidateRuntime):
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


@dataclass(frozen=True, slots=True)
class _OracleTarget:
    runtime: _OutageJavaRuntime

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


def _candidate(repository: Path, dns: ScriptedDnsServer) -> _OutageCandidateRuntime:
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
    return _OutageCandidateRuntime(command_template=command_template, dns=dns)


def _storage_state(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise AssertionError("report outage target is not started")
    client: redis.Redis = redis.Redis(
        host="127.0.0.1",
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


def _connect_postgres(
    target: RuntimeTarget,
) -> psycopg.Connection[tuple[Any, ...]]:
    if target.ports is None:
        raise AssertionError("report outage target is not started")
    connection = psycopg.connect(
        host="127.0.0.1",
        port=target.ports.postgres,
        user="lmyzmail_test",
        dbname="lmyzmail",
        connect_timeout=5,
        autocommit=False,
    )
    connection.execute("SET statement_timeout = '30s'")
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


def _wait_for_blocked_query(
    connection: psycopg.Connection[tuple[Any, ...]],
    *,
    timeout_seconds: float = 5.0,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _blocked_domain_query_count(connection) == 1:
            return
        time.sleep(0.025)
    raise AssertionError("report domain query did not block before PostgreSQL pause")


def _long_request(target: RuntimeTarget) -> RawHttpResponse:
    if target.ports is None:
        raise AssertionError("report outage target ports are unavailable")
    return http_exchange(
        "127.0.0.1",
        target.ports.http,
        "POST",
        f"/api/reports/trigger?date={_NO_DATA_DATE}",
        headers=(("X-API-Key", API_KEY),),
        timeout=_FIRST_RESPONSE_TIMEOUT_SECONDS,
        max_response=1 * 1024 * 1024,
    )


def _capture(runtime: _PostgresOutageMixin, target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise AssertionError("report outage target ports are unavailable")
    if _drain_report_dns_queries(target):
        raise AssertionError("report outage DNS trace was not initially empty")
    before = _storage_state(target)
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="report-postgres-outage") as executor:
        with _connect_postgres(target) as blocker:
            blocker.execute("LOCK TABLE inbound_dmarc_log IN ACCESS EXCLUSIVE MODE")
            first = executor.submit(_long_request, target)
            _wait_for_blocked_query(blocker)
            runtime.pause_postgres_for_test()
            try:
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
                deadline = time.monotonic() + _PAUSED_OBSERVATION_SECONDS
                while not first.done() and time.monotonic() < deadline:
                    time.sleep(0.025)
                completed_while_paused = first.done()
            finally:
                runtime.resume_postgres_for_test()
        outage_response = first.result(timeout=10.0)
    expected_error = (
        "none"
        if target.target_kind == "java-oracle"
        else "reporting database deadline exceeded"
    )
    outage_snapshot = _expect_json(
        outage_response,
        status=200,
        body={
            "date": _NO_DATA_DATE,
            "dmarcSent": 0,
            "dmarcFailed": 0,
            "tlsSent": 0,
            "tlsFailed": 0,
            "error": expected_error,
        },
    )
    after = _storage_state(target)
    if after != before:
        raise AssertionError(f"report outage mutated storage: before={before!r}, after={after!r}")
    retry = _expect_json(
        _request(target, "POST", f"/api/reports/trigger?date={_NO_DATA_DATE}"),
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
    queries = _drain_report_dns_queries(target)
    if queries:
        raise AssertionError(f"PostgreSQL outage reached DNS: {queries!r}")
    return {
        "postgresFault": "SIGSTOP process group with existing connections retained",
        "completedWhilePostgresPaused": completed_while_paused,
        "pausedObservationSeconds": _PAUSED_OBSERVATION_SECONDS,
        "overlapResponse": overlap,
        "outageResponse": outage_snapshot,
        "guardReleasedAfterRecovery": True,
        "retryResponse": retry,
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
            f"report PostgreSQL outage observation changed: "
            f"actual={observation!r}, expected={expected!r}"
        )


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(120)
def test_observe_java_report_trigger_postgres_outage(tmp_path: Path) -> None:
    with report_dns_server() as dns:
        with _OutageJavaRuntime(tmp_path / "java-report-postgres-outage", dns) as runtime:
            observation = _capture(runtime, _OracleTarget(runtime))
    _assert_frozen_observation("java-observation.json", observation)
    print(json.dumps(observation, ensure_ascii=False, sort_keys=True, indent=2))


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(120)
def test_observe_rust_report_trigger_postgres_outage() -> None:
    repository = Path(__file__).resolve().parents[3]
    with report_dns_server() as dns:
        with _candidate(repository, dns) as runtime:
            observation = _capture(runtime, runtime)
    _assert_frozen_observation("candidate-observation.json", observation)
    print(json.dumps(observation, ensure_ascii=False, sort_keys=True, indent=2))
