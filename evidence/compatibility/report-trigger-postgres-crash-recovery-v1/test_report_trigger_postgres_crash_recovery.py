from __future__ import annotations

import contextlib
import json
import os
import time
from collections.abc import Callable
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
from lmyzmail_blackbox.processes import ManagedProcess
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
_FIRST_RESPONSE_TIMEOUT_SECONDS = 30.0


class _PostgresCrashMixin:
    report_dns: ScriptedDnsServer
    paths: Any
    workspace: Path | None
    ports: PortSet | None
    _postgres: ManagedProcess | None
    _application: ManagedProcess | None
    _port_allocator: Any
    _require_state: Callable[[], tuple[Path, PortSet]]
    _postgres_env: Callable[[], dict[str, str]]
    _wait_for_postgres_ready: Callable[..., None]

    @property
    def application_pid_for_test(self) -> int:
        if self._application is None:
            raise RuntimeError("application is not running")
        return self._application.pid

    @property
    def postgres_pid_for_test(self) -> int:
        if self._postgres is None:
            raise RuntimeError("PostgreSQL is not running")
        return self._postgres.pid

    def terminate_postgres_for_test(self) -> None:
        if self._postgres is None:
            raise RuntimeError("PostgreSQL is not running")
        self._postgres.kill(timeout=5.0)
        self._postgres = None

    def _start_existing_postgres(self, log_name: str) -> None:
        workspace, ports = self._require_state()
        if self._postgres is not None:
            raise RuntimeError("PostgreSQL is already running")
        if self._port_allocator is None:
            raise RuntimeError("port allocator is not available")
        root = self.paths.runtime / "postgres-root"
        bin_dir = root / "usr/lib/postgresql/16/bin"
        data = workspace / "postgres-data"
        version = data / "PG_VERSION"
        if (
            data.is_symlink()
            or not data.is_dir()
            or version.is_symlink()
            or not version.is_file()
        ):
            raise RuntimeError("PostgreSQL data directory is missing or symlinked")
        log = workspace / log_name
        env = self._postgres_env()
        self._port_allocator.reserve_port(ports.postgres)
        self._port_allocator.release_port(ports.postgres)
        process = ManagedProcess(
            "postgres-crash-recovery",
            [
                str(bin_dir / "postgres"),
                "-D",
                str(data),
                "-h",
                "127.0.0.1",
                "-p",
                str(ports.postgres),
                "-c",
                "fsync=on",
                "-c",
                "synchronous_commit=on",
                "-c",
                "full_page_writes=on",
                "-c",
                "max_connections=128",
                "-c",
                "unix_socket_directories=",
            ],
            log,
            env=env,
            inherit_env=False,
        )
        self._postgres = process
        try:
            process.start()
            process.wait_for_tcp("127.0.0.1", ports.postgres, timeout=20.0)
            self._wait_for_postgres_ready(
                bin_dir,
                ports.postgres,
                env=env,
                log_path=log,
                timeout=20.0,
            )
        except BaseException:
            with contextlib.suppress(BaseException):
                process.kill(timeout=5.0)
            self._postgres = None
            raise

    def restart_postgres_for_test(self) -> None:
        self._start_existing_postgres("postgres-crash-recovery.log")

    def drain_report_dns_queries(self) -> tuple[DnsQuery, ...]:
        return self.report_dns.drain_queries()


class _CrashJavaRuntime(_PostgresCrashMixin, PersistentJavaOracleRuntime):
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


class _CrashCandidateRuntime(_PostgresCrashMixin, CandidateRuntime):
    def __init__(self, *, command_template: tuple[str, ...], dns: ScriptedDnsServer) -> None:
        super().__init__(command_template=command_template)
        self.report_dns = dns

    @property
    def requires_qa_account(self) -> bool:
        return False

    def _start_postgres(self) -> None:
        CandidateRuntime._start_postgres(self)
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
        if self._postgres is None:
            raise RuntimeError("candidate PostgreSQL did not start")
        self._postgres.stop(timeout=5.0, kill_timeout=5.0)
        self._postgres = None
        self._start_existing_postgres("postgres-durable.log")
        self._run_checked(
            [
                str(psql),
                "--host=127.0.0.1",
                f"--port={ports.postgres}",
                "--username=lmyzmail_test",
                "--dbname=lmyzmail",
                "--set=ON_ERROR_STOP=1",
                "--command=CHECKPOINT",
            ],
            env=self._postgres_env(),
            log_path=workspace / "postgres-checkpoint.log",
        )

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


@dataclass(frozen=True, slots=True)
class _OracleTarget:
    runtime: _CrashJavaRuntime

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


def _candidate(repository: Path, dns: ScriptedDnsServer) -> _CrashCandidateRuntime:
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
    return _CrashCandidateRuntime(command_template=command_template, dns=dns)


def _storage_state(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise AssertionError("report crash-recovery target is not started")
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


def _non_database_state(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise AssertionError("report crash-recovery target is not started")
    client: redis.Redis = redis.Redis(
        host="127.0.0.1",
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


def _connect_postgres(
    target: RuntimeTarget,
) -> psycopg.Connection[tuple[Any, ...]]:
    if target.ports is None:
        raise AssertionError("report crash-recovery target is not started")
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
    raise AssertionError("report domain query did not block before PostgreSQL crash")


def _long_request(target: RuntimeTarget) -> RawHttpResponse:
    if target.ports is None:
        raise AssertionError("report crash-recovery target ports are unavailable")
    return http_exchange(
        "127.0.0.1",
        target.ports.http,
        "POST",
        f"/api/reports/trigger?date={_NO_DATA_DATE}",
        headers=(("X-API-Key", API_KEY),),
        timeout=_FIRST_RESPONSE_TIMEOUT_SECONDS,
        max_response=1 * 1024 * 1024,
    )


def _capture(runtime: _PostgresCrashMixin, target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise AssertionError("report crash-recovery target ports are unavailable")
    if _drain_report_dns_queries(target):
        raise AssertionError("report crash-recovery DNS trace was not initially empty")
    before = _storage_state(target)
    application_pid = runtime.application_pid_for_test
    postgres_pid = runtime.postgres_pid_for_test
    blocker = _connect_postgres(target)
    try:
        blocker.execute("LOCK TABLE inbound_dmarc_log IN ACCESS EXCLUSIVE MODE")
        with ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="report-postgres-crash-recovery",
        ) as executor:
            first = executor.submit(_long_request, target)
            _wait_for_blocked_query(blocker)
            runtime.terminate_postgres_for_test()
            outage_response = first.result(timeout=15.0)
    finally:
        with contextlib.suppress(psycopg.Error):
            blocker.close()
    while_down = _non_database_state(target)
    runtime.restart_postgres_for_test()
    after = _storage_state(target)
    if after != before:
        raise AssertionError(
            f"report crash recovery mutated storage: before={before!r}, after={after!r}"
        )
    outage_error = (
        "JDBC exception executing SQL [select distinct idl1_0.header_from_domain "
        "from inbound_dmarc_log idl1_0 where idl1_0.report_date=? and "
        "idl1_0.header_from_domain is not null] [An I/O error occurred while "
        "sending to the backend.] [n/a]"
        if target.target_kind == "java-oracle"
        else "reporting database unavailable"
    )
    outage = _expect_json(
        outage_response,
        status=200,
        body={
            "date": _NO_DATA_DATE,
            "dmarcSent": 0,
            "dmarcFailed": 0,
            "tlsSent": 0,
            "tlsFailed": 0,
            "error": outage_error,
        },
    )
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
        raise AssertionError(f"PostgreSQL crash reached DNS: {queries!r}")
    return {
        "postgresFault": "SIGKILL process group after blocked domain query",
        "applicationPidUnchanged": runtime.application_pid_for_test == application_pid,
        "postgresPidChanged": runtime.postgres_pid_for_test != postgres_pid,
        "outageResponse": outage,
        "retryResponse": retry,
        "state": {
            "dnsQueries": [],
            "redisQueueUnchangedWhileDown": while_down["redis"] == before["redis"],
            "maildirUnchangedWhileDown": while_down["maildir"] == before["maildir"],
            "redisQueueUnchangedAfterRecovery": after["redis"] == before["redis"],
            "maildirUnchangedAfterRecovery": after["maildir"] == before["maildir"],
            "sourceDatabaseUnchangedAfterRecovery": after["database"] == before["database"],
        },
    }


def _assert_frozen_observation(name: str, observation: dict[str, Any]) -> None:
    path = Path(__file__).with_name(name)
    expected = json.loads(path.read_text(encoding="utf-8"))
    if observation != expected:
        raise AssertionError(
            f"report PostgreSQL crash-recovery observation changed: "
            f"actual={observation!r}, expected={expected!r}"
        )


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(150)
def test_observe_java_report_trigger_postgres_crash_recovery(tmp_path: Path) -> None:
    with report_dns_server() as dns:
        with _CrashJavaRuntime(tmp_path / "java-report-postgres-crash", dns) as runtime:
            observation = _capture(runtime, _OracleTarget(runtime))
    _assert_frozen_observation("java-observation.json", observation)
    print(json.dumps(observation, ensure_ascii=False, sort_keys=True, indent=2))


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(150)
def test_observe_rust_report_trigger_postgres_crash_recovery() -> None:
    repository = Path(__file__).resolve().parents[3]
    with report_dns_server() as dns:
        with _candidate(repository, dns) as runtime:
            observation = _capture(runtime, runtime)
    _assert_frozen_observation("candidate-observation.json", observation)
    print(json.dumps(observation, ensure_ascii=False, sort_keys=True, indent=2))
