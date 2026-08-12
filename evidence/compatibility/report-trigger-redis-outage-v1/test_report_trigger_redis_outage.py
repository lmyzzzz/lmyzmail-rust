from __future__ import annotations

import json
import hashlib
import os
import signal
import time
from concurrent.futures import Future, ThreadPoolExecutor
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
    _report_message_snapshot,
    _redis_pending,
    _report_database_state,
    _sent_files,
    _task_snapshot,
    report_dns_server,
)
from lmyzmail_blackbox.runtime import API_KEY, CandidateRuntime
from lmyzmail_blackbox.scripted_dns import DnsQuery, ScriptedDnsServer

_HOST = "127.0.0.1"
_REPORT_DATE = "2024-01-01"
_DMARC_DOMAIN = "sender.example"
_REPORT_SENDER = "qa@example.test"
_PAUSED_OBSERVATION_SECONDS = 12.0
_FIRST_RESPONSE_TIMEOUT_SECONDS = 30.0
_EXPECTED_DNS_QUERIES = (
    "_dmarc.sender.example",
    "sender.example._report._dmarc.example.test",
)
_SEEDED_DELIVERY_GOLDEN = Path(
    "blackbox/golden/java/managed-reports-v23/observations/http/reports/seeded-delivery.json"
)
_SEEDED_DELIVERY_GOLDEN_SHA256 = (
    "887abea00d415a4b283b5611f6902b125c6928c67c94226f8a2ef45239d4e366"
)


class _RedisOutageMixin:
    report_dns: ScriptedDnsServer
    workspace: Path | None
    ports: PortSet | None
    _redis: Any
    _application: Any

    @property
    def application_pid_for_test(self) -> int:
        if self._application is None:
            raise RuntimeError("application is not running")
        return cast(int, self._application.pid)

    @property
    def redis_pid_for_test(self) -> int:
        if self._redis is None:
            raise RuntimeError("Redis is not running")
        return cast(int, self._redis.pid)

    def pause_redis_for_test(self) -> None:
        if self._redis is None:
            raise RuntimeError("Redis is not running")
        os.killpg(self._redis.pid, signal.SIGSTOP)

    def resume_redis_for_test(self) -> None:
        if self._redis is None:
            raise RuntimeError("Redis is not running")
        os.killpg(self._redis.pid, signal.SIGCONT)

    def drain_report_dns_queries(self) -> tuple[DnsQuery, ...]:
        return self.report_dns.drain_queries()


class _RedisOutageJavaRuntime(_RedisOutageMixin, PersistentJavaOracleRuntime):
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


class _RedisOutageCandidateRuntime(_RedisOutageMixin, CandidateRuntime):
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
    runtime: _RedisOutageJavaRuntime

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


def _candidate(repository: Path, dns: ScriptedDnsServer) -> _RedisOutageCandidateRuntime:
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
    return _RedisOutageCandidateRuntime(command_template=command_template, dns=dns)


def _connect_postgres(
    target: RuntimeTarget,
) -> psycopg.Connection[tuple[Any, ...]]:
    if target.ports is None:
        raise AssertionError("report Redis outage target is not started")
    connection = psycopg.connect(
        host=_HOST,
        port=target.ports.postgres,
        user="lmyzmail_test",
        dbname="lmyzmail",
        connect_timeout=5,
        autocommit=False,
    )
    connection.execute("SET statement_timeout = '5s'")
    connection.execute("SET lock_timeout = '5s'")
    return connection


def _outbound_database_state(target: RuntimeTarget) -> list[dict[str, Any]]:
    with _connect_postgres(target) as connection:
        rows = connection.execute(
            """
            SELECT status, retry_count, max_retries, sender_address,
                   recipients_json, sent_file_name IS NOT NULL,
                   sent_subdirectory, message_id IS NOT NULL, last_error
            FROM outbound_mail_queue
            ORDER BY id
            """
        ).fetchall()
    return [
        {
            "status": row[0],
            "retryCount": row[1],
            "maxRetries": row[2],
            "senderAddress": row[3],
            "recipientsJson": json.loads(cast(str, row[4])),
            "sentFilePresent": row[5],
            "sentSubdirectory": row[6],
            "messageIdPresent": row[7],
            "lastError": row[8],
        }
        for row in rows
    ]


def _durable_state(target: RuntimeTarget) -> dict[str, Any]:
    return {
        "sourceDatabase": _report_database_state(target),
        "outboundDatabase": _outbound_database_state(target),
        "maildir": sorted(_sent_files(target)),
    }


def _redis_client(target: RuntimeTarget) -> redis.Redis:
    if target.ports is None:
        raise AssertionError("report Redis outage target is not started")
    return cast(
        redis.Redis,
        redis.Redis(
            host=_HOST,
            port=target.ports.redis,
            decode_responses=False,
            socket_connect_timeout=2.0,
            socket_timeout=2.0,
        ),
    )


def _long_request(target: RuntimeTarget) -> RawHttpResponse:
    if target.ports is None:
        raise AssertionError("report Redis outage target ports are unavailable")
    return http_exchange(
        _HOST,
        target.ports.http,
        "POST",
        f"/api/reports/domain/{_DMARC_DOMAIN}?date={_REPORT_DATE}",
        headers=(("X-API-Key", API_KEY),),
        timeout=_FIRST_RESPONSE_TIMEOUT_SECONDS,
        max_response=1 * 1024 * 1024,
    )


def _wait_for_dns_queries(target: RuntimeTarget) -> tuple[DnsQuery, ...]:
    queries: list[DnsQuery] = []
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        queries.extend(_drain_report_dns_queries(target))
        if len(queries) >= len(_EXPECTED_DNS_QUERIES):
            names = tuple(query.qname for query in queries)
            if names != _EXPECTED_DNS_QUERIES:
                raise AssertionError(f"report Redis outage DNS order changed: {queries!r}")
            return tuple(queries)
        time.sleep(0.025)
    raise AssertionError(f"report Redis outage did not reach DNS discovery: {queries!r}")


def _success_response(response: RawHttpResponse) -> dict[str, Any]:
    return _expect_json(
        response,
        status=200,
        body={
            "domain": _DMARC_DOMAIN,
            "date": _REPORT_DATE,
            "dmarc": {
                "results": [
                    {
                        "success": True,
                        "method": "email",
                        "target": _REPORT_SENDER,
                    }
                ],
                "error": "none",
            },
            "tls": {
                "results": [],
                "error": "No TLS data for this domain/date",
            },
        },
    )


def _capture_single_publication(
    target: RuntimeTarget,
    client: redis.Redis,
    before_pending: list[int],
    before_files: dict[str, Path],
) -> tuple[list[str], dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, Path]]:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        pending = _redis_pending(client)
        files = _sent_files(target)
        if len(pending) == len(before_pending) + 1 and len(files) == len(before_files) + 1:
            if pending[: len(before_pending)] != before_pending:
                raise AssertionError("report Redis recovery mutated the pending prefix")
            new_ids = pending[len(before_pending) :]
            added_files = {
                key: path for key, path in files.items() if key not in before_files
            }
            break
        time.sleep(0.05)
    else:
        raise AssertionError("timed out waiting for one recovered report publication")

    label, task = _task_snapshot(client, new_ids[0])
    if label != "dmarc":
        raise AssertionError(f"recovered report queue task was not DMARC: {label!r}")
    if len(added_files) != 1:
        raise AssertionError("recovered report did not add exactly one Maildir file")
    message = _report_message_snapshot(next(iter(added_files.values())).read_bytes())
    if message != task["message"]:
        raise AssertionError("recovered report Redis and Maildir bytes differed")
    return [label], {label: task}, {label: message}, added_files


def _assert_active_dmarc_golden(
    target: RuntimeTarget,
    response: dict[str, Any],
    tasks: dict[str, dict[str, Any]],
    maildir_messages: dict[str, dict[str, Any]],
) -> None:
    repository = Path(__file__).resolve().parents[3]
    path = repository / _SEEDED_DELIVERY_GOLDEN
    actual_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual_sha256 != _SEEDED_DELIVERY_GOLDEN_SHA256:
        raise AssertionError(
            "active seeded report delivery golden changed: "
            f"actual={actual_sha256}, expected={_SEEDED_DELIVERY_GOLDEN_SHA256}"
        )
    golden = json.loads(path.read_text(encoding="utf-8"))["observation"]
    expected = {
        "response": golden["responses"]["dmarc"],
        "task": golden["queue"]["tasks"]["dmarc"],
        "maildir": golden["maildir"]["messages"]["dmarc"],
    }
    actual = {
        "response": response,
        "task": tasks["dmarc"],
        "maildir": maildir_messages["dmarc"],
    }
    if actual != expected:
        raise AssertionError(
            f"recovered report publication changed from the active golden for "
            f"{target.target_kind}: actual={actual!r}, expected={expected!r}"
        )


def _failure_response(response: RawHttpResponse) -> dict[str, Any]:
    return _expect_json(
        response,
        status=200,
        body={
            "domain": _DMARC_DOMAIN,
            "date": _REPORT_DATE,
            "dmarc": {
                "results": [
                    {
                        "success": False,
                        "method": "email",
                        "target": _REPORT_SENDER,
                        "error": "outbound queue unavailable",
                    }
                ],
                "error": "none",
            },
            "tls": {
                "results": [],
                "error": "No TLS data for this domain/date",
            },
        },
    )


def _capture(
    runtime: _RedisOutageMixin,
    target: RuntimeTarget,
) -> dict[str, Any]:
    if _drain_report_dns_queries(target):
        raise AssertionError("report Redis outage DNS trace was not initially empty")
    before = _durable_state(target)
    before_files = _sent_files(target)
    initial_client = _redis_client(target)
    try:
        before_pending = _redis_pending(initial_client)
    finally:
        initial_client.close()
    application_pid = runtime.application_pid_for_test
    redis_pid = runtime.redis_pid_for_test
    runtime.pause_redis_for_test()
    first_response: RawHttpResponse | None = None
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="report-redis-outage") as executor:
        first: Future[RawHttpResponse] = executor.submit(_long_request, target)
        try:
            outage_queries = _wait_for_dns_queries(target)
            deadline = time.monotonic() + _PAUSED_OBSERVATION_SECONDS
            while not first.done() and time.monotonic() < deadline:
                time.sleep(0.025)
            completed_while_paused = first.done()
            if completed_while_paused:
                first_response = first.result()
            while_paused = _durable_state(target)
            if while_paused != before:
                raise AssertionError(
                    "report Redis outage caused a partial durable write while Redis was paused: "
                    f"before={before!r}, while_paused={while_paused!r}"
                )
        finally:
            runtime.resume_redis_for_test()
        if first_response is None:
            first_response = first.result(timeout=10.0)

    if runtime.application_pid_for_test != application_pid:
        raise AssertionError("application restarted during report Redis recovery")
    if runtime.redis_pid_for_test != redis_pid:
        raise AssertionError("Redis process identity changed during SIGSTOP recovery")

    client = _redis_client(target)
    try:
        client.ping()
        recovered_pending = _redis_pending(client)
        if completed_while_paused:
            if recovered_pending != before_pending:
                raise AssertionError(
                    "bounded report Redis failure published before explicit recovery: "
                    f"before={before_pending!r}, recovered={recovered_pending!r}"
                )
            outage_response = _failure_response(first_response)
            after_outage = _durable_state(target)
            if after_outage != before:
                raise AssertionError(
                    "bounded report Redis failure left partial durable state: "
                    f"before={before!r}, after={after_outage!r}"
                )
            recovery_response = _success_response(_long_request(target))
            recovery_queries = _drain_report_dns_queries(target)
        else:
            outage_response = None
            after_outage = before
            recovery_response = _success_response(first_response)
            recovery_queries = _drain_report_dns_queries(target)
        pending_order, tasks, maildir_messages, added_files = _capture_single_publication(
            target,
            client,
            before_pending,
            before_files,
        )
    finally:
        client.close()

    _assert_active_dmarc_golden(target, recovery_response, tasks, maildir_messages)

    after = _durable_state(target)
    if after["sourceDatabase"] != before["sourceDatabase"]:
        raise AssertionError("report Redis recovery mutated source report rows")
    if len(after["maildir"]) != len(before["maildir"]) + 1:
        raise AssertionError("report Redis recovery did not create exactly one Maildir message")
    before_outbound = before["outboundDatabase"]
    after_outbound = after["outboundDatabase"]
    if after_outbound[: len(before_outbound)] != before_outbound:
        raise AssertionError("report Redis recovery mutated pre-existing outbound rows")
    return {
        "redisFault": "SIGSTOP process group with existing connections retained",
        "completedWhileRedisPaused": completed_while_paused,
        "pausedObservationSeconds": _PAUSED_OBSERVATION_SECONDS,
        "applicationPidUnchanged": True,
        "redisPidUnchanged": True,
        "outageDnsQueries": [query.qname for query in outage_queries],
        "outageResponse": outage_response,
        "stateWhilePausedUnchanged": True,
        "recoveryResponse": recovery_response,
        "recoveryDnsQueries": [query.qname for query in recovery_queries],
        "publication": {
            "pendingOrder": pending_order,
            "maildirAddedCount": len(added_files),
            "noTemporaryFiles": not any(".tmp" in key for key in added_files),
            "redisMaildirByteEquivalent": True,
            "activeGoldenPath": _SEEDED_DELIVERY_GOLDEN.as_posix(),
            "activeGoldenSha256": _SEEDED_DELIVERY_GOLDEN_SHA256,
            "activeGoldenDmarcMatched": True,
        },
        "outboundDatabaseAddedAfterRecovery": after_outbound[len(before_outbound) :],
        "sourceDatabaseUnchanged": True,
    }


def _assert_frozen_observation(name: str, observation: dict[str, Any]) -> None:
    path = Path(__file__).with_name(name)
    expected = json.loads(path.read_text(encoding="utf-8"))
    if observation != expected:
        raise AssertionError(
            f"report Redis outage observation changed: "
            f"actual={observation!r}, expected={expected!r}"
        )


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(120)
def test_observe_java_report_trigger_redis_outage(tmp_path: Path) -> None:
    with report_dns_server() as dns:
        with _RedisOutageJavaRuntime(tmp_path / "java-report-redis-outage", dns) as runtime:
            observation = _capture(runtime, _OracleTarget(runtime))
    _assert_frozen_observation("java-observation.json", observation)
    print(json.dumps(observation, ensure_ascii=False, sort_keys=True, indent=2))


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(120)
def test_observe_rust_report_trigger_redis_outage() -> None:
    repository = Path(__file__).resolve().parents[3]
    with report_dns_server() as dns:
        with _candidate(repository, dns) as runtime:
            observation = _capture(runtime, runtime)
    _assert_frozen_observation("candidate-observation.json", observation)
    print(json.dumps(observation, ensure_ascii=False, sort_keys=True, indent=2))
