from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest
import redis

from lmyzmail_blackbox.differential import RuntimeTarget
from lmyzmail_blackbox.golden import GoldenAttestation, GoldenStore
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.report_contract import (
    _capture_report_publications,
    _drain_report_dns_queries,
    _redis_pending,
    _report_database_state,
    _restore_volume_threshold,
    _seed_volume_threshold,
    _sent_files,
    report_dns_server,
)
from lmyzmail_blackbox.runtime import CandidateRuntime
from lmyzmail_blackbox.scripted_dns import DnsQuery, ScriptedDnsServer

_FAKE_START_EPOCH = 1704157170  # 2024-01-02T00:59:30Z
_FAKE_BEFORE_MISSED_EPOCH = 1704157160  # 2024-01-02T00:59:20Z
_FAKE_AFTER_MISSED_EPOCH = 1704157220  # 2024-01-02T01:00:20Z
_REDIS_HOST = "127.0.0.1"
_NORMALIZERS = (
    "report-id:uuid-v4",
    "rfc5322:parsed-message",
    "report-body:wall-clock-period",
    "redis-domain-status:updated-at",
    "maildir:generated-filename",
)


class _SchedulerJavaRuntime(PersistentJavaOracleRuntime):
    def __init__(
        self,
        workspace: Path,
        dns: ScriptedDnsServer,
        shim: Path,
        *,
        fake_epoch: int = _FAKE_START_EPOCH,
    ) -> None:
        super().__init__(workspace)
        self.report_dns = dns
        self.shim = shim
        self.fake_epoch = fake_epoch

    def drain_report_dns_queries(self) -> tuple[DnsQuery, ...]:
        return self.report_dns.drain_queries()

    def _application_arguments(self) -> list[str]:
        arguments = super()._application_arguments()
        jar_index = arguments.index("-jar")
        arguments[jar_index:jar_index] = [
            f"-Ddns.server={self.report_dns.host}:{self.report_dns.port}"
        ]
        disabled_auto_send = "--botmail.reporting.auto-send-enabled=false"
        arguments[arguments.index(disabled_auto_send)] = (
            "--botmail.reporting.auto-send-enabled=true"
        )
        arguments.extend(
            (
                "--botmail.reporting.dmarc-report-sender-address=qa@example.test",
                "--botmail.reporting.tls-report-sender-address=qa@example.test",
                "--botmail.reporting.organization-name=Blackbox Reports",
                "--botmail.reporting.organization-email=reports@example.test",
                "--botmail.queue.poll-interval-ms=60000",
            )
        )
        return arguments

    def _application_environment(self) -> dict[str, str]:
        environment = super()._application_environment()
        environment["LD_PRELOAD"] = str(self.shim)
        environment["LMYZMAIL_FAKE_REALTIME_EPOCH"] = str(self.fake_epoch)
        return environment


class _SchedulerCandidateRuntime(CandidateRuntime):
    def __init__(
        self,
        *,
        command_template: tuple[str, ...],
        dns: ScriptedDnsServer,
        shim: Path,
        fake_epoch: int = _FAKE_START_EPOCH,
    ) -> None:
        super().__init__(command_template=command_template)
        self.report_dns = dns
        self.shim = shim
        self.fake_epoch = fake_epoch

    @property
    def requires_qa_account(self) -> bool:
        return False

    def drain_report_dns_queries(self) -> tuple[DnsQuery, ...]:
        return self.report_dns.drain_queries()

    def _candidate_configuration(self) -> Path:
        path = super()._candidate_configuration()
        value = json.loads(path.read_text(encoding="utf-8"))
        value["reporting"] = {
            "enabled": True,
            "auto_send_enabled": True,
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
            "--lmyzmail.reporting.auto-send-enabled=true",
            "--lmyzmail.queue.poll-interval-ms=60000",
            "--lmyzmail.maildir.max-files-per-directory=1",
        ]

    def _application_environment(self) -> dict[str, str]:
        environment = super()._application_environment()
        environment["LD_PRELOAD"] = str(self.shim)
        environment["LMYZMAIL_FAKE_REALTIME_EPOCH"] = str(self.fake_epoch)
        return environment

    def restart_application(self) -> None:
        if self._application is None:
            raise RuntimeError("candidate application is not running")
        self._application.stop(
            timeout=self.shutdown_timeout,
            kill_timeout=self.shutdown_kill_timeout,
        )
        self._application = None
        CandidateRuntime._start_application(self)

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


def _compile_shim(repository: Path, output: Path) -> None:
    source = repository / "blackbox/fixtures/fake_realtime.c"
    result = subprocess.run(  # noqa: S603,S607
        [
            "/usr/bin/cc",
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fPIC",
            "-shared",
            str(source),
            "-pthread",
            "-ldl",
            "-o",
            str(output),
        ],
        cwd=repository,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"fake realtime shim compilation failed: {result.stderr}")


def _candidate(
    repository: Path,
    dns: ScriptedDnsServer,
    shim: Path,
    *,
    fake_epoch: int = _FAKE_START_EPOCH,
) -> _SchedulerCandidateRuntime:
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
    return _SchedulerCandidateRuntime(
        command_template=command_template,
        dns=dns,
        shim=shim,
        fake_epoch=fake_epoch,
    )


def _wait_until_due_side_effects(
    runtime: RuntimeTarget,
    client: redis.Redis,
    before_pending: list[int],
    before_files: dict[str, Path],
) -> None:
    time.sleep(2.0)
    if _redis_pending(client) != before_pending or _sent_files(runtime) != before_files:
        raise AssertionError("report scheduler published before the fake 01:00 UTC boundary")
    deadline = time.monotonic() + 45.0
    while time.monotonic() < deadline:
        if (
            len(_redis_pending(client)) == len(before_pending) + 2
            and len(_sent_files(runtime)) == len(before_files) + 2
        ):
            return
        time.sleep(0.05)
    raise AssertionError("report scheduler did not publish after the fake 01:00 UTC boundary")


def _capture_scheduler(runtime: RuntimeTarget) -> dict[str, Any]:
    if runtime.ports is None:
        raise AssertionError("scheduler runtime ports are unavailable")
    if _drain_report_dns_queries(runtime):
        raise AssertionError("scheduler DNS trace was not empty before threshold seeding")
    original = _seed_volume_threshold(runtime)
    client: redis.Redis = redis.Redis(
        host=_REDIS_HOST,
        port=runtime.ports.redis,
        decode_responses=False,
    )
    try:
        before_database = _report_database_state(runtime)
        before_pending = _redis_pending(client)
        before_files = _sent_files(runtime)
        _wait_until_due_side_effects(runtime, client, before_pending, before_files)
        pending_order, tasks, messages, added_files = _capture_report_publications(
            runtime,
            client,
            before_pending,
            before_files,
        )
        if _report_database_state(runtime) != before_database:
            raise AssertionError("scheduled reports mutated their source database rows")
        queries = _drain_report_dns_queries(runtime)
        expected = (
            "_dmarc.sender.example",
            "sender.example._report._dmarc.example.test",
            "_smtp._tls.recipient.example",
        )
        if tuple(query.qname for query in queries) != expected:
            raise AssertionError(f"scheduled report DNS trace changed: {queries!r}")
        time.sleep(1.0)
        if len(_redis_pending(client)) != len(before_pending) + 2:
            raise AssertionError("report scheduler published more than once at one boundary")
        return {
            "triggeredAtFakeUtcBoundary": "2024-01-02T01:00:00Z",
            "reportDate": "2024-01-01",
            "dnsQueries": [query.qname for query in queries],
            "queue": {"pendingOrder": pending_order, "tasks": tasks},
            "maildir": {
                "addedCount": len(added_files),
                "messages": messages,
                "noTemporaryFiles": not any(".tmp" in key for key in added_files),
            },
            "sourceDatabaseUnchanged": True,
            "singleRunAtBoundary": True,
        }
    finally:
        client.close()
        _restore_volume_threshold(runtime, original)


def _assert_golden(repository: Path, observed: dict[str, Any], *, record: bool) -> None:
    attestation = GoldenAttestation.from_repository(
        repository,
        profile="managed-reports-scheduler",
        normalizers=_NORMALIZERS,
    )
    GoldenStore(
        repository / "blackbox/golden/java/managed-reports-scheduler-v3",
        attestation,
        record=record,
    ).assert_observation("observation.json", observed)


def _assert_restart_golden(
    repository: Path,
    observed: dict[str, Any],
    *,
    record: bool,
) -> None:
    attestation = GoldenAttestation.from_repository(
        repository,
        profile="managed-reports-scheduler-restart",
        normalizers=(),
    )
    GoldenStore(
        repository / "blackbox/golden/java/managed-reports-scheduler-restart-v2",
        attestation,
        record=record,
    ).assert_observation("observation.json", observed)


def _run_java_scheduler(repository: Path, workspace: Path, shim: Path) -> dict[str, Any]:
    with report_dns_server() as dns:
        with _SchedulerJavaRuntime(workspace, dns, shim) as runtime:
            return _capture_scheduler(runtime)


def _capture_missed_restart(
    runtime: _SchedulerJavaRuntime | _SchedulerCandidateRuntime,
) -> dict[str, Any]:
    if runtime.ports is None:
        raise AssertionError("scheduler restart runtime ports are unavailable")
    if _drain_report_dns_queries(runtime):
        raise AssertionError("scheduler restart DNS trace was not initially empty")
    original = _seed_volume_threshold(runtime)
    client: redis.Redis = redis.Redis(
        host=_REDIS_HOST,
        port=runtime.ports.redis,
        decode_responses=False,
    )
    try:
        before_database = _report_database_state(runtime)
        before_pending = _redis_pending(client)
        before_files = _sent_files(runtime)
        time.sleep(1.0)
        if _redis_pending(client) != before_pending or _sent_files(runtime) != before_files:
            raise AssertionError("report scheduler published before the missed boundary")

        runtime.fake_epoch = _FAKE_AFTER_MISSED_EPOCH
        runtime.restart_application()
        time.sleep(5.0)
        if _redis_pending(client) != before_pending:
            raise AssertionError("report scheduler caught up a missed run after restart")
        if _sent_files(runtime) != before_files:
            raise AssertionError("report scheduler wrote Maildir state for a missed run")
        if _report_database_state(runtime) != before_database:
            raise AssertionError("missed scheduler restart mutated source report rows")
        queries = _drain_report_dns_queries(runtime)
        if queries:
            raise AssertionError(f"missed scheduler restart performed DNS work: {queries!r}")
        return {
            "stoppedBeforeBoundary": "2024-01-02T00:59:20Z",
            "restartedAfterBoundary": "2024-01-02T01:00:20Z",
            "missedReportDate": "2024-01-01",
            "redisQueueUnchanged": True,
            "maildirUnchanged": True,
            "sourceDatabaseUnchanged": True,
            "dnsQueries": [],
            "catchUpPublicationCount": 0,
        }
    finally:
        client.close()
        _restore_volume_threshold(runtime, original)


def _run_java_missed_restart(
    repository: Path,
    workspace: Path,
    shim: Path,
) -> dict[str, Any]:
    with report_dns_server() as dns:
        with _SchedulerJavaRuntime(
            workspace,
            dns,
            shim,
            fake_epoch=_FAKE_BEFORE_MISSED_EPOCH,
        ) as runtime:
            return _capture_missed_restart(runtime)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(120)
def test_java_report_scheduler_crosses_real_cron_boundary(
    tmp_path: Path,
    record_java_golden: bool,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    shim = tmp_path / "fake-realtime.so"
    _compile_shim(repository, shim)
    if record_java_golden:
        observed = _run_java_scheduler(repository, tmp_path / "java-record", shim)
        _assert_golden(repository, observed, record=True)
    observed = _run_java_scheduler(repository, tmp_path / "java-verify", shim)
    _assert_golden(repository, observed, record=False)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(120)
def test_rust_report_scheduler_crosses_real_cron_boundary(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    shim = tmp_path / "fake-realtime.so"
    _compile_shim(repository, shim)
    with report_dns_server() as dns:
        with _candidate(repository, dns, shim) as runtime:
            observed = _capture_scheduler(runtime)
    _assert_golden(repository, observed, record=False)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(120)
def test_java_report_scheduler_does_not_catch_up_after_restart(
    tmp_path: Path,
    record_java_golden: bool,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    shim = tmp_path / "fake-realtime.so"
    _compile_shim(repository, shim)
    if record_java_golden:
        observed = _run_java_missed_restart(repository, tmp_path / "java-record", shim)
        _assert_restart_golden(repository, observed, record=True)
    observed = _run_java_missed_restart(repository, tmp_path / "java-verify", shim)
    _assert_restart_golden(repository, observed, record=False)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(120)
def test_rust_report_scheduler_does_not_catch_up_after_restart(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    shim = tmp_path / "fake-realtime.so"
    _compile_shim(repository, shim)
    with report_dns_server() as dns:
        with _candidate(
            repository,
            dns,
            shim,
            fake_epoch=_FAKE_BEFORE_MISSED_EPOCH,
        ) as runtime:
            observed = _capture_missed_restart(runtime)
    _assert_restart_golden(repository, observed, record=False)
