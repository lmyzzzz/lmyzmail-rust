from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.report_contract import REPORT_SCENARIOS, report_dns_server
from lmyzmail_blackbox.scripted_dns import DnsQuery, ScriptedDnsServer


class _ReportsJavaOracleRuntime(PersistentJavaOracleRuntime):
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


@dataclass(frozen=True, slots=True)
class _OracleTarget:
    runtime: _ReportsJavaOracleRuntime

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
        return self.runtime.report_dns.drain_queries()


def _verify_fresh_java(
    runner: DifferentialRunner,
    workspace: Path,
    *,
    record: bool,
) -> None:
    with report_dns_server() as dns:
        with _ReportsJavaOracleRuntime(workspace, dns) as oracle:
            target = _OracleTarget(oracle)
            if record:
                runner.record_from_java(REPORT_SCENARIOS, target)
            else:
                runner.verify_java(REPORT_SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(360)
def test_frozen_java_reports_golden(
    tmp_path: Path,
    record_java_golden: bool,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    runner = DifferentialRunner(
        repository,
        repository / "blackbox/golden/java/managed-reports-v16",
        "managed-reports",
        record_java=record_java_golden,
    )

    if record_java_golden:
        _verify_fresh_java(runner, tmp_path / "reports-record", record=True)

    _verify_fresh_java(runner, tmp_path / "reports-verify", record=False)
