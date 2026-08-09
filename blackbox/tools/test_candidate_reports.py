from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner
from lmyzmail_blackbox.report_contract import REPORT_SCENARIOS, report_dns_server
from lmyzmail_blackbox.runtime import CandidateRuntime
from lmyzmail_blackbox.scripted_dns import DnsQuery, ScriptedDnsServer


class _LegacyReportsCandidateRuntime(CandidateRuntime):
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
            "dns_server": f"{self.report_dns.host}:{self.report_dns.port}",
            "dmarc_report_sender_address": "qa@example.test",
            "tls_report_sender_address": "qa@example.test",
            "organization_name": "Blackbox Reports",
            "organization_email": "reports@example.test",
        }
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def drain_report_dns_queries(self) -> tuple[DnsQuery, ...]:
        return self.report_dns.drain_queries()

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


def _candidate(
    repository: Path,
    dns: ScriptedDnsServer,
) -> _LegacyReportsCandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        configured = CandidateRuntime.from_environment()
        return _LegacyReportsCandidateRuntime(
            dns=dns,
            command_template=(
                *configured.command_template,
                "--lmyzmail.reporting.enabled=true",
                "--lmyzmail.queue.poll-interval-ms=60000",
                "--lmyzmail.maildir.max-files-per-directory=1",
            ),
        )
    return _LegacyReportsCandidateRuntime(
        dns=dns,
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
            "--lmyzmail.reporting.enabled=true",
            "--lmyzmail.queue.poll-interval-ms=60000",
            "--lmyzmail.maildir.max-files-per-directory=1",
        ),
    )


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(240)
def test_rust_candidate_reports_match_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with report_dns_server() as dns:
        with _candidate(repository, dns) as candidate:
            DifferentialRunner(
                repository,
                repository / "blackbox/golden/java/managed-reports-v15",
                "managed-reports",
            ).verify_candidate(REPORT_SCENARIOS, candidate)
