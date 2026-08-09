from __future__ import annotations

import os
from pathlib import Path

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner
from lmyzmail_blackbox.errors import HarnessError
from lmyzmail_blackbox.report_contract import REPORT_SCENARIOS
from lmyzmail_blackbox.runtime import CandidateRuntime


class _LegacyReportsCandidateRuntime(CandidateRuntime):
    @property
    def requires_qa_account(self) -> bool:
        return False

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


def _candidate(repository: Path) -> _LegacyReportsCandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        candidate = _LegacyReportsCandidateRuntime.from_environment()
        if not isinstance(candidate, _LegacyReportsCandidateRuntime):
            raise HarnessError("reports candidate runtime type was not preserved")
        candidate.command_template = (
            *candidate.command_template,
            "--lmyzmail.reporting.enabled=true",
        )
        return candidate
    return _LegacyReportsCandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
            "--lmyzmail.reporting.enabled=true",
        )
    )


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(240)
def test_rust_candidate_reports_match_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java/managed-reports-v1",
            "managed-reports",
        ).verify_candidate(REPORT_SCENARIOS, candidate)
