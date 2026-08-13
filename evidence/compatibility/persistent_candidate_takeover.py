from __future__ import annotations

import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Literal

import httpx

from lmyzmail_blackbox.errors import HarnessError, ProcessStartError
from lmyzmail_blackbox.persistent_runtime import (
    LEGACY_SESSION_TOKEN,
    PersistentJavaOracleRuntime,
)
from lmyzmail_blackbox.runtime import CandidateRuntime, HarnessPaths, JavaOracleRuntime


class PersistentCandidateRuntime(PersistentJavaOracleRuntime):
    """Candidate takeover runtime kept outside the frozen golden definition tree."""

    def __init__(
        self,
        workspace_path: Path,
        *,
        command_template: tuple[str, ...],
        paths: HarnessPaths | None = None,
        startup_timeout: float = 90.0,
        shutdown_timeout: float = 5.0,
        shutdown_kill_timeout: float = 2.0,
        index_migration_enabled: bool = False,
        redis_mode: Literal["both", "rdb-only"] = "both",
    ) -> None:
        super().__init__(
            workspace_path,
            paths=paths,
            startup_timeout=startup_timeout,
            shutdown_timeout=shutdown_timeout,
            shutdown_kill_timeout=shutdown_kill_timeout,
            index_migration_enabled=index_migration_enabled,
            redis_mode=redis_mode,
        )
        if not command_template:
            raise HarnessError("candidate command template is empty")
        self.command_template = command_template

    @property
    def target_kind(self) -> str:
        return f"rust-candidate-persistent-{self.generation:04d}"

    @property
    def requires_smtp_readiness(self) -> bool:
        return False

    def _verify_inputs(self) -> None:
        CandidateRuntime._verify_inputs(self)

    def _candidate_configuration(self) -> Path:
        return CandidateRuntime._candidate_configuration(self)

    def _application_arguments(self) -> list[str]:
        return CandidateRuntime._application_arguments(self)

    def _expected_attestation(self) -> dict[str, object]:
        fixture_root = self.paths.repository / "blackbox/fixtures/legacy"
        return {
            "schema_version": 1,
            "candidate": {"command_template": list(self.command_template)},
            "runtime": {
                "index_migration_enabled": self.index_migration_enabled,
                "redis_mode": self.redis_mode,
            },
            "fixtures": {
                "postgres_schema_sha256": self._sha256(fixture_root / "postgres-schema.sql"),
                "postgres_schema_metadata_sha256": self._sha256(fixture_root / "postgres-schema.json"),
                "postgres_seed_sha256": self._sha256(fixture_root / "postgres-seed.sql"),
                "redis_seed_sha256": self._sha256(fixture_root / "redis-seed.json"),
                "maildir_manifest_sha256": self._sha256(fixture_root / "maildir.json"),
            },
        }

    def _verify_postgres_schema(self, bin_dir: Path, log: Path, env: dict[str, str]) -> None:
        _, ports = self._require_state()
        descriptor, dump_name = tempfile.mkstemp(
            prefix=".candidate-postgres-schema-", suffix=".sql", dir=self.persistent_workspace
        )
        os.close(descriptor)
        dump = Path(dump_name)
        try:
            self._run_checked(
                [str(bin_dir / "pg_dump"), "--host=127.0.0.1", f"--port={ports.postgres}",
                 "--username=lmyzmail_test", "--dbname=lmyzmail", "--schema=public",
                 "--schema-only", "--no-owner", "--no-privileges", "--no-comments",
                 "--quote-all-identifiers", f"--file={dump}"],
                env=env, log_path=log,
            )
            actual = dump.read_text(encoding="utf-8")
        finally:
            dump.unlink(missing_ok=True)
        fixture = (self.paths.repository / "blackbox/fixtures/legacy/postgres-schema.sql").read_text(
            encoding="utf-8"
        )
        legacy_tables = set(re.findall(r'CREATE TABLE "public"\."([^"]+)"', fixture))
        missing = sorted(table for table in legacy_tables if f'"{table}"' not in actual)
        if missing:
            raise HarnessError("candidate PostgreSQL schema lost legacy tables: " + ", ".join(missing))

    def _start_application(self) -> None:
        JavaOracleRuntime._start_application(self)
        if self._application is None:
            raise RuntimeError("persistent candidate process is not available")
        _, ports = self._require_state()
        deadline = time.monotonic() + self.startup_timeout
        url = f"http://127.0.0.1:{ports.http}/web/mail/list/inbox?page=0&size=1"
        last_error: BaseException | None = None
        with httpx.Client(trust_env=False, timeout=1.0) as client:
            while time.monotonic() < deadline:
                try:
                    response = client.get(url, headers={"X-Session-Token": LEGACY_SESSION_TOKEN})
                    if response.status_code == 200:
                        return
                    last_error = RuntimeError(f"persistent candidate readiness returned {response.status_code}")
                except httpx.HTTPError as error:
                    last_error = error
                time.sleep(0.05)
        raise ProcessStartError(
            f"persistent candidate did not finish readiness: {last_error}; tail:\n{self._application.log_tail()}"
        )


def run_takeover(workspace: Path, repository: Path) -> dict[str, object]:
    candidate = repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"
    runtime = PersistentCandidateRuntime(workspace, command_template=(str(candidate), "--config", "{config}"))
    generations: list[int] = []
    try:
        runtime.start()
        generations.append(runtime.generation)
        assert runtime.workspace is not None and runtime.ports is not None
        marker = json.loads((runtime.workspace / "lmyzmail-runtime-attestation.json").read_text(encoding="utf-8"))
        response = httpx.get(
            f"http://127.0.0.1:{runtime.ports.http}/web/mail/list/inbox?page=0&size=50",
            headers={"X-Session-Token": LEGACY_SESSION_TOKEN}, timeout=10.0, trust_env=False,
        )
        assert response.status_code == 200 and response.json()["totalElements"] == 3
        runtime.restart_application()
        generations.append(runtime.generation)
        runtime.shutdown()
        runtime.recover()
        generations.append(runtime.generation)
    finally:
        runtime.close()
    reopened = PersistentCandidateRuntime(workspace, command_template=(str(candidate), "--config", "{config}"))
    try:
        reopened.recover()
        generations.append(reopened.generation)
    finally:
        reopened.close()
    return {"status": "passed", "generations": generations, "attestation": marker}


if __name__ == "__main__":
    repository = Path(__file__).resolve().parents[2]
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("workspace", type=Path)
    args = parser.parse_args()
    print(json.dumps(run_takeover(args.workspace, repository), sort_keys=True, indent=2))
