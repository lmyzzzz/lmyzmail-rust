from __future__ import annotations

import json
import os
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.persistent_runtime import (
    LEGACY_SESSION_TOKEN,
    PersistentJavaOracleRuntime,
)
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.protocols import http_exchange, json_http_exchange
from lmyzmail_blackbox.runtime import CandidateRuntime
from lmyzmail_blackbox.snapshots import http_bytes_snapshot, http_json_snapshot

_SESSION_HEADERS = (("X-Session-Token", LEGACY_SESSION_TOKEN),)


@dataclass(frozen=True, slots=True)
class _OracleTarget:
    runtime: PersistentJavaOracleRuntime

    @property
    def target_kind(self) -> str:
        return "java-oracle"

    @property
    def workspace(self) -> Path | None:
        return self.runtime.workspace

    @property
    def ports(self) -> PortSet | None:
        return self.runtime.ports


def _capture_json(
    path: str,
    *,
    method: str = "GET",
    canonicalize_object_order: bool = False,
) -> Callable[[RuntimeTarget], dict[str, Any]]:
    def capture(target: RuntimeTarget) -> dict[str, Any]:
        assert target.ports is not None
        response = http_exchange(
            "127.0.0.1",
            target.ports.http,
            method,
            path,
            headers=_SESSION_HEADERS,
            timeout=10.0,
        )
        return http_json_snapshot(
            response,
            canonicalize_object_order=canonicalize_object_order,
        )

    cast(Any, capture).__lmyzmail_contract__ = {
        "protocol": "http",
        "method": method,
        "target": path,
        "headers": [["X-Session-Token", "<legacy-session-token>"]],
        "state": "attested legacy PostgreSQL seed and Maildir fixture",
    }
    return capture


def _capture_raw(path: str) -> Callable[[RuntimeTarget], dict[str, Any]]:
    def capture(target: RuntimeTarget) -> dict[str, Any]:
        assert target.ports is not None
        response = http_exchange(
            "127.0.0.1",
            target.ports.http,
            "GET",
            path,
            headers=_SESSION_HEADERS,
            timeout=10.0,
        )
        return http_bytes_snapshot(response)

    cast(Any, capture).__lmyzmail_contract__ = {
        "protocol": "http",
        "method": "GET",
        "target": path,
        "headers": [["X-Session-Token", "<legacy-session-token>"]],
        "state": "attested legacy PostgreSQL seed and Maildir fixture",
        "body": "exact bytes",
    }
    return capture


def _capture_attachment(
    path: str,
    *,
    headers: tuple[tuple[str, str], ...] = _SESSION_HEADERS,
) -> Callable[[RuntimeTarget], dict[str, Any]]:
    def capture(target: RuntimeTarget) -> dict[str, Any]:
        assert target.ports is not None
        response = http_exchange(
            "127.0.0.1",
            target.ports.http,
            "GET",
            path,
            headers=headers,
            timeout=10.0,
        )
        return http_bytes_snapshot(response)

    cast(Any, capture).__lmyzmail_contract__ = {
        "protocol": "http",
        "method": "GET",
        "target": path,
        "headers": [list(header) for header in headers],
        "state": "attested legacy PostgreSQL seed and Maildir fixture",
        "body": "exact bytes and attachment security headers",
    }
    return capture


MAIL_READ_SCENARIOS = (
    Scenario(
        "http/mail/list-inbox",
        _capture_json("/web/mail/list/inbox?page=0&size=50"),
    ),
    Scenario("http/mail/list-default", _capture_json("/web/mail/list?page=0&size=2")),
    Scenario(
        "http/mail/list-starred",
        _capture_json("/web/mail/list/inbox?page=0&size=50&starredOnly=true"),
    ),
    Scenario(
        "http/mail/detail-root",
        _capture_json("/web/mail/detail/inbox/legacy-root.eml"),
    ),
    Scenario(
        "http/mail/detail-attachment",
        _capture_json("/web/mail/detail/inbox/legacy-shard-2.eml"),
    ),
    Scenario(
        "http/mail/headers-root",
        _capture_json("/web/mail/headers/inbox/legacy-root.eml"),
    ),
    Scenario(
        "http/mail/raw-root",
        _capture_raw("/web/mail/raw/inbox/legacy-root.eml"),
    ),
    Scenario(
        "http/mail/invalid-folder",
        _capture_json(
            "/web/mail/detail/invalid/legacy-root.eml",
            canonicalize_object_order=True,
        ),
        normalizers=("json-object-order:jdk-map-of",),
    ),
    Scenario(
        "http/mail/encoded-traversal",
        _capture_json(
            "/web/mail/raw/inbox/%2e%2e%2flegacy-root.eml",
            canonicalize_object_order=True,
        ),
        normalizers=("json-object-order:jdk-map-of",),
    ),
    Scenario(
        "http/mail/missing-index",
        _capture_json("/web/mail/detail/inbox/missing.eml"),
    ),
)

MAIL_ATTACHMENT_SCENARIOS = (
    Scenario(
        "http/mail/attachment-valid",
        _capture_attachment(
            "/web/mail/attachment/inbox/legacy-shard-2.eml/0",
        ),
    ),
    Scenario(
        "http/mail/attachment-index-out-of-range",
        _capture_attachment(
            "/web/mail/attachment/inbox/legacy-shard-2.eml/1",
        ),
    ),
    Scenario(
        "http/mail/attachment-query-token-rejected",
        _capture_attachment(
            f"/web/mail/attachment/inbox/legacy-shard-2.eml/0?token={LEGACY_SESSION_TOKEN}",
            headers=(),
        ),
    ),
)

MAIL_STATE_SCENARIOS = (
    Scenario(
        "http/mail/stars-before",
        _capture_json("/web/userdata/stars/inbox"),
    ),
    Scenario(
        "http/mail/toggle-star-off",
        _capture_json(
            "/web/mail/star/inbox/legacy-root.eml",
            method="POST",
        ),
    ),
    Scenario(
        "http/mail/stars-after-off",
        _capture_json("/web/userdata/stars/inbox"),
    ),
    Scenario(
        "http/mail/toggle-star-on",
        _capture_json(
            "/web/mail/star/inbox/legacy-root.eml",
            method="POST",
        ),
    ),
    Scenario(
        "http/mail/stars-after-on",
        _capture_json("/web/userdata/stars/inbox"),
    ),
)


def _capture_mail_mutations(target: RuntimeTarget) -> dict[str, Any]:
    assert target.ports is not None
    port = target.ports.http

    def request(
        method: str,
        path: str,
        *,
        value: object | None = None,
        canonicalize: bool = False,
    ) -> dict[str, Any]:
        if value is None:
            response = http_exchange(
                "127.0.0.1",
                port,
                method,
                path,
                headers=_SESSION_HEADERS,
                timeout=10.0,
            )
        else:
            response = json_http_exchange(
                "127.0.0.1",
                port,
                method,
                path,
                value=value,
                headers=_SESSION_HEADERS,
                timeout=10.0,
            )
        return http_json_snapshot(response, canonicalize_object_order=canonicalize)

    before = request("GET", "/web/userdata/labels")
    duplicate = request(
        "POST",
        "/web/userdata/labels",
        value={"name": "Legacy", "color": "#ffffff"},
        canonicalize=True,
    )
    created_response = json_http_exchange(
        "127.0.0.1",
        port,
        "POST",
        "/web/userdata/labels",
        value={"name": "Blackbox", "color": "#123456"},
        headers=_SESSION_HEADERS,
        timeout=10.0,
    )
    created = http_json_snapshot(created_response, canonicalize_object_order=True)
    created_body = json.loads(created_response.body)
    label_id = created_body["id"]
    assert isinstance(label_id, int) and label_id > 0

    updated = request(
        "PUT",
        f"/web/userdata/labels/{label_id}",
        value={"name": "Blackbox Renamed", "color": "#654321"},
        canonicalize=True,
    )
    listed = request("GET", "/web/userdata/labels")
    email_before = request("GET", "/web/userdata/labels/email/inbox/legacy-root.eml")
    assigned = request(
        "POST",
        f"/web/userdata/labels/email/inbox/legacy-root.eml/{label_id}",
    )
    assigned_again = request(
        "POST",
        f"/web/userdata/labels/email/inbox/legacy-root.eml/{label_id}",
    )
    email_after_assign = request("GET", "/web/userdata/labels/email/inbox/legacy-root.eml")
    removed = request(
        "DELETE",
        f"/web/userdata/labels/email/inbox/legacy-root.eml/{label_id}",
    )
    removed_again = request(
        "DELETE",
        f"/web/userdata/labels/email/inbox/legacy-root.eml/{label_id}",
    )
    email_after_remove = request("GET", "/web/userdata/labels/email/inbox/legacy-root.eml")
    deleted = request("DELETE", f"/web/userdata/labels/{label_id}")
    after = request("GET", "/web/userdata/labels")
    missing_update = request(
        "PUT",
        "/web/userdata/labels/999999",
        value={"name": "missing", "color": "#000000"},
        canonicalize=True,
    )
    missing_delete = request(
        "DELETE",
        "/web/userdata/labels/999999",
        canonicalize=True,
    )
    missing_assignment = request(
        "POST",
        "/web/userdata/labels/email/inbox/legacy-root.eml/999999",
        canonicalize=True,
    )
    return {
        "before": before,
        "duplicate": duplicate,
        "created": created,
        "updated": updated,
        "listed": listed,
        "email_before": email_before,
        "assigned": assigned,
        "assigned_again": assigned_again,
        "email_after_assign": email_after_assign,
        "removed": removed,
        "removed_again": removed_again,
        "email_after_remove": email_after_remove,
        "deleted": deleted,
        "after": after,
        "missing_update": missing_update,
        "missing_delete": missing_delete,
        "missing_assignment": missing_assignment,
    }


cast(Any, _capture_mail_mutations).__lmyzmail_contract__ = {
    "protocol": "http",
    "sequence": [
        "list, reject duplicate, create, update, and list labels",
        "assign and remove one label idempotently on the seeded email",
        "delete the label and exercise missing-label errors",
    ],
    "headers": [
        ["X-Session-Token", "<legacy-session-token>"],
        ["Content-Type", "application/json"],
    ],
    "state": "attested legacy PostgreSQL seed and Maildir fixture",
}


def _capture_delete_email(target: RuntimeTarget) -> dict[str, Any]:
    assert target.ports is not None
    port = target.ports.http

    def request(
        method: str,
        path: str,
        *,
        canonicalize: bool = False,
    ) -> dict[str, Any]:
        response = http_exchange(
            "127.0.0.1",
            port,
            method,
            path,
            headers=_SESSION_HEADERS,
            timeout=10.0,
        )
        if response.body.startswith((b"{", b"[")):
            return http_json_snapshot(
                response,
                canonicalize_object_order=canonicalize,
            )
        return http_bytes_snapshot(response)

    return {
        "before_list": request("GET", "/web/mail/list/inbox?page=0&size=50"),
        "before_stars": request("GET", "/web/userdata/stars/inbox"),
        "before_labels": request("GET", "/web/userdata/labels/email/inbox/legacy-root.eml"),
        "delete": request(
            "DELETE",
            "/web/mail/inbox/legacy-root.eml",
            canonicalize=True,
        ),
        "after_list": request("GET", "/web/mail/list/inbox?page=0&size=50"),
        "after_stars": request("GET", "/web/userdata/stars/inbox"),
        "after_labels": request("GET", "/web/userdata/labels/email/inbox/legacy-root.eml"),
        "after_detail": request("GET", "/web/mail/detail/inbox/legacy-root.eml"),
        "after_raw": request("GET", "/web/mail/raw/inbox/legacy-root.eml"),
        "delete_again": request("DELETE", "/web/mail/inbox/legacy-root.eml"),
    }


cast(Any, _capture_delete_email).__lmyzmail_contract__ = {
    "protocol": "http",
    "sequence": [
        "observe seeded email, star, and label assignment",
        "DELETE /web/mail/inbox/legacy-root.eml",
        "observe list, star, label, detail, raw, and repeated-delete behavior",
    ],
    "headers": [["X-Session-Token", "<legacy-session-token>"]],
    "state": "attested legacy PostgreSQL seed and Maildir fixture",
}


MAIL_MUTATION_SCENARIOS = (
    Scenario(
        "http/mail/labels-crud",
        _capture_mail_mutations,
        normalizers=("json-object-order:jdk-map-of:create-update",),
    ),
)
MAIL_DELETE_SCENARIOS = (
    Scenario(
        "http/mail/delete-email",
        _capture_delete_email,
        normalizers=("json-object-order:jdk-map-of:delete-response",),
    ),
)


class LegacyCandidateRuntime(CandidateRuntime):
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

    def _start_application(self) -> None:
        workspace, _ = self._require_state()
        source = self.paths.repository / "blackbox/fixtures/legacy/maildir"
        shutil.copytree(source, workspace / "maildir")
        super()._start_application()


def _candidate(repository: Path) -> LegacyCandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        runtime = LegacyCandidateRuntime.from_environment()
        assert isinstance(runtime, LegacyCandidateRuntime)
        return runtime
    return LegacyCandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        )
    )


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_frozen_java_mail_read_golden(
    tmp_path: Path,
    record_java_golden: bool,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java/managed-mail-read-v23"
    runner = DifferentialRunner(
        repository,
        golden,
        "managed-mail-read",
        record_java=record_java_golden,
    )
    with PersistentJavaOracleRuntime(tmp_path / "java-mail-read") as oracle:
        target = _OracleTarget(oracle)
        if record_java_golden:
            runner.record_from_java(MAIL_READ_SCENARIOS, target)
        else:
            runner.verify_java(MAIL_READ_SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_mail_read_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java/managed-mail-read-v23",
            "managed-mail-read",
        ).verify_candidate(MAIL_READ_SCENARIOS, candidate)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_frozen_java_mail_attachment_golden(
    tmp_path: Path,
    record_java_golden: bool,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java/managed-mail-attachment-v18"
    runner = DifferentialRunner(
        repository,
        golden,
        "managed-mail-attachment",
        record_java=record_java_golden,
    )
    with PersistentJavaOracleRuntime(tmp_path / "java-mail-attachment") as oracle:
        target = _OracleTarget(oracle)
        if record_java_golden:
            runner.record_from_java(MAIL_ATTACHMENT_SCENARIOS, target)
        else:
            runner.verify_java(MAIL_ATTACHMENT_SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_mail_attachment_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java/managed-mail-attachment-v18",
            "managed-mail-attachment",
        ).verify_candidate(MAIL_ATTACHMENT_SCENARIOS, candidate)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_frozen_java_mail_state_golden(
    tmp_path: Path,
    record_java_golden: bool,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java/managed-mail-state-v21"
    runner = DifferentialRunner(
        repository,
        golden,
        "managed-mail-state",
        record_java=record_java_golden,
    )
    with PersistentJavaOracleRuntime(tmp_path / "java-mail-state") as oracle:
        target = _OracleTarget(oracle)
        if record_java_golden:
            runner.record_from_java(MAIL_STATE_SCENARIOS, target)
        else:
            runner.verify_java(MAIL_STATE_SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_mail_state_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java/managed-mail-state-v21",
            "managed-mail-state",
        ).verify_candidate(MAIL_STATE_SCENARIOS, candidate)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_frozen_java_mail_mutations_golden(
    tmp_path: Path,
    record_java_golden: bool,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java/managed-mail-mutations-v20"
    runner = DifferentialRunner(
        repository,
        golden,
        "managed-mail-mutations",
        record_java=record_java_golden,
    )
    with PersistentJavaOracleRuntime(tmp_path / "java-mail-mutations") as oracle:
        target = _OracleTarget(oracle)
        if record_java_golden:
            runner.record_from_java(MAIL_MUTATION_SCENARIOS, target)
        else:
            runner.verify_java(MAIL_MUTATION_SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_mail_mutations_match_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java/managed-mail-mutations-v20",
            "managed-mail-mutations",
        ).verify_candidate(MAIL_MUTATION_SCENARIOS, candidate)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_frozen_java_delete_email_golden(
    tmp_path: Path,
    record_java_golden: bool,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    golden = repository / "blackbox/golden/java/managed-mail-delete-v20"
    runner = DifferentialRunner(
        repository,
        golden,
        "managed-mail-delete",
        record_java=record_java_golden,
    )
    with PersistentJavaOracleRuntime(tmp_path / "java-mail-delete") as oracle:
        target = _OracleTarget(oracle)
        if record_java_golden:
            runner.record_from_java(MAIL_DELETE_SCENARIOS, target)
        else:
            runner.verify_java(MAIL_DELETE_SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_delete_email_matches_frozen_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java/managed-mail-delete-v20",
            "managed-mail-delete",
        ).verify_candidate(MAIL_DELETE_SCENARIOS, candidate)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_rust_candidate_rejects_unindexed_maildir_file() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        assert candidate.workspace is not None
        assert candidate.ports is not None
        source = (
            repository / "blackbox/fixtures/legacy/maildir/qa@example.test/inbox/legacy-root.eml"
        )
        destination = candidate.workspace / "maildir/qa@example.test/inbox/unindexed.eml"
        shutil.copyfile(source, destination)
        response = http_exchange(
            "127.0.0.1",
            candidate.ports.http,
            "GET",
            "/web/mail/raw/inbox/unindexed.eml",
            headers=_SESSION_HEADERS,
        )
        assert response.status_code == 404
