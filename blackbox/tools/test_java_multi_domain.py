# ruff: noqa: S101 - black-box probe assertions are test contract checks.
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psycopg
import pytest

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.normalize import FieldRule, constant
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.protocols import http_exchange
from lmyzmail_blackbox.runtime import API_KEY, CandidateRuntime
from lmyzmail_blackbox.smtp_contract import open_smtp_client, smtp_ehlo, smtp_reply_snapshot
from lmyzmail_blackbox.snapshots import HeaderRule, http_json_snapshot

_GOLDEN = "managed-java-multi-domain-v7"
_PROFILE = "managed-java-multi-domain"

_PASSWORD_HASH = (
    "$2a$10$KMejGNeOXWSJBM831XMwmeVrw.16AhD65yYCs7vxZIM0osXpoyPsm"  # noqa: S105 - public isolated bcrypt fixture.
)
_OUTBOUND_SENDERS = (
    "outbound-primary@example.test",
    "outbound-second@second.example.test",
    "outbound-send-only@send-only.example.test",
    "outbound-unknown@unknown.example.test",
)


def _seed_outbound_senders(runtime: PersistentJavaOracleRuntime | CandidateRuntime) -> None:
    workspace, ports = runtime._require_state()
    psql = runtime.paths.runtime / "postgres-root/usr/lib/postgresql/16/bin/psql"
    values = ",".join(
        f"('{address}','{_PASSWORD_HASH}',CURRENT_TIMESTAMP)" for address in _OUTBOUND_SENDERS
    )
    runtime._run_checked(
        [
            str(psql),
            "--host=127.0.0.1",
            f"--port={ports.postgres}",
            "--username=lmyzmail_test",
            "--dbname=lmyzmail",
            "--set=ON_ERROR_STOP=1",
            "--command="  # noqa: S608 - values are compile-time fixture constants.
            + "INSERT INTO mailbox (address,password_hash,created_at) VALUES "
            + values
            + " ON CONFLICT (address) DO NOTHING;",
        ],
        env=runtime._postgres_env(),
        log_path=workspace / "postgres-multi-domain-seed.log",
    )


class _MultiDomainJavaRuntime(PersistentJavaOracleRuntime):
    def _application_arguments(self) -> list[str]:
        inherited = [
            argument
            for argument in super()._application_arguments()
            if not argument.startswith("--botmail.domains.")
        ]
        return [
            *inherited,
            "--botmail.domains.main.domain=example.test",
            "--botmail.domains.main.receiveEnabled=true",
            "--botmail.domains.main.sendEnabled=true",
            "--botmail.domains.main.requireExistingMailbox=true",
            "--botmail.domains.secondary.domain=SECOND.example.test",
            "--botmail.domains.secondary.receiveEnabled=false",
            "--botmail.domains.secondary.sendEnabled=false",
            "--botmail.domains.secondary.requireExistingMailbox=false",
            "--botmail.domains.duplicate.domain=second.example.test",
            "--botmail.domains.duplicate.receiveEnabled=true",
            "--botmail.domains.duplicate.sendEnabled=true",
            "--botmail.domains.duplicate.requireExistingMailbox=false",
            "--botmail.domains.send-only.domain=send-only.example.test",
            "--botmail.domains.send-only.receiveEnabled=false",
            "--botmail.domains.send-only.sendEnabled=true",
            "--botmail.domains.send-only.requireExistingMailbox=false",
        ]

    def _start_application(self) -> None:
        _seed_outbound_senders(self)
        super()._start_application()


@dataclass(frozen=True, slots=True)
class _Target:
    runtime: _MultiDomainJavaRuntime

    @property
    def target_kind(self) -> str:
        return "java-oracle"

    @property
    def workspace(self) -> Path | None:
        return self.runtime.workspace

    @property
    def ports(self) -> PortSet | None:
        return self.runtime.ports


class _MultiDomainCandidateRuntime(CandidateRuntime):
    def _start_application(self) -> None:
        _seed_outbound_senders(self)
        super()._start_application()

    def _candidate_configuration(self) -> Path:
        path = super()._candidate_configuration()
        value = json.loads(path.read_text(encoding="utf-8"))
        value["domains"] = [
            {
                "domain": "second.example.test",
                "receive_enabled": True,
                "send_enabled": True,
                "require_existing_mailbox": False,
            },
            {
                "domain": "example.test",
                "receive_enabled": True,
                "send_enabled": True,
                "require_existing_mailbox": True,
            },
            {
                "domain": "SECOND.example.test",
                "receive_enabled": False,
                "send_enabled": False,
                "require_existing_mailbox": False,
            },
            {
                "domain": "send-only.example.test",
                "receive_enabled": False,
                "send_enabled": True,
                "require_existing_mailbox": False,
            },
        ]
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return path


def _http_json(target: RuntimeTarget, method: str, path: str) -> dict[str, Any]:
    assert target.ports is not None
    response = http_exchange(
        "127.0.0.1",
        target.ports.http,
        method,
        path,
        headers=(("X-API-Key", API_KEY),) if path.startswith("/api/") else (),
        body=b"{}" if method in {"POST", "PUT"} else b"",
    )
    rules = (FieldRule(("timestamp",), constant("<timestamp>")),) if path == "/api/status" else ()
    return http_json_snapshot(
        response,
        rules=rules,
        header_rules=(HeaderRule(b"content-length", lambda _: b"<normalized-json>"),),
        canonicalize_object_order=True,
    )


def _register(target: RuntimeTarget, address: str) -> dict[str, Any]:
    assert target.ports is not None
    response = http_exchange(
        "127.0.0.1",
        target.ports.http,
        "POST",
        "/web/register",
        headers=(("Content-Type", "application/json"),),
        body=json.dumps(
            {"address": address, "password": "BlackboxPass123!"},
            separators=(",", ":"),
        ).encode("utf-8"),
    )
    rules = (FieldRule(("id",), constant("<id>")),) if response.status_code == 201 else ()
    return http_json_snapshot(
        response,
        rules=rules,
        header_rules=(HeaderRule(b"content-length", lambda _: b"<normalized-json>"),),
        canonicalize_object_order=True,
    )


def _send(target: RuntimeTarget, address: str) -> dict[str, Any]:
    assert target.ports is not None
    response = http_exchange(
        "127.0.0.1",
        target.ports.http,
        "POST",
        "/api/mail/send",
        headers=(
            ("X-API-Key", API_KEY),
            ("Content-Type", "application/json"),
        ),
        body=json.dumps(
            {
                "from": address,
                "password": "BlackboxPass123!",
                "to": ["recipient@example.invalid"],
                "subject": "Multi-domain outbound admission",
                "text": "queued body",
                "async": True,
            },
            separators=(",", ":"),
        ).encode("utf-8"),
    )
    rules = (
        (
            FieldRule(("queueId",), constant("<queue-id>")),
            FieldRule(("messageId",), constant("<message-id>")),
        )
        if response.status_code == 202
        else ()
    )
    return http_json_snapshot(
        response,
        rules=rules,
        header_rules=(HeaderRule(b"content-length", lambda _: b"<normalized-json>"),),
        canonicalize_object_order=True,
    )


def _outbound_sender_count(target: RuntimeTarget, address: str) -> int:
    assert target.ports is not None
    client = psycopg.connect(
        host="127.0.0.1",
        port=target.ports.postgres,
        dbname="lmyzmail",
        user="lmyzmail_test",
        password="",
    )
    try:
        row = client.execute(
            "SELECT count(*) FROM outbound_mail_queue WHERE sender_address=%s", (address,)
        ).fetchone()
        assert row is not None
        return int(row[0])
    finally:
        client.close()


def _smtp_rcpt(target: RuntimeTarget, recipient: bytes) -> dict[str, Any]:
    client, hostname = open_smtp_client(target)
    try:
        ehlo = smtp_ehlo(client, hostname)
        mail_from = client.command(b"MAIL FROM:<sender@sender.lmyz.net>")
        rcpt = client.command(b"RCPT TO:<" + recipient + b">")
        quit_reply = client.quit()
    finally:
        client.close()
    ehlo_lines = [line.decode("ascii", errors="strict") for line in ehlo]
    if ehlo_lines:
        ehlo_lines[0] = ehlo_lines[0].replace("MSI", "<brand>").replace("lmyzmail", "<brand>")
    return {
        "ehlo": ehlo_lines,
        "mail_from": smtp_reply_snapshot(mail_from, hostname),
        "rcpt": smtp_reply_snapshot(rcpt, hostname),
        "quit": smtp_reply_snapshot(quit_reply, hostname),
    }


def _capture(target: RuntimeTarget) -> dict[str, Any]:
    return {
        "api_status": _http_json(target, "POST", "/api/status"),
        "web_domains": _http_json(target, "GET", "/web/domains"),
        "web_config": _http_json(target, "GET", "/web/config"),
        "registration": {
            "primary": _register(target, "multi-primary@example.test"),
            "second": _register(target, "multi-second@second.example.test"),
            "send_only": _register(target, "multi-send@send-only.example.test"),
            "unknown": _register(target, "multi-unknown@unknown.example.test"),
        },
        "outbound_admission": _capture_outbound_admission(target),
        "smtp": {
            "primary": _smtp_rcpt(target, b"qa@example.test"),
            "second": _smtp_rcpt(target, b"unknown@second.example.test"),
            "second_case": _smtp_rcpt(target, b"unknown@SECOND.EXAMPLE.TEST"),
            "send_only": _smtp_rcpt(target, b"unknown@send-only.example.test"),
            "unknown": _smtp_rcpt(target, b"unknown@unknown.example.test"),
        },
}


def _capture_outbound_admission(target: RuntimeTarget) -> dict[str, Any]:
    primary = _send(target, _OUTBOUND_SENDERS[0])
    second = _send(target, _OUTBOUND_SENDERS[1])
    after_second = _outbound_sender_count(target, _OUTBOUND_SENDERS[1])
    send_only = _send(target, _OUTBOUND_SENDERS[2])
    unknown = _send(target, _OUTBOUND_SENDERS[3])
    after_unknown = _outbound_sender_count(target, _OUTBOUND_SENDERS[3])
    return {
        "primary": primary,
        "second": second,
        "send_only": send_only,
        "unknown": unknown,
        "rejected_sender_counts": {
            "second": after_second,
            "unknown": after_unknown,
        },
    }


SCENARIOS = (
    Scenario(
        "config/multi-domain-surface",
        _capture,
        normalizers=(
            "header:date:http-date",
            "smtp:server-hostname",
            "smtp:explicit-java-msi-to-lmyzmail-brand-difference",
        ),
        contract={
            "protocols": ["http", "smtp"],
            "http_operations": [
                "domain-discovery",
                "mailbox-registration",
                "outbound-admission",
            ],
            "domains": [
                "example.test",
                "second.example.test",
                "send-only.example.test",
                "unknown.example.test",
            ],
            "duplicate_normalized_domain": "second.example.test",
        },
    ),
)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(240)
def test_java_multi_domain_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    runner = DifferentialRunner(
        repository,
        repository / "blackbox/golden/java" / _GOLDEN,
        _PROFILE,
        record_java=os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1",
    )
    with _MultiDomainJavaRuntime(tmp_path / "java-multi-domain") as oracle:
        if runner.record_java:
            runner.record_from_java(SCENARIOS, _Target(oracle))
        else:
            runner.verify_java(SCENARIOS, _Target(oracle))


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(240)
def test_rust_candidate_multi_domain_matches_java_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        candidate = _MultiDomainCandidateRuntime.from_environment()
    else:
        candidate = _MultiDomainCandidateRuntime(
            command_template=(
                str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
                "--config",
                "{config}",
            )
        )
    with candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java" / _GOLDEN,
            _PROFILE,
        ).verify_candidate(SCENARIOS, candidate)
