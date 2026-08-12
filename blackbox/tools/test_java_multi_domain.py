from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.protocols import http_exchange
from lmyzmail_blackbox.runtime import API_KEY
from lmyzmail_blackbox.snapshots import HeaderRule, http_json_snapshot
from lmyzmail_blackbox.normalize import FieldRule, constant
from lmyzmail_blackbox.smtp_contract import open_smtp_client, smtp_ehlo, smtp_reply_snapshot

_GOLDEN = "managed-java-multi-domain-v1"
_PROFILE = "managed-java-multi-domain"


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


def _smtp_rcpt(target: RuntimeTarget, recipient: bytes) -> dict[str, Any]:
    client, hostname = open_smtp_client(target)
    try:
        ehlo = smtp_ehlo(client, hostname)
        mail_from = client.command(b"MAIL FROM:<sender@sender.lmyz.net>")
        rcpt = client.command(b"RCPT TO:<" + recipient + b">")
        quit_reply = client.quit()
    finally:
        client.close()
    return {
        "ehlo": [line.decode("ascii", errors="strict") for line in ehlo],
        "mail_from": smtp_reply_snapshot(mail_from, hostname),
        "rcpt": smtp_reply_snapshot(rcpt, hostname),
        "quit": smtp_reply_snapshot(quit_reply, hostname),
    }


def _capture(target: RuntimeTarget) -> dict[str, Any]:
    return {
        "api_status": _http_json(target, "POST", "/api/status"),
        "web_domains": _http_json(target, "GET", "/web/domains"),
        "web_config": _http_json(target, "GET", "/web/config"),
        "smtp": {
            "primary": _smtp_rcpt(target, b"qa@example.test"),
            "second": _smtp_rcpt(target, b"unknown@second.example.test"),
            "second_case": _smtp_rcpt(target, b"unknown@SECOND.EXAMPLE.TEST"),
            "send_only": _smtp_rcpt(target, b"unknown@send-only.example.test"),
            "unknown": _smtp_rcpt(target, b"unknown@unknown.example.test"),
        },
    }


SCENARIOS = (
    Scenario(
        "config/multi-domain-surface",
        _capture,
        normalizers=("header:date:http-date", "smtp:server-hostname"),
        contract={
            "protocols": ["http", "smtp"],
            "domains": ["example.test", "second.example.test", "send-only.example.test", "unknown.example.test"],
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
