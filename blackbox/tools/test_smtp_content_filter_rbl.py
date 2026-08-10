from __future__ import annotations

import base64
import hashlib
import os
import shutil
import socket
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest

from lmyzmail_blackbox import smtp_contract
from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.errors import HarnessError, ProtocolError
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.protocols import BoundedSocket, RawSmtpClient, read_smtp_reply
from lmyzmail_blackbox.runtime import CandidateRuntime
from lmyzmail_blackbox.smtp_contract import capture_delivery

_GOLDEN = "managed-smtp-content-filter-rbl-v1"
_PROFILE = "managed-smtp-content-filter-rbl"
_RBL_SERVERS = ("listed-one.rbl.test", "absent.rbl.test", "listed-two.rbl.test")
_RBL_ENVIRONMENT = (
    "LMYZMAIL_RBL_HOSTS_FILE",
    "LMYZMAIL_RBL_RESOLV_CONF_FILE",
    "LMYZMAIL_RBL_SOURCE_IP",
    "LMYZMAIL_RBL_REVERSED_IP",
)
_NORMALIZERS = (
    "smtp:greeting-skibidi-grammar",
    "smtp:server-hostname",
    "smtp:session-id",
    "maildir:generated-filename",
    "maildir:server-hostname",
    "maildir:received-id",
    "maildir:received-at",
    "postgres:identity-timestamps-and-hostname-derived-size",
    "smtp:data-dot-unstuff",
    "smtp:rbl-source-ipv6",
)
_JAVA_OVERRIDES = (
    "--botmail.smtp.bind-address=::",
    "--botmail.contentfilter.rules.RBL_CHECK.enabled=true",
    "--botmail.contentfilter.rules.RBL_CHECK.weight=1.5",
    "--botmail.contentfilter.rules.NEW_DOMAIN.enabled=false",
    "--botmail.contentfilter.rules.MISSING_HEADERS.enabled=false",
    "--botmail.contentfilter.rules.SUBJECT_ENCODING_TRICK.enabled=false",
    "--botmail.contentfilter.rules.EXCESSIVE_RECIPIENTS.enabled=false",
    "--botmail.contentfilter.rules.FROM_REPLYTO_MISMATCH.enabled=false",
    "--botmail.contentfilter.rules.SUSPICIOUS_DATE.enabled=false",
    "--botmail.contentfilter.rules.SPAM_KEYWORDS.enabled=false",
    "--botmail.contentfilter.rules.SUSPICIOUS_URL.enabled=false",
    "--botmail.contentfilter.rules.HTML_TEXT_RATIO.enabled=false",
    "--botmail.contentfilter.rules.PHISHING_PATTERN.enabled=false",
    "--botmail.contentfilter.rules.INVISIBLE_TEXT.enabled=false",
    "--botmail.contentfilter.rules.DANGEROUS_EXTENSION.enabled=false",
    "--botmail.contentfilter.rules.DOUBLE_EXTENSION.enabled=false",
    "--botmail.contentfilter.rules.MIME_TYPE_MISMATCH.enabled=false",
    f"--botmail.contentfilter.rbl.servers={','.join(_RBL_SERVERS)}",
    "--botmail.contentfilter.rbl.timeout-ms=500",
    "--botmail.contentfilter.rbl.score-per-hit=3.0",
    "--botmail.contentfilter.rbl.max-score=5.0",
)
_CANDIDATE_OVERRIDES = (
    "--lmyzmail.maildir.max-files-per-directory=1",
    *(value.replace("--botmail.", "--lmyzmail.", 1) for value in _JAVA_OVERRIDES[1:]),
)
_POSITIVE_ID = "<bb-rbl-positive-001@example.test>"
_PRIVATE_ID = "<bb-rbl-private-001@example.test>"


def _message(subject: str, message_id: str) -> bytes:
    return (
        "From: sender@external.test\r\n"
        "Date: Tue, 5 Aug 2025 12:00:00 GMT\r\n"
        f"Subject: {subject}\r\n"
        f"Message-ID: {message_id}\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "\r\n"
        "RBL envelope test body.\r\n"
    ).encode("ascii")


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value:
        raise HarnessError(f"RBL harness environment is missing: {name}")
    return value


def _namespace_prefix() -> list[str]:
    unshare = shutil.which("unshare")
    if unshare is None:
        raise HarnessError("RBL harness requires unshare")
    script = Path(__file__).with_name("run_smtp_rbl.py").resolve()
    return [
        str(Path(unshare).resolve()),
        "--user",
        "--map-root-user",
        "--mount",
        "--propagation",
        "private",
        sys.executable,
        str(script),
        "--namespace-exec",
    ]


def _namespace_environment(environment: dict[str, str]) -> dict[str, str]:
    for name in _RBL_ENVIRONMENT:
        environment[name] = _required_environment(name)
    return environment


def _normalize_source_ipv6(delivery: dict[str, Any]) -> dict[str, Any]:
    raw = delivery["storage"]["maildir"]["raw"]
    encoded = raw["base64"]
    if not isinstance(encoded, str):
        raise ProtocolError("RBL Maildir observation lost its base64 payload")
    message = base64.b64decode(encoded, validate=True)
    source = _required_environment("LMYZMAIL_RBL_SOURCE_IP").encode("ascii")
    occurrences = message.count(source)
    if occurrences < 1:
        raise ProtocolError("RBL Maildir observation did not contain the dynamic source IPv6")
    normalized = message.replace(source, b"<rbl-source-ipv6>")
    raw["base64"] = base64.b64encode(normalized).decode("ascii")
    raw["length"] = len(normalized)
    raw["sha256"] = hashlib.sha256(normalized).hexdigest()
    return delivery


class _RblJavaRuntime(PersistentJavaOracleRuntime):
    def _application_arguments(self) -> list[str]:
        arguments = [*super()._application_arguments(), *_JAVA_OVERRIDES]
        return [*_namespace_prefix(), *arguments]

    def _application_environment(self) -> dict[str, str]:
        return _namespace_environment(super()._application_environment())


class _RblCandidateRuntime(CandidateRuntime):
    def _application_arguments(self) -> list[str]:
        return [*_namespace_prefix(), *super()._application_arguments()]

    def _application_environment(self) -> dict[str, str]:
        return _namespace_environment(super()._application_environment())


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


def _candidate(repository: Path) -> _RblCandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        return cast(_RblCandidateRuntime, _RblCandidateRuntime.from_environment())
    return _RblCandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
            "--lmyzmail.listen.host=::",
            *_CANDIDATE_OVERRIDES,
        )
    )


def _source_bound_smtp_client(target: RuntimeTarget) -> tuple[RawSmtpClient, bytes]:
    if target.ports is None:
        raise RuntimeError("RBL SMTP target is not started")
    deadline = time.monotonic() + 10.0
    source_ip = _required_environment("LMYZMAIL_RBL_SOURCE_IP")
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        sock.settimeout(10.0)
        sock.bind((source_ip, 0))
        sock.connect((source_ip, target.ports.smtp))
        stream = BoundedSocket(sock, deadline=deadline)
        greeting = read_smtp_reply(stream)
        client = RawSmtpClient(stream=stream, greeting=greeting)
        if len(greeting) != 1:
            raise ProtocolError(f"RBL SMTP greeting was not singular: {greeting!r}")
        match = smtp_contract._GREETING.fullmatch(greeting[0])
        if match is None:
            raise ProtocolError(f"RBL SMTP greeting was invalid: {greeting!r}")
        return client, match.group("hostname")
    except BaseException:
        sock.close()
        raise


def _capture_positive(target: RuntimeTarget) -> dict[str, Any]:
    original = smtp_contract.open_smtp_client
    smtp_contract.open_smtp_client = _source_bound_smtp_client
    try:
        delivery = capture_delivery(
            target,
            mode="data",
            subject="bb-rbl-positive-001",
            message_id=_POSITIVE_ID,
            message=_message("bb-rbl-positive-001", _POSITIVE_ID),
            expected_from_address="sender@external.test",
        )
    finally:
        smtp_contract.open_smtp_client = original
    return _normalize_source_ipv6(delivery)


def _capture_private_skip(target: RuntimeTarget) -> dict[str, Any]:
    return capture_delivery(
        target,
        mode="data",
        subject="bb-rbl-private-001",
        message_id=_PRIVATE_ID,
        message=_message("bb-rbl-private-001", _PRIVATE_ID),
        expected_from_address="sender@external.test",
    )


SCENARIOS = (
    Scenario(
        "smtp/content-filter/rbl-positive-cap-and-weight",
        _capture_positive,
        _NORMALIZERS,
        contract={
            "protocol": "smtp",
            "operation": "content-filter-envelope-rbl",
            "client_ip": "<rbl-source-ipv6>",
            "reversed_ip": "<rbl-source-ipv6-reversed-nibbles>",
            "listed_servers": ["listed-one.rbl.test", "listed-two.rbl.test"],
            "nxdomain_servers": ["absent.rbl.test"],
            "score_per_hit": 3.0,
            "max_score": 5.0,
            "rule_weight": 1.5,
            "expected_weighted_score": 7.5,
        },
    ),
    Scenario(
        "smtp/content-filter/rbl-private-skip",
        _capture_private_skip,
        _NORMALIZERS,
        contract={
            "protocol": "smtp",
            "operation": "content-filter-envelope-rbl-private-skip",
            "client_ip": "127.0.0.1",
            "expected_rbl_queries": 0,
            "expected_score": 0.0,
        },
    ),
)


def _require_runner() -> None:
    if any(os.environ.get(name) is None for name in _RBL_ENVIRONMENT):
        pytest.fail("RBL differential must run through blackbox/tools/run_smtp_rbl.py")


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(240)
def test_frozen_java_smtp_content_filter_rbl_golden(tmp_path: Path) -> None:
    _require_runner()
    repository = Path(__file__).resolve().parents[2]
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        repository / "blackbox/golden/java" / _GOLDEN,
        _PROFILE,
        record_java=record,
    )
    with _RblJavaRuntime(tmp_path / "java-smtp-content-filter-rbl") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(240)
def test_rust_candidate_smtp_content_filter_rbl_matches_golden() -> None:
    _require_runner()
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java" / _GOLDEN,
            _PROFILE,
        ).verify_candidate(SCENARIOS, candidate)
