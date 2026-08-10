from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.ports import PortSet
from lmyzmail_blackbox.runtime import CandidateRuntime
from lmyzmail_blackbox.smtp_contract import capture_delivery

_GOLDEN = "managed-smtp-content-filter-body-v1"
_PROFILE = "managed-smtp-content-filter-body"
_FROM = "sender@external.test"
_DATE = "Tue, 5 Aug 2025 12:00:00 GMT"
_JAVA_OVERRIDES = (
    "--botmail.contentfilter.rules.RBL_CHECK.enabled=false",
    "--botmail.contentfilter.rules.NEW_DOMAIN.enabled=false",
    "--botmail.contentfilter.rules.MISSING_HEADERS.enabled=false",
    "--botmail.contentfilter.rules.SUBJECT_ENCODING_TRICK.enabled=false",
    "--botmail.contentfilter.rules.EXCESSIVE_RECIPIENTS.enabled=false",
    "--botmail.contentfilter.rules.FROM_REPLYTO_MISMATCH.enabled=false",
    "--botmail.contentfilter.rules.SUSPICIOUS_DATE.enabled=false",
    "--botmail.contentfilter.rules.SPAM_KEYWORDS.enabled=true",
    "--botmail.contentfilter.rules.SPAM_KEYWORDS.weight=2.0",
    "--botmail.contentfilter.rules.SUSPICIOUS_URL.enabled=true",
    "--botmail.contentfilter.rules.SUSPICIOUS_URL.weight=1.5",
    "--botmail.contentfilter.rules.HTML_TEXT_RATIO.enabled=false",
    "--botmail.contentfilter.rules.PHISHING_PATTERN.enabled=false",
    "--botmail.contentfilter.rules.INVISIBLE_TEXT.enabled=false",
    "--botmail.contentfilter.rules.DANGEROUS_EXTENSION.enabled=false",
    "--botmail.contentfilter.rules.DOUBLE_EXTENSION.enabled=false",
    "--botmail.contentfilter.rules.MIME_TYPE_MISMATCH.enabled=false",
)
_CANDIDATE_OVERRIDES = (
    "--lmyzmail.maildir.max-files-per-directory=1",
    *(value.replace("--botmail.", "--lmyzmail.", 1) for value in _JAVA_OVERRIDES),
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
)


class _BodyFilterJavaRuntime(PersistentJavaOracleRuntime):
    def _application_arguments(self) -> list[str]:
        return [*super()._application_arguments(), *_JAVA_OVERRIDES]


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


def _candidate(repository: Path) -> CandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        return CandidateRuntime.from_environment()
    return CandidateRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
            *_CANDIDATE_OVERRIDES,
        )
    )


def _message(subject: str, message_id: str, body: str, *, content_type: str) -> bytes:
    return (
        f"From: {_FROM}\r\n"
        f"Date: {_DATE}\r\n"
        f"Subject: {subject}\r\n"
        f"Message-ID: {message_id}\r\n"
        "MIME-Version: 1.0\r\n"
        f"Content-Type: {content_type}\r\n"
        "\r\n"
        f"{body}"
    ).encode("ascii")


def _scenario(
    name: str,
    *,
    subject: str,
    body: str,
    content_type: str = "text/plain; charset=us-ascii",
    expected_status: str,
    expected_score: str,
    expected_rules: tuple[tuple[str, str], ...],
) -> Scenario:
    message_id = f"<{subject}@example.test>"
    message = _message(subject, message_id, body, content_type=content_type)
    expected_has_attachments = content_type == "application/octet-stream"

    def capture(target: RuntimeTarget) -> dict[str, Any]:
        return capture_delivery(
            target,
            mode="data",
            subject=subject,
            message_id=message_id,
            message=message,
            expected_from_address=_FROM,
            expected_has_attachments=expected_has_attachments,
        )

    return Scenario(
        name,
        capture,
        _NORMALIZERS,
        contract={
            "protocol": "smtp",
            "operation": "content-filter-body-phase",
            "message_sha256": hashlib.sha256(message).hexdigest(),
            "message_id": message_id,
            "rules_enabled": ["SPAM_KEYWORDS", "SUSPICIOUS_URL"],
            "rule_weights": {"SPAM_KEYWORDS": 2.0, "SUSPICIOUS_URL": 1.5},
            "expected": {
                "status": expected_status,
                "score": expected_score,
                "rules": [list(value) for value in expected_rules],
                "storage_folder": "spam",
            },
            "side_effects": ["maildir", "postgres:email_index", "redis:mail-count"],
            "delivery_cardinality": "exactly-once",
        },
    )


SCENARIOS = (
    _scenario(
        "smtp/content-filter/body-keyword-low-density",
        subject="bb-body-keyword-low-001",
        body=("a" * 3_000) + " viagra\r\n",
        expected_status="No",
        expected_score="1.0",
        expected_rules=(("SPAM_KEYWORDS", "1.0"),),
    ),
    _scenario(
        "smtp/content-filter/body-keyword-and-shortener-order",
        subject="bb-body-order-001",
        body="viagra\r\nhttps://bit.ly/offer\r\n",
        expected_status="Yes",
        expected_score="18.3",
        expected_rules=(("SPAM_KEYWORDS", "16.0"), ("SUSPICIOUS_URL", "2.3")),
    ),
    _scenario(
        "smtp/content-filter/body-url-dedup-and-cap",
        subject="bb-body-url-cap-001",
        body=(
            "https://bit.ly/a https://bit.ly/a\r\n"
            "https://sub.bit.ly/b\r\n"
            "https://bad.xyz/a https://evil.top/b\r\n"
            "http://203.0.113.10/a\r\n"
        ),
        expected_status="Yes",
        expected_score="12.0",
        expected_rules=(("SUSPICIOUS_URL", "12.0"),),
    ),
    _scenario(
        "smtp/content-filter/body-non-text-skip",
        subject="bb-body-nontext-001",
        body="viagra https://bit.ly/offer\r\n",
        content_type="application/octet-stream",
        expected_status="No",
        expected_score="0.0",
        expected_rules=(),
    ),
)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(360)
def test_frozen_java_smtp_content_filter_body_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        repository / "blackbox/golden/java" / _GOLDEN,
        _PROFILE,
        record_java=record,
    )
    with _BodyFilterJavaRuntime(tmp_path / "java-smtp-content-filter-body") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(360)
def test_rust_candidate_smtp_content_filter_body_matches_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java" / _GOLDEN,
            _PROFILE,
        ).verify_candidate(SCENARIOS, candidate)
