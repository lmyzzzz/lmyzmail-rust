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

_GOLDEN = "managed-smtp-content-filter-headers-v7"
_PROFILE = "managed-smtp-content-filter-headers"
_FROM = "sender@external.test"
_DATE = "Tue, 5 Aug 2025 12:00:00 GMT"
_RULE_OVERRIDES = (
    "--botmail.contentfilter.rules.RBL_CHECK.enabled=false",
    "--botmail.contentfilter.rules.NEW_DOMAIN.enabled=false",
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
)
_CANDIDATE_RULE_OVERRIDES = tuple(
    value.replace("--botmail.", "--lmyzmail.", 1) for value in _RULE_OVERRIDES
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
)


class _HeaderFilterJavaRuntime(PersistentJavaOracleRuntime):
    def _application_arguments(self) -> list[str]:
        return [*super()._application_arguments(), *_RULE_OVERRIDES]


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
            "--botmail.maildir.max-files-per-directory=1",
            *_CANDIDATE_RULE_OVERRIDES,
        )
    )


def _message(
    raw_subject: str,
    message_id: str,
    *,
    from_value: str | None = _FROM,
    date_value: str | None = _DATE,
    extra_headers: tuple[str, ...] = (),
) -> bytes:
    headers: list[str] = []
    if from_value is not None:
        headers.append(f"From: {from_value}")
    if date_value is not None:
        headers.append(f"Date: {date_value}")
    headers.extend(
        (
            f"Subject: {raw_subject}",
            f"Message-ID: {message_id}",
            *extra_headers,
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=us-ascii",
        )
    )
    return ("\r\n".join(headers) + "\r\n\r\nHeader filter body.\r\n").encode("ascii")


def _recipient_header(count: int) -> str:
    return "Cc: " + ", ".join(f"recipient-{index}@example.test" for index in range(count))


_CLEAN_ID = "<bb-filter-clean-001@example.test>"
_CLEAN_MESSAGE = _message("bb-filter-clean-001", _CLEAN_ID)
_MISSING_ID = "<bb-filter-missing-001@example.test>"
_MISSING_MESSAGE = _message(
    "bb-filter-missing-001",
    _MISSING_ID,
    from_value=None,
    date_value=None,
)
_MALFORMED_ID = "<bb-filter-malformed-001@example.test>"
_MALFORMED_MESSAGE = _message(
    "bb-filter-malformed-001",
    _MALFORMED_ID,
    from_value="not-an-address",
    date_value="short",
)
_ENCODED_ID = "<bb-filter-encoded-001@example.test>"
_ENCODED_RAW_SUBJECT = "=?UTF-8?Q?FREE?= =?ISO-8859-1?Q?MONEY?="
_ENCODED_MESSAGE = _message(_ENCODED_RAW_SUBJECT, _ENCODED_ID)
_RECIPIENT_20_ID = "<bb-filter-recipient-20@example.test>"
_RECIPIENT_20_MESSAGE = _message(
    "bb-filter-recipient-20",
    _RECIPIENT_20_ID,
    extra_headers=(_recipient_header(20),),
)
_RECIPIENT_50_ID = "<bb-filter-recipient-50@example.test>"
_RECIPIENT_50_MESSAGE = _message(
    "bb-filter-recipient-50",
    _RECIPIENT_50_ID,
    extra_headers=(_recipient_header(50),),
)


def _capture(
    target: RuntimeTarget,
    *,
    indexed_subject: str,
    message_id: str,
    message: bytes,
    expected_from: str | None,
) -> dict[str, Any]:
    return capture_delivery(
        target,
        mode="data",
        subject=indexed_subject,
        message_id=message_id,
        message=message,
        expected_from_address=expected_from,
    )


def _scenario(
    name: str,
    *,
    indexed_subject: str,
    message_id: str,
    message: bytes,
    expected_from: str | None,
    expected_score: str,
    expected_rules: tuple[tuple[str, str], ...],
) -> Scenario:
    def capture(target: RuntimeTarget) -> dict[str, Any]:
        return _capture(
            target,
            indexed_subject=indexed_subject,
            message_id=message_id,
            message=message,
            expected_from=expected_from,
        )

    contract = {
        "protocol": "smtp",
        "operation": "content-filter-header-phase",
        "message_sha256": hashlib.sha256(message).hexdigest(),
        "message_id": message_id,
        "rules_enabled": [
            "MISSING_HEADERS",
            "SUBJECT_ENCODING_TRICK",
            "EXCESSIVE_RECIPIENTS",
        ],
        "rules_disabled": [
            value.removeprefix("--botmail.contentfilter.rules.") for value in _RULE_OVERRIDES
        ],
        "expected": {
            "status": "No",
            "score": expected_score,
            "rules": [list(value) for value in expected_rules],
            "storage_folder": "spam",
        },
        "side_effects": ["maildir", "postgres:email_index", "redis:mail-count"],
        "delivery_cardinality": "exactly-once",
    }
    return Scenario(name, capture, _NORMALIZERS + ("smtp:data-dot-unstuff",), contract)


SCENARIOS = (
    _scenario(
        "smtp/content-filter/header-clean",
        indexed_subject="bb-filter-clean-001",
        message_id=_CLEAN_ID,
        message=_CLEAN_MESSAGE,
        expected_from=_FROM,
        expected_score="0.0",
        expected_rules=(),
    ),
    _scenario(
        "smtp/content-filter/header-missing-required",
        indexed_subject="bb-filter-missing-001",
        message_id=_MISSING_ID,
        message=_MISSING_MESSAGE,
        expected_from=None,
        expected_score="3.5",
        expected_rules=(("MISSING_HEADERS", "3.5"),),
    ),
    _scenario(
        "smtp/content-filter/header-malformed-required",
        indexed_subject="bb-filter-malformed-001",
        message_id=_MALFORMED_ID,
        message=_MALFORMED_MESSAGE,
        expected_from="not-an-address",
        expected_score="1.8",
        expected_rules=(("MISSING_HEADERS", "1.8"),),
    ),
    _scenario(
        "smtp/content-filter/header-encoded-subject",
        indexed_subject="FREEMONEY",
        message_id=_ENCODED_ID,
        message=_ENCODED_MESSAGE,
        expected_from=_FROM,
        expected_score="2.5",
        expected_rules=(("SUBJECT_ENCODING_TRICK", "2.5"),),
    ),
    _scenario(
        "smtp/content-filter/header-recipients-20",
        indexed_subject="bb-filter-recipient-20",
        message_id=_RECIPIENT_20_ID,
        message=_RECIPIENT_20_MESSAGE,
        expected_from=_FROM,
        expected_score="1.0",
        expected_rules=(("EXCESSIVE_RECIPIENTS", "1.0"),),
    ),
    _scenario(
        "smtp/content-filter/header-recipients-50",
        indexed_subject="bb-filter-recipient-50",
        message_id=_RECIPIENT_50_ID,
        message=_RECIPIENT_50_MESSAGE,
        expected_from=_FROM,
        expected_score="2.0",
        expected_rules=(("EXCESSIVE_RECIPIENTS", "2.0"),),
    ),
)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(360)
def test_frozen_java_smtp_content_filter_header_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        repository / "blackbox/golden/java" / _GOLDEN,
        _PROFILE,
        record_java=record,
    )
    with _HeaderFilterJavaRuntime(tmp_path / "java-smtp-content-filter-headers") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(360)
def test_rust_candidate_smtp_content_filter_headers_match_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java" / _GOLDEN,
            _PROFILE,
        ).verify_candidate(SCENARIOS, candidate)
