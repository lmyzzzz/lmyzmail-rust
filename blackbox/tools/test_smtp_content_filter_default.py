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

_GOLDEN = "managed-smtp-content-filter-default-v12"
_PROFILE = "managed-smtp-content-filter-default"
_FROM = "sender@external.test"
_DATE = "Tue, 5 Aug 2025 12:00:00 GMT"

# Keep network-dependent envelope rules out of this deterministic composition
# fixture. All remaining non-placeholder defaults stay enabled.
_JAVA_OVERRIDES = (
    "--botmail.contentfilter.rules.RBL_CHECK.enabled=false",
    "--botmail.contentfilter.rules.NEW_DOMAIN.enabled=false",
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


class _DefaultFilterJavaRuntime(PersistentJavaOracleRuntime):
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


def _message(
    subject: str,
    message_id: str,
    body: str,
    *,
    include_from: bool = True,
    include_date: bool = True,
) -> bytes:
    headers: list[str] = []
    if include_from:
        headers.append(f"From: {_FROM}")
    if include_date:
        headers.append(f"Date: {_DATE}")
    headers.extend(
        (
            f"Subject: {subject}",
            f"Message-ID: {message_id}",
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=us-ascii",
        )
    )
    return ("\r\n".join(headers) + "\r\n\r\n" + body).encode("ascii")


def _scenario(
    name: str,
    *,
    subject: str,
    message: bytes,
    expected_score: str,
    expected_rules: tuple[tuple[str, str], ...],
    expected_from_address: str | None = _FROM,
) -> Scenario:
    message_id = f"<{subject}@example.test>"

    def capture(target: RuntimeTarget) -> dict[str, Any]:
        return capture_delivery(
            target,
            mode="data",
            subject=subject,
            message_id=message_id,
            message=message,
            expected_from_address=expected_from_address,
        )

    return Scenario(
        name,
        capture,
        _NORMALIZERS,
        contract={
            "protocol": "smtp",
            "operation": "content-filter-default-composition",
            "message_sha256": hashlib.sha256(message).hexdigest(),
            "message_id": message_id,
            "rules_enabled": [
                "MISSING_HEADERS",
                "SUBJECT_ENCODING_TRICK",
                "EXCESSIVE_RECIPIENTS",
                "SPAM_KEYWORDS",
                "SUSPICIOUS_URL",
                "DANGEROUS_EXTENSION",
                "DOUBLE_EXTENSION",
                "MIME_TYPE_MISMATCH",
            ],
            "rules_disabled": ["RBL_CHECK", "NEW_DOMAIN"],
            "rule_weights": {
                "MISSING_HEADERS": 1.0,
                "SPAM_KEYWORDS": 1.0,
                "SUSPICIOUS_URL": 1.0,
            },
            "expected": {
                "status": "Yes" if expected_rules else "No",
                "score": expected_score,
                "rules": [list(value) for value in expected_rules],
                "storage_folder": "spam",
            },
            "side_effects": ["maildir", "postgres:email_index", "redis:mail-count"],
            "delivery_cardinality": "exactly-once",
        },
    )


_BODY_ID = "<bb-default-body-001@example.test>"
_BODY_MESSAGE = _message(
    "bb-default-body-001",
    _BODY_ID,
    "viagra\r\nhttps://bit.ly/offer\r\n",
)
_HEADER_BODY_ID = "<bb-default-header-body-001@example.test>"
_HEADER_BODY_MESSAGE = _message(
    "bb-default-header-body-001",
    _HEADER_BODY_ID,
    "viagra\r\nhttps://bit.ly/offer\r\n",
    include_from=False,
    include_date=False,
)


SCENARIOS = (
    _scenario(
        "smtp/content-filter/default-body-composition",
        subject="bb-default-body-001",
        message=_BODY_MESSAGE,
        expected_score="9.5",
        expected_rules=(
            ("SPAM_KEYWORDS", "8.0"),
            ("SUSPICIOUS_URL", "1.5"),
        ),
    ),
    _scenario(
        "smtp/content-filter/default-header-body-composition",
        subject="bb-default-header-body-001",
        message=_HEADER_BODY_MESSAGE,
        expected_score="13.0",
        expected_rules=(
            ("MISSING_HEADERS", "3.5"),
            ("SPAM_KEYWORDS", "8.0"),
            ("SUSPICIOUS_URL", "1.5"),
        ),
        expected_from_address=None,
    ),
)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(240)
def test_frozen_java_smtp_content_filter_default_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        repository / "blackbox/golden/java" / _GOLDEN,
        _PROFILE,
        record_java=record,
    )
    with _DefaultFilterJavaRuntime(tmp_path / "java-smtp-content-filter-default") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(240)
def test_rust_candidate_smtp_content_filter_default_matches_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java" / _GOLDEN,
            _PROFILE,
        ).verify_candidate(SCENARIOS, candidate)
