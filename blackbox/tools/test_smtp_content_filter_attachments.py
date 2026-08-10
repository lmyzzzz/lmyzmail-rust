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

_GOLDEN = "managed-smtp-content-filter-attachments-v9"
_PROFILE = "managed-smtp-content-filter-attachments"
_FROM = "sender@external.test"
_DATE = "Tue, 5 Aug 2025 12:00:00 GMT"
_BOUNDARY = "bb-attachment-boundary"
_RULE_OVERRIDES = (
    "--botmail.contentfilter.rules.RBL_CHECK.enabled=false",
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
    "--botmail.contentfilter.rules.DANGEROUS_EXTENSION.enabled=true",
    "--botmail.contentfilter.rules.DOUBLE_EXTENSION.enabled=true",
    "--botmail.contentfilter.rules.MIME_TYPE_MISMATCH.enabled=true",
    "--botmail.contentfilter.attachment.enabled=true",
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


class _AttachmentFilterJavaRuntime(PersistentJavaOracleRuntime):
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
            *_RULE_OVERRIDES,
        )
    )


def _attachment_part(
    mime_type: str,
    content_disposition: str,
    *,
    content_type_name: str | None = None,
    boundary: str = _BOUNDARY,
) -> str:
    content_type = mime_type
    if content_type_name is not None:
        content_type += f"; name=\"{content_type_name}\""
    return (
        f"--{boundary}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Disposition: {content_disposition}\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        "YXR0YWNobWVudAo=\r\n"
    )


def _message(
    subject: str,
    message_id: str,
    attachment_parts: tuple[str, ...],
    *,
    boundary: str = _BOUNDARY,
    epilogue: str = "",
) -> bytes:
    headers = (
        f"From: {_FROM}\r\n"
        f"Date: {_DATE}\r\n"
        f"Subject: {subject}\r\n"
        f"Message-ID: {message_id}\r\n"
        "MIME-Version: 1.0\r\n"
        f"Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n"
        "\r\n"
    )
    text_part = (
        f"--{boundary}\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "\r\n"
        "Attachment filter body.\r\n"
    )
    closing = f"--{boundary}--\r\n"
    return (headers + text_part + "".join(attachment_parts) + closing + epilogue).encode(
        "ascii"
    )


_SAFE_ID = "<bb-attachment-safe-001@example.test>"
_SAFE_MESSAGE = _message(
    "bb-attachment-safe-001",
    _SAFE_ID,
    (_attachment_part("application/pdf", 'attachment; filename="report.pdf"'),),
)
_DANGEROUS_ID = "<bb-attachment-dangerous-001@example.test>"
_DANGEROUS_MESSAGE = _message(
    "bb-attachment-dangerous-001",
    _DANGEROUS_ID,
    (
        _attachment_part(
            "application/octet-stream",
            'attachment; filename="payload.exe"',
        ),
    ),
)
_DOUBLE_ID = "<bb-attachment-double-001@example.test>"
_DOUBLE_MESSAGE = _message(
    "bb-attachment-double-001",
    _DOUBLE_ID,
    (
        _attachment_part(
            "application/pdf",
            'attachment; filename="invoice.pdf.exe"',
        ),
    ),
)
_RFC2231_ID = "<bb-attachment-rfc2231-001@example.test>"
_RFC2231_MESSAGE = _message(
    "bb-attachment-rfc2231-001",
    _RFC2231_ID,
    (
        _attachment_part(
            "application/octet-stream",
            "attachment; filename*=utf-8''payload%2Eps1",
        ),
    ),
)
_MULTIPLE_ID = "<bb-attachment-multiple-001@example.test>"
_MULTIPLE_MESSAGE = _message(
    "bb-attachment-multiple-001",
    _MULTIPLE_ID,
    (
        _attachment_part(
            "application/octet-stream",
            'attachment; filename="first.exe"',
        ),
        _attachment_part(
            "application/octet-stream",
            'attachment; filename="second.js"',
        ),
    ),
)
_UNICODE_ID = "<bb-attachment-unicode-001@example.test>"
_UNICODE_MESSAGE = _message(
    "bb-attachment-unicode-001",
    _UNICODE_ID,
    (
        _attachment_part(
            "application/pdf",
            "attachment; filename*=utf-8''invoice.%C3%A9.exe",
        ),
    ),
)
_CONTINUATION_ID = "<bb-attachment-continuation-001@example.test>"
_CONTINUATION_MESSAGE = _message(
    "bb-attachment-continuation-001",
    _CONTINUATION_ID,
    (
        _attachment_part(
            "application/pdf",
            "attachment; filename*0=invoice.pdf.; filename*1=exe",
        ),
    ),
)
_TYPE_NAME_ID = "<bb-attachment-type-name-001@example.test>"
_TYPE_NAME_MESSAGE = _message(
    "bb-attachment-type-name-001",
    _TYPE_NAME_ID,
    (
        _attachment_part(
            "application/octet-stream",
            "attachment",
            content_type_name="payload.exe",
        ),
    ),
)
_FOLDED_ID = "<bb-attachment-folded-001@example.test>"
_FOLDED_MESSAGE = _message(
    "bb-attachment-folded-001",
    _FOLDED_ID,
    (
        _attachment_part(
            "application/octet-stream",
            'attachment;\r\n filename="payload.exe"',
        ),
    ),
)
_CLOSED_BOUNDARY_EPILOGUE_ID = "<bb-attachment-closed-boundary-epilogue-001@example.test>"
_CLOSED_BOUNDARY_EPILOGUE_MESSAGE = _message(
    "bb-attachment-closed-boundary-epilogue-001",
    _CLOSED_BOUNDARY_EPILOGUE_ID,
    (),
    epilogue=(
        "epilogue\r\n"
        f"--{_BOUNDARY}\r\n"
        "Content-Type: application/pdf\r\n"
        'Content-Disposition: attachment; filename="payload.exe"\r\n'
        "\r\n"
        "not-a-mime-part\r\n"
    ),
)
_QUOTED_SPACE_BOUNDARY = " bb-quoted-space"
_QUOTED_SPACE_BOUNDARY_ID = "<bb-attachment-quoted-space-boundary-001@example.test>"
_QUOTED_SPACE_BOUNDARY_MESSAGE = _message(
    "bb-attachment-quoted-space-boundary-001",
    _QUOTED_SPACE_BOUNDARY_ID,
    (
        _attachment_part(
            "application/octet-stream",
            'attachment; filename="payload.exe"',
            boundary=_QUOTED_SPACE_BOUNDARY,
        ),
    ),
    boundary=_QUOTED_SPACE_BOUNDARY,
)
_MESSAGE_RFC822_ID = "<bb-attachment-message-rfc822-001@example.test>"
_MESSAGE_RFC822_INNER_BOUNDARY = "bb-inner-attachment-boundary"
_MESSAGE_RFC822_MESSAGE = _message(
    "bb-attachment-message-rfc822-001",
    _MESSAGE_RFC822_ID,
    (
        (
            f"--{_BOUNDARY}\r\n"
            "Content-Type: message/rfc822\r\n"
            "Content-Disposition: inline\r\n"
            "\r\n"
            "From: nested@external.test\r\n"
            "Date: Tue, 5 Aug 2025 12:00:00 GMT\r\n"
            "Subject: nested attachment\r\n"
            "Message-ID: <bb-nested-attachment@example.test>\r\n"
            "MIME-Version: 1.0\r\n"
            f'Content-Type: multipart/mixed; boundary="{_MESSAGE_RFC822_INNER_BOUNDARY}"\r\n'
            "\r\n"
            f"--{_MESSAGE_RFC822_INNER_BOUNDARY}\r\n"
            "Content-Type: text/plain; charset=us-ascii\r\n"
            "\r\n"
            "Nested body.\r\n"
            f"--{_MESSAGE_RFC822_INNER_BOUNDARY}\r\n"
            "Content-Type: application/octet-stream\r\n"
            'Content-Disposition: attachment; filename="payload.exe"\r\n'
            "\r\n"
            "nested-payload\r\n"
            f"--{_MESSAGE_RFC822_INNER_BOUNDARY}--\r\n"
        ),
    ),
)
_NON_MULTIPART_BOUNDARY_ID = "<bb-attachment-non-multipart-boundary-001@example.test>"
_NON_MULTIPART_BOUNDARY = "bb-opaque-boundary"
_NON_MULTIPART_BOUNDARY_MESSAGE = (
    f"From: {_FROM}\r\n"
    f"Date: {_DATE}\r\n"
    "Subject: bb-attachment-non-multipart-boundary-001\r\n"
    f"Message-ID: {_NON_MULTIPART_BOUNDARY_ID}\r\n"
    "MIME-Version: 1.0\r\n"
    f'Content-Type: text/plain; boundary="{_NON_MULTIPART_BOUNDARY}"\r\n'
    "\r\n"
    "Opaque text body.\r\n"
    f"--{_NON_MULTIPART_BOUNDARY}\r\n"
    "Content-Type: application/octet-stream\r\n"
    'Content-Disposition: attachment; filename="payload.exe"\r\n'
    "\r\n"
    "not-a-mime-part\r\n"
    f"--{_NON_MULTIPART_BOUNDARY}--\r\n"
).encode("ascii")


def _capture(
    target: RuntimeTarget,
    *,
    subject: str,
    message_id: str,
    message: bytes,
) -> dict[str, Any]:
    return capture_delivery(
        target,
        mode="data",
        subject=subject,
        message_id=message_id,
        message=message,
        expected_from_address=_FROM,
        expected_has_attachments=False,
    )


def _scenario(
    name: str,
    *,
    subject: str,
    message_id: str,
    message: bytes,
    expected_score: str,
    expected_rules: tuple[tuple[str, str], ...],
) -> Scenario:
    def capture(target: RuntimeTarget) -> dict[str, Any]:
        return _capture(
            target,
            subject=subject,
            message_id=message_id,
            message=message,
        )

    contract = {
        "protocol": "smtp",
        "operation": "content-filter-attachment-phase",
        "message_sha256": hashlib.sha256(message).hexdigest(),
        "message_id": message_id,
        "rules_enabled": [
            "DANGEROUS_EXTENSION",
            "DOUBLE_EXTENSION",
            "MIME_TYPE_MISMATCH",
        ],
        "expected": {
            "score": expected_score,
            "rules": [list(value) for value in expected_rules],
            "storage_folder": "spam",
            "has_attachments": False,
            "has_attachments_note": "Java indexes only the first MIME part",
        },
        "side_effects": ["maildir", "postgres:email_index", "redis:mail-count"],
        "delivery_cardinality": "exactly-once",
    }
    return Scenario(name, capture, _NORMALIZERS, contract)


SCENARIOS = (
    _scenario(
        "smtp/content-filter/attachment-safe-pdf",
        subject="bb-attachment-safe-001",
        message_id=_SAFE_ID,
        message=_SAFE_MESSAGE,
        expected_score="0.0",
        expected_rules=(),
    ),
    _scenario(
        "smtp/content-filter/attachment-dangerous-extension",
        subject="bb-attachment-dangerous-001",
        message_id=_DANGEROUS_ID,
        message=_DANGEROUS_MESSAGE,
        expected_score="5.0",
        expected_rules=(("DANGEROUS_EXTENSION", "5.0"),),
    ),
    _scenario(
        "smtp/content-filter/attachment-double-mime-mismatch",
        subject="bb-attachment-double-001",
        message_id=_DOUBLE_ID,
        message=_DOUBLE_MESSAGE,
        expected_score="13.5",
        expected_rules=(
            ("DANGEROUS_EXTENSION", "5.0"),
            ("DOUBLE_EXTENSION", "4.0"),
            ("MIME_TYPE_MISMATCH", "4.5"),
        ),
    ),
    _scenario(
        "smtp/content-filter/attachment-rfc2231-filename",
        subject="bb-attachment-rfc2231-001",
        message_id=_RFC2231_ID,
        message=_RFC2231_MESSAGE,
        expected_score="5.0",
        expected_rules=(("DANGEROUS_EXTENSION", "5.0"),),
    ),
    _scenario(
        "smtp/content-filter/attachment-multiple-dangerous",
        subject="bb-attachment-multiple-001",
        message_id=_MULTIPLE_ID,
        message=_MULTIPLE_MESSAGE,
        expected_score="5.5",
        expected_rules=(("DANGEROUS_EXTENSION", "5.5"),),
    ),
    _scenario(
        "smtp/content-filter/attachment-unicode-extension",
        subject="bb-attachment-unicode-001",
        message_id=_UNICODE_ID,
        message=_UNICODE_MESSAGE,
        expected_score="9.5",
        expected_rules=(
            ("DANGEROUS_EXTENSION", "5.0"),
            ("MIME_TYPE_MISMATCH", "4.5"),
        ),
    ),
    _scenario(
        "smtp/content-filter/attachment-rfc2231-continuation",
        subject="bb-attachment-continuation-001",
        message_id=_CONTINUATION_ID,
        message=_CONTINUATION_MESSAGE,
        expected_score="0.0",
        expected_rules=(),
    ),
    _scenario(
        "smtp/content-filter/attachment-content-type-name",
        subject="bb-attachment-type-name-001",
        message_id=_TYPE_NAME_ID,
        message=_TYPE_NAME_MESSAGE,
        expected_score="5.0",
        expected_rules=(("DANGEROUS_EXTENSION", "5.0"),),
    ),
    _scenario(
        "smtp/content-filter/attachment-folded-filename",
        subject="bb-attachment-folded-001",
        message_id=_FOLDED_ID,
        message=_FOLDED_MESSAGE,
        expected_score="5.0",
        expected_rules=(("DANGEROUS_EXTENSION", "5.0"),),
    ),
    _scenario(
        "smtp/content-filter/attachment-closed-boundary-epilogue",
        subject="bb-attachment-closed-boundary-epilogue-001",
        message_id=_CLOSED_BOUNDARY_EPILOGUE_ID,
        message=_CLOSED_BOUNDARY_EPILOGUE_MESSAGE,
        expected_score="0.0",
        expected_rules=(),
    ),
    _scenario(
        "smtp/content-filter/attachment-quoted-space-boundary",
        subject="bb-attachment-quoted-space-boundary-001",
        message_id=_QUOTED_SPACE_BOUNDARY_ID,
        message=_QUOTED_SPACE_BOUNDARY_MESSAGE,
        expected_score="5.0",
        expected_rules=(("DANGEROUS_EXTENSION", "5.0"),),
    ),
    _scenario(
        "smtp/content-filter/attachment-message-rfc822",
        subject="bb-attachment-message-rfc822-001",
        message_id=_MESSAGE_RFC822_ID,
        message=_MESSAGE_RFC822_MESSAGE,
        expected_score="5.0",
        expected_rules=(("DANGEROUS_EXTENSION", "5.0"),),
    ),
    _scenario(
        "smtp/content-filter/attachment-non-multipart-boundary",
        subject="bb-attachment-non-multipart-boundary-001",
        message_id=_NON_MULTIPART_BOUNDARY_ID,
        message=_NON_MULTIPART_BOUNDARY_MESSAGE,
        expected_score="0.0",
        expected_rules=(),
    ),
)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(360)
def test_frozen_java_smtp_content_filter_attachment_golden(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    record = os.environ.get("LMYZMAIL_RECORD_JAVA_GOLDEN") == "1"
    runner = DifferentialRunner(
        repository,
        repository / "blackbox/golden/java" / _GOLDEN,
        _PROFILE,
        record_java=record,
    )
    with _AttachmentFilterJavaRuntime(tmp_path / "java-smtp-content-filter-attachments") as oracle:
        target = _OracleTarget(oracle)
        if record:
            runner.record_from_java(SCENARIOS, target)
        else:
            runner.verify_java(SCENARIOS, target)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(360)
def test_rust_candidate_smtp_content_filter_attachments_match_golden() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(
            repository,
            repository / "blackbox/golden/java" / _GOLDEN,
            _PROFILE,
        ).verify_candidate(SCENARIOS, candidate)
