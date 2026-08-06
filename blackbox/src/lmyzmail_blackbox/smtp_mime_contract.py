from __future__ import annotations

import hashlib
from typing import Any

from .differential import RuntimeTarget, Scenario
from .smtp_contract import capture_delivery

_MIME_BOUNDARY = "bb-mime-boundary-001"
_MIME_FROM = "sender@external.test"
_MIME_TO_JSON = '["qa@example.test","other@example.test"]'
_MIME_NORMALIZERS = (
    "smtp:greeting-skibidi-grammar",
    "smtp:server-hostname",
    "smtp:session-id",
    "maildir:generated-filename",
    "maildir:server-hostname",
    "maildir:received-id",
    "maildir:received-at",
    "postgres:identity-timestamps-and-hostname-derived-size",
)


def _multipart_message(subject: str, message_id: str, *, attachment_first: bool) -> bytes:
    header = (
        f"From: {_MIME_FROM}\r\n"
        "To: qa@example.test, other@example.test\r\n"
        f"Subject: {subject}\r\n"
        f"Message-ID: {message_id}\r\n"
        "MIME-Version: 1.0\r\n"
        f'Content-Type: multipart/mixed; boundary="{_MIME_BOUNDARY}"\r\n'
        "\r\n"
    ).encode("ascii")
    text_part = (
        f"--{_MIME_BOUNDARY}\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: 8bit\r\n"
        "\r\n"
        "MIME body before the attachment.\r\n"
        ".dot-leading-line\r\n"
    ).encode("ascii")
    attachment_part = (
        f"--{_MIME_BOUNDARY}\r\n"
        'Content-Type: application/octet-stream; name="payload.bin"\r\n'
        "Content-Transfer-Encoding: base64\r\n"
        'Content-Disposition: attachment; filename="payload.bin"\r\n'
        "\r\n"
        "AAECAwQFBgcICQ==\r\n"
    ).encode("ascii")
    closing = f"--{_MIME_BOUNDARY}--\r\n".encode("ascii")
    parts = attachment_part + text_part if attachment_first else text_part + attachment_part
    return header + parts + closing


_DATA_MESSAGE_ID = "<bb-mime-data-001@example.test>"
_DATA_SUBJECT = "bb-mime-data-001"
_DATA_MESSAGE = _multipart_message(_DATA_SUBJECT, _DATA_MESSAGE_ID, attachment_first=True)
_BDAT_MESSAGE_ID = "<bb-mime-bdat-001@example.test>"
_BDAT_SUBJECT = "bb-mime-bdat-001"
_BDAT_MESSAGE = _multipart_message(_BDAT_SUBJECT, _BDAT_MESSAGE_ID, attachment_first=True)
_BODY_FIRST_MESSAGE_ID = "<bb-mime-body-first-001@example.test>"
_BODY_FIRST_SUBJECT = "bb-mime-body-first-001"
_BODY_FIRST_MESSAGE = _multipart_message(
    _BODY_FIRST_SUBJECT,
    _BODY_FIRST_MESSAGE_ID,
    attachment_first=False,
)


def _capture_data(target: RuntimeTarget) -> dict[str, Any]:
    return capture_delivery(
        target,
        mode="data",
        subject=_DATA_SUBJECT,
        message_id=_DATA_MESSAGE_ID,
        message=_DATA_MESSAGE,
        expected_from_address=_MIME_FROM,
        expected_to_addresses=_MIME_TO_JSON,
        expected_has_attachments=True,
    )


def _capture_bdat(target: RuntimeTarget) -> dict[str, Any]:
    return capture_delivery(
        target,
        mode="bdat",
        subject=_BDAT_SUBJECT,
        message_id=_BDAT_MESSAGE_ID,
        message=_BDAT_MESSAGE,
        expected_from_address=_MIME_FROM,
        expected_to_addresses=_MIME_TO_JSON,
        expected_has_attachments=True,
    )


def _capture_body_first(target: RuntimeTarget) -> dict[str, Any]:
    return capture_delivery(
        target,
        mode="data",
        subject=_BODY_FIRST_SUBJECT,
        message_id=_BODY_FIRST_MESSAGE_ID,
        message=_BODY_FIRST_MESSAGE,
        expected_from_address=_MIME_FROM,
        expected_to_addresses=_MIME_TO_JSON,
        expected_has_attachments=False,
    )


def _contract(
    mode: str,
    message: bytes,
    message_id: str,
    *,
    attachment_first: bool,
    indexed_has_attachments: bool,
) -> dict[str, Any]:
    return {
        "protocol": "smtp",
        "operation": "inbound-mime-storage",
        "mode": mode,
        "envelope_from": "<>",
        "recipient": "qa@example.test",
        "message_id": message_id,
        "message_sha256": hashlib.sha256(message).hexdigest(),
        "mime": {
            "content_type": "multipart/mixed",
            "boundary": _MIME_BOUNDARY,
            "attachment_first": attachment_first,
            "attachment_filename": "payload.bin",
            "attachment_decoded_sha256": hashlib.sha256(bytes(range(10))).hexdigest(),
        },
        "indexed_from": _MIME_FROM,
        "indexed_to_addresses": ["qa@example.test", "other@example.test"],
        "indexed_has_attachments": indexed_has_attachments,
        "side_effects": ["maildir", "postgres:email_index", "redis:mail-count"],
        "delivery_cardinality": "exactly-once",
        "storage_visibility": "joint-15-second-absolute-deadline",
    }


SMTP_MIME_SCENARIOS = (
    Scenario(
        "smtp/mime/data-multipart-storage",
        _capture_data,
        _MIME_NORMALIZERS + ("smtp:data-dot-unstuff", "mime:base64-attachment-index"),
        _contract(
            "DATA",
            _DATA_MESSAGE,
            _DATA_MESSAGE_ID,
            attachment_first=True,
            indexed_has_attachments=True,
        ),
    ),
    Scenario(
        "smtp/mime/bdat-multipart-storage",
        _capture_bdat,
        _MIME_NORMALIZERS + ("smtp:bdat-chunk-framing", "mime:base64-attachment-index"),
        _contract(
            "BDAT",
            _BDAT_MESSAGE,
            _BDAT_MESSAGE_ID,
            attachment_first=True,
            indexed_has_attachments=True,
        ),
    ),
    Scenario(
        "smtp/mime/data-body-first-indexing",
        _capture_body_first,
        _MIME_NORMALIZERS + ("smtp:data-dot-unstuff", "mime:oracle-first-body-indexing"),
        _contract(
            "DATA",
            _BODY_FIRST_MESSAGE,
            _BODY_FIRST_MESSAGE_ID,
            attachment_first=False,
            indexed_has_attachments=False,
        ),
    ),
)
