from __future__ import annotations

from lmyzmail_blackbox.smtp_mime_contract import SMTP_MIME_SCENARIOS


def test_smtp_mime_profile_binds_data_bdat_and_attachment_indexing() -> None:
    assert [scenario.name for scenario in SMTP_MIME_SCENARIOS] == [
        "smtp/mime/data-multipart-storage",
        "smtp/mime/bdat-multipart-storage",
        "smtp/mime/data-body-first-indexing",
    ]

    for scenario in SMTP_MIME_SCENARIOS[:2]:
        assert scenario.contract is not None
        assert scenario.contract["operation"] == "inbound-mime-storage"
        assert scenario.contract["mime"]["content_type"] == "multipart/mixed"
        assert scenario.contract["mime"]["attachment_filename"] == "payload.bin"
        assert scenario.contract["indexed_has_attachments"] is True
        assert scenario.contract["delivery_cardinality"] == "exactly-once"

    body_first = SMTP_MIME_SCENARIOS[2].contract
    assert body_first is not None
    assert body_first["mime"]["attachment_first"] is False
    assert body_first["indexed_has_attachments"] is False
