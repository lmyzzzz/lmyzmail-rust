from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

import pytest

from lmyzmail_blackbox.smtp_contract import (
    _assert_path_chain_without_symlinks,
    _check_maildir_delta,
    _logical_maildir_path,
    _maildir_files,
    _parse_java_rfc1123,
    _parse_maildir_filename_time,
)

_ENCODED_QA = "7161406578616D706C652E74657374"


def test_java_rfc1123_parser_freezes_oracle_wire_format() -> None:
    assert _parse_java_rfc1123(b"Tue, 5 Aug 2025 12:34:56 GMT") == datetime(
        2025,
        8,
        5,
        12,
        34,
        56,
        tzinfo=UTC,
    )

    invalid = (
        b"Tue, 05 Aug 2025 12:34:56 GMT",
        b"Tue, 5 Aug 2025 12:34:56 UTC",
        b"Tue, 5 Aug 2025 12:34:56 +0000",
        b"Mon, 5 Aug 2025 12:34:56 GMT",
        b"Tue, 31 Feb 2025 12:34:56 GMT",
    )
    for value in invalid:
        with pytest.raises(AssertionError, match="SMTP contract violation"):
            _parse_java_rfc1123(value)


def test_maildir_filename_parser_extracts_strict_utc_timestamp() -> None:
    assert _parse_maildir_filename_time("20250805123456.789-123456789-7.eml") == datetime(
        2025, 8, 5, 12, 34, 56, 789000, tzinfo=UTC
    )

    invalid = (
        "20250805123456-123-7.eml",
        "20250805123456.789-123-7.tmp",
        "20250230123456.789-123-7.eml",
        "20250805123456.789--7.eml",
        "20250805123456.789-123-7-\u90ae\u4ef6.eml",
    )
    for value in invalid:
        with pytest.raises(AssertionError, match="SMTP contract violation"):
            _parse_maildir_filename_time(value)


def test_maildir_delta_requires_one_file_without_orphans_or_temp(tmp_path: Path) -> None:
    workspace = tmp_path
    folder = workspace / "maildir" / "qa@example.test" / "spam" / "1"
    folder.mkdir(parents=True)
    existing = folder / "existing.eml"
    existing.write_bytes(b"existing")
    before = _maildir_files(workspace)

    delivered = folder / "delivered.eml"
    delivered.write_bytes(b"delivered")
    after = _maildir_files(workspace)
    expected = "qa@example.test/spam/1/delivered.eml"
    _check_maildir_delta(before, after, expected)

    existing.write_bytes(b"tampered")
    with pytest.raises(AssertionError, match="pre-existing Maildir files changed"):
        _check_maildir_delta(before, _maildir_files(workspace), expected)
    existing.write_bytes(b"existing")

    orphan = folder / "orphan.eml"
    orphan.write_bytes(b"orphan")
    with pytest.raises(AssertionError, match="SMTP contract violation"):
        _check_maildir_delta(before, _maildir_files(workspace), expected)

    orphan.unlink()
    temp = workspace / "maildir" / "temp" / "delivery.tmp"
    temp.parent.mkdir()
    temp.write_bytes(b"residue")
    with pytest.raises(AssertionError, match="residual Maildir temp"):
        _check_maildir_delta(before, _maildir_files(workspace), expected)


def test_maildir_walk_and_path_chain_reject_symlinks(tmp_path: Path) -> None:
    workspace = tmp_path
    maildir = workspace / "maildir"
    outside = workspace / "outside"
    maildir.mkdir()
    outside.mkdir()
    link = maildir / "linked"
    link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(AssertionError, match="SMTP contract violation"):
        _maildir_files(workspace)
    with pytest.raises(AssertionError, match="SMTP contract violation"):
        _assert_path_chain_without_symlinks(workspace, link / "message.eml")


@pytest.mark.parametrize(
    ("encoded", "expected"),
    (
        (
            f"v2/c-{_ENCODED_QA}/z-0000000F/spam/1/message.eml",
            "qa@example.test/spam/1/message.eml",
        ),
        (
            "v2/c-71614065/c-78616D706C652E74657374/"
            "z-0000000F/spam/1/message.eml",
            "qa@example.test/spam/1/message.eml",
        ),
    ),
)
def test_logical_maildir_path_decodes_valid_v2_paths(encoded: str, expected: str) -> None:
    assert _logical_maildir_path(PurePosixPath(encoded)) == expected


@pytest.mark.parametrize(
    "encoded",
    (
        f"v2/c-{_ENCODED_QA}/z-00000010/spam/1/message.eml",
        "v2/c-7161406578616d706C652E74657374/z-0000000F/spam/1/message.eml",
        f"v2/c-{_ENCODED_QA}/z-0000000f/spam/1/message.eml",
        "v2/c-FF/z-00000001/spam/1/message.eml",
    ),
)
def test_logical_maildir_path_preserves_malformed_v2_paths(encoded: str) -> None:
    assert _logical_maildir_path(PurePosixPath(encoded)) == encoded


def test_maildir_walk_rejects_duplicate_logical_v2_path(tmp_path: Path) -> None:
    relative = Path("spam", "1", "message.eml")
    legacy = tmp_path / "maildir" / "qa@example.test" / relative
    encoded = (
        tmp_path
        / "maildir"
        / "v2"
        / f"c-{_ENCODED_QA}"
        / "z-0000000F"
        / relative
    )
    legacy.parent.mkdir(parents=True)
    encoded.parent.mkdir(parents=True)
    legacy.write_bytes(b"legacy")
    encoded.write_bytes(b"encoded")

    with pytest.raises(AssertionError, match="duplicate logical Maildir path"):
        _maildir_files(tmp_path)
