from __future__ import annotations

import pytest

from lmyzmail_blackbox.outbound_oracle_probe import (
    _normalize_message,
    _normalize_retry_deadlines,
    _normalize_task_ttl,
)


def test_outbound_message_normalization_is_confined_to_the_header_block() -> None:
    body = (
        b"Date: body value must remain\r\n"
        b"Message-ID: <body-id-must-remain>\r\n"
        b"DKIM-Signature: body value must remain\r\n"
    )
    message = (
        b"Date: Tue, 12 Aug 2026 01:02:03 +0000\r\n"
        b"Message-ID: <generated@example.test>\r\n"
        b"DKIM-Signature: v=1; a=rsa-sha256;\r\n\tb=generated\r\n"
        b"Subject: normalization boundary\r\n\r\n"
        + body
    )

    assert _normalize_message(message) == (
        b"Date: <NORMALIZED>\r\n"
        b"Message-ID: <MESSAGE_ID>\r\n"
        b"DKIM-Signature: <NORMALIZED>\r\n"
        b"Subject: normalization boundary\r\n\r\n"
        + body
    )


@pytest.mark.parametrize("separator", [b"\r\n\r\n", b"\n\n", b"\r\r"])
def test_outbound_message_normalization_preserves_the_first_body_separator(
    separator: bytes,
) -> None:
    body = b"Message-ID: <body-id>"
    assert _normalize_message(b"Message-ID: <header-id>" + separator + body) == (
        b"Message-ID: <MESSAGE_ID>" + separator + body
    )


@pytest.mark.parametrize("ttl_seconds", [604_770, 604_799, 604_800])
def test_outbound_task_ttl_normalizes_only_the_bounded_observation_window(
    ttl_seconds: int,
) -> None:
    assert _normalize_task_ttl(ttl_seconds) == 604_800


@pytest.mark.parametrize("ttl_seconds", [-2, -1, 0, 604_769, 604_801])
def test_outbound_task_ttl_rejects_missing_unbounded_or_invalid_expiry(
    ttl_seconds: int,
) -> None:
    with pytest.raises(AssertionError, match="outside the seven-day observation window"):
        _normalize_task_ttl(ttl_seconds)


def test_outbound_retry_deadlines_normalize_only_bounded_wall_clock_jitter() -> None:
    assert (
        _normalize_retry_deadlines(
            1_000.0,
            30,
            {"redis_task": 1_030.1, "redis_zset": 1_030.2},
        )
        == 30
    )


@pytest.mark.parametrize(
    "deadlines, match",
    [
        ({"redis_task": 1_030.0}, "sources are incomplete"),
        (
            {"redis_task": 1_040.0, "redis_zset": 1_040.1},
            "outside the observation window",
        ),
        (
            {"redis_task": 1_029.0, "redis_zset": 1_031.0},
            "sources differ",
        ),
    ],
)
def test_outbound_retry_deadlines_reject_missing_unbounded_or_divergent_sources(
    deadlines: dict[str, float],
    match: str,
) -> None:
    with pytest.raises(AssertionError, match=match):
        _normalize_retry_deadlines(1_000.0, 30, deadlines)
