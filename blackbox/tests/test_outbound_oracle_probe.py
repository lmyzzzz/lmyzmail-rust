from __future__ import annotations

import pytest

from lmyzmail_blackbox.outbound_oracle_probe import (
    _normalize_retry_deadlines,
    _normalize_task_ttl,
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
