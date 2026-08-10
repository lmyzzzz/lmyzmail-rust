from __future__ import annotations

import pytest

from lmyzmail_blackbox.outbound_oracle_probe import _normalize_task_ttl


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
