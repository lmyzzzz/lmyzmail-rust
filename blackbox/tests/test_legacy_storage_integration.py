from __future__ import annotations

import time
from pathlib import Path

import pytest
import redis

from lmyzmail_blackbox.legacy_storage import (
    apply_redis_seed,
    load_redis_seed,
    snapshot_redis_seed,
)
from lmyzmail_blackbox.runtime import JavaOracleRuntime


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(120)
def test_legacy_redis_seed_preserves_real_types_values_and_ttls() -> None:
    repository = Path(__file__).resolve().parents[2]
    fixture = load_redis_seed(repository)

    with JavaOracleRuntime() as oracle:
        assert oracle.ports is not None
        client = redis.Redis(
            host="127.0.0.1",
            port=oracle.ports.redis,
            db=fixture.database,
            socket_connect_timeout=5.0,
            socket_timeout=5.0,
        )
        try:
            apply_redis_seed(client, fixture)
            first = snapshot_redis_seed(client, fixture)
            time.sleep(0.25)
            second = snapshot_redis_seed(client, fixture)
        finally:
            client.close()

    assert first == second
    assert {entry["type"] for entry in first} == {"string", "hash", "zset"}
