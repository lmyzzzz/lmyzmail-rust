from __future__ import annotations

import socket
from pathlib import Path

import httpx
import psycopg
import pytest
import redis

from lmyzmail_blackbox.runtime import API_KEY, QA_ADDRESS, QA_PASSWORD, JavaOracleRuntime


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(120)
def test_managed_oracle_uses_isolated_storage_and_authentication() -> None:
    workspace: Path | None = None
    service_ports: tuple[int, ...] = ()
    with JavaOracleRuntime() as oracle:
        assert oracle.workspace is not None
        assert oracle.ports is not None
        workspace = oracle.workspace
        service_ports = (
            oracle.ports.http,
            oracle.ports.postgres,
            oracle.ports.redis,
        )
        base_url = f"http://127.0.0.1:{oracle.ports.http}"

        with httpx.Client(trust_env=False, timeout=10.0) as client:
            health = client.get(f"{base_url}/api/health")
            login = client.post(
                f"{base_url}/web/login",
                json={"address": QA_ADDRESS, "password": QA_PASSWORD},
            )
            api_status = client.post(
                f"{base_url}/api/status",
                headers={"X-API-Key": API_KEY},
                json={},
            )

        assert health.status_code == 200
        assert health.json()["status"] == "healthy"
        assert login.status_code == 200
        assert login.json()["address"] == QA_ADDRESS
        assert isinstance(login.json()["token"], str)
        assert len(login.json()["token"]) >= 32

        assert api_status.status_code == 200
        assert api_status.json()["status"] == "ok"

        with psycopg.connect(
            host="127.0.0.1",
            port=oracle.ports.postgres,
            user="lmyzmail_test",
            dbname="lmyzmail",
            connect_timeout=5,
        ) as connection:
            table_count = connection.execute(
                "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'"
            ).fetchone()
            assert table_count is not None
            assert table_count[0] > 0

        redis_client = redis.Redis(
            host="127.0.0.1",
            port=oracle.ports.redis,
            socket_connect_timeout=5.0,
            socket_timeout=5.0,
        )
        assert redis_client.ping()
        redis_client.close()

    assert workspace is not None
    assert not workspace.exists()
    for port in service_ports:
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=0.25)
