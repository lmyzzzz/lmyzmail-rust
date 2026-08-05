from __future__ import annotations

import contextlib
import hashlib
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any, cast

import httpx
import psycopg
import pytest
import redis

import lmyzmail_blackbox.persistent_runtime as persistent_runtime_module
from lmyzmail_blackbox.errors import HarnessError
from lmyzmail_blackbox.legacy_storage import (
    load_maildir_fixture,
    load_redis_seed,
    snapshot_redis_seed,
)
from lmyzmail_blackbox.persistent_runtime import (
    LEGACY_SESSION_TOKEN,
    PersistentJavaOracleRuntime,
    PersistentRuntimeState,
)
from lmyzmail_blackbox.processes import (
    ManagedProcess,
)
from lmyzmail_blackbox.processes import (
    kill_managed_processes as real_kill_managed_processes,
)

_EXPECTED_TABLE_ROWS = {
    "contact": 1,
    "email_index": 3,
    "email_label": 1,
    "email_label_assignment": 1,
    "inbound_dmarc_log": 1,
    "mailbox": 1,
    "outbound_mail_queue": 1,
    "outbound_tls_log": 1,
    "skibidi_cringe_ip": 1,
    "skibidi_cringe_ip_activity": 1,
    "starred_email": 1,
    "user_preference": 1,
    "user_session": 1,
}


def _assert_postgres(runtime: PersistentJavaOracleRuntime) -> None:
    assert runtime.ports is not None
    with psycopg.connect(
        host="127.0.0.1",
        port=runtime.ports.postgres,
        user="lmyzmail_test",
        dbname="lmyzmail",
        connect_timeout=5,
    ) as connection:
        table_rows = connection.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'public' ORDER BY table_name"
        ).fetchall()
        assert {cast(str, row[0]) for row in table_rows} == set(_EXPECTED_TABLE_ROWS)

        for table, expected_rows in _EXPECTED_TABLE_ROWS.items():
            query = psycopg.sql.SQL("SELECT count(*) FROM {}").format(psycopg.sql.Identifier(table))
            result = connection.execute(query).fetchone()
            assert result is not None
            assert result[0] == expected_rows

        settings: dict[str, str] = dict(
            connection.execute(
                "SELECT name, setting FROM pg_settings "
                "WHERE name IN ('data_checksums', 'fsync', 'full_page_writes', "
                "'synchronous_commit')"
            ).fetchall()
        )
        assert settings == {
            "data_checksums": "on",
            "fsync": "on",
            "full_page_writes": "on",
            "synchronous_commit": "on",
        }


def _assert_maildir(repository: Path, workspace: Path) -> None:
    fixture = load_maildir_fixture(repository)
    actual_files: set[str] = set()
    root = workspace / "maildir"
    for path in root.rglob("*"):
        assert not path.is_symlink()
        if path.is_file():
            actual_files.add(path.relative_to(root).as_posix())
    assert actual_files == {entry.path for entry in fixture.files}

    for entry in fixture.files:
        path = root.joinpath(*PurePosixPath(entry.path).parts)
        value = path.read_bytes()
        assert len(value) == entry.size
        assert hashlib.sha256(value).hexdigest() == entry.sha256


def _assert_redis(repository: Path, runtime: PersistentJavaOracleRuntime) -> None:
    assert runtime.ports is not None
    fixture = load_redis_seed(repository)
    client = redis.Redis(
        host="127.0.0.1",
        port=runtime.ports.redis,
        db=fixture.database,
        socket_connect_timeout=5.0,
        socket_timeout=5.0,
    )
    try:
        observations = snapshot_redis_seed(
            client,
            fixture,
            ttl_drift_ms=180_000,
        )
        assert len(observations) == len(fixture.keys)
    finally:
        client.close()


def _assert_http_takeover(repository: Path, runtime: PersistentJavaOracleRuntime) -> None:
    assert runtime.ports is not None
    base_url = f"http://127.0.0.1:{runtime.ports.http}"
    headers = {"X-Session-Token": LEGACY_SESSION_TOKEN}
    fixture = load_maildir_fixture(repository)
    fixture_by_name = {
        PurePosixPath(entry.path).name: repository
        / "blackbox/fixtures/legacy/maildir"
        / Path(*PurePosixPath(entry.path).parts)
        for entry in fixture.files
    }

    with httpx.Client(trust_env=False, timeout=10.0) as client:
        response = client.get(
            f"{base_url}/web/mail/list/inbox?page=0&size=50",
            headers=headers,
        )
        assert response.status_code == 200
        payload = cast(dict[str, Any], response.json())
        content = cast(list[dict[str, Any]], payload["content"])
        assert payload["totalElements"] == 3
        assert {cast(str, item["fileName"]) for item in content} == set(fixture_by_name)

        for file_name, expected_path in fixture_by_name.items():
            raw = client.get(
                f"{base_url}/web/mail/raw/inbox/{file_name}",
                headers=headers,
            )
            assert raw.status_code == 200
            assert raw.content == expected_path.read_bytes()


def _assert_runtime_state(repository: Path, runtime: PersistentJavaOracleRuntime) -> None:
    assert runtime.workspace is not None
    assert stat.S_IMODE(runtime.workspace.stat().st_mode) == 0o700
    assert (runtime.workspace / "lmyzmail-runtime-attestation.json").is_file()
    assert (runtime.workspace / "redis-data/dump.rdb").is_file()
    append_manifest = runtime.workspace / "redis-data/appendonlydir/appendonly.aof.manifest"
    if runtime.redis_mode == "both":
        assert append_manifest.is_file()
    else:
        assert not append_manifest.exists()
    _assert_postgres(runtime)
    _assert_redis(repository, runtime)
    _assert_maildir(repository, runtime.workspace)
    _assert_http_takeover(repository, runtime)


def _assert_state(
    runtime: PersistentJavaOracleRuntime,
    expected: PersistentRuntimeState,
) -> None:
    assert runtime.state is expected


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(240)
def test_persistent_oracle_bootstrap_and_restarts_preserve_legacy_state(
    tmp_path: Path,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    workspace = tmp_path / "persistent-oracle"
    runtime = PersistentJavaOracleRuntime(workspace)

    try:
        runtime.start()
        _assert_state(runtime, PersistentRuntimeState.RUNNING)
        _assert_runtime_state(repository, runtime)

        runtime.restart_application()
        _assert_state(runtime, PersistentRuntimeState.RUNNING)
        _assert_runtime_state(repository, runtime)

        runtime.shutdown()
        _assert_state(runtime, PersistentRuntimeState.STOPPED)
        assert workspace.is_dir()

        runtime.recover()
        _assert_state(runtime, PersistentRuntimeState.RUNNING)
        _assert_runtime_state(repository, runtime)
    finally:
        runtime.close()

    _assert_state(runtime, PersistentRuntimeState.CLOSED)
    assert workspace.is_dir()

    reopened = PersistentJavaOracleRuntime(workspace)
    assert reopened.generation == 3
    try:
        reopened.recover()
        assert reopened.generation == 4
        _assert_runtime_state(repository, reopened)
    finally:
        reopened.close()


def _redis_expiry_ms(client: redis.Redis, key: str) -> int:
    seconds, microseconds = cast(tuple[int, int], client.time())
    ttl_ms = cast(int, client.pttl(key))
    assert ttl_ms > 0
    return seconds * 1000 + microseconds // 1000 + ttl_ms


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_persistent_oracle_crash_recovery_rolls_back_and_replays_aof(
    tmp_path: Path,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    runtime = PersistentJavaOracleRuntime(tmp_path / "crash-oracle")
    postgres_connection: psycopg.Connection[tuple[Any, ...]] | None = None
    redis_client: redis.Redis | None = None

    try:
        runtime.start()
        assert runtime.ports is not None
        postgres_connection = psycopg.connect(
            host="127.0.0.1",
            port=runtime.ports.postgres,
            user="lmyzmail_test",
            dbname="lmyzmail",
            connect_timeout=5,
        )
        postgres_connection.execute(
            "UPDATE user_preference SET preferences_json = %s WHERE id = 1101",
            ('{"uncommitted":true}',),
        )

        redis_client = redis.Redis(
            host="127.0.0.1",
            port=runtime.ports.redis,
            socket_connect_timeout=5.0,
            socket_timeout=5.0,
        )
        assert redis_client.set("lmyzmail:blackbox:ttl-canary", b"durable", px=300_000)
        expected_expiry = _redis_expiry_ms(redis_client, "lmyzmail:blackbox:ttl-canary")

        executed = redis_client.pipeline(transaction=True)
        executed.set("lmyzmail:blackbox:multi:a", b"a")
        executed.set("lmyzmail:blackbox:multi:b", b"b")
        assert executed.execute() == [True, True]

        unexecuted = redis_client.pipeline(transaction=True)
        unexecuted.set("lmyzmail:blackbox:multi:not-executed", b"absent")

        runtime.crash()
        _assert_state(runtime, PersistentRuntimeState.CRASHED)
        with contextlib.suppress(psycopg.Error):
            postgres_connection.close()
        postgres_connection = None
        redis_client.close()
        redis_client = None

        runtime.recover()
        _assert_state(runtime, PersistentRuntimeState.RUNNING)
        assert runtime.ports is not None
        with psycopg.connect(
            host="127.0.0.1",
            port=runtime.ports.postgres,
            user="lmyzmail_test",
            dbname="lmyzmail",
            connect_timeout=5,
        ) as connection:
            result = connection.execute(
                "SELECT preferences_json FROM user_preference WHERE id = 1101"
            ).fetchone()
            assert result == ('{"itemsPerPage":25,"legacyFixture":true,"theme":"dark"}',)

        recovered_redis = redis.Redis(
            host="127.0.0.1",
            port=runtime.ports.redis,
            socket_connect_timeout=5.0,
            socket_timeout=5.0,
        )
        try:
            assert recovered_redis.get("lmyzmail:blackbox:ttl-canary") == b"durable"
            assert (
                abs(
                    _redis_expiry_ms(recovered_redis, "lmyzmail:blackbox:ttl-canary")
                    - expected_expiry
                )
                <= 2_000
            )
            assert recovered_redis.mget(
                "lmyzmail:blackbox:multi:a", "lmyzmail:blackbox:multi:b"
            ) == [b"a", b"b"]
            assert not recovered_redis.exists("lmyzmail:blackbox:multi:not-executed")
        finally:
            recovered_redis.close()
        _assert_runtime_state(repository, runtime)
    finally:
        if postgres_connection is not None:
            with contextlib.suppress(psycopg.Error):
                postgres_connection.close()
        if redis_client is not None:
            redis_client.close()
        runtime.close()


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_persistent_oracle_rdb_only_recovery_is_independent(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    runtime = PersistentJavaOracleRuntime(
        tmp_path / "rdb-oracle",
        redis_mode="rdb-only",
    )
    try:
        runtime.start()
        assert runtime.ports is not None
        client = redis.Redis(
            host="127.0.0.1",
            port=runtime.ports.redis,
            socket_connect_timeout=5.0,
            socket_timeout=5.0,
        )
        try:
            assert client.set("lmyzmail:blackbox:rdb-canary", b"rdb")
            assert client.save()
        finally:
            client.close()

        runtime.crash()
        runtime.recover()
        assert runtime.ports is not None
        recovered = redis.Redis(
            host="127.0.0.1",
            port=runtime.ports.redis,
            socket_connect_timeout=5.0,
            socket_timeout=5.0,
        )
        try:
            assert recovered.get("lmyzmail:blackbox:rdb-canary") == b"rdb"
        finally:
            recovered.close()
        _assert_runtime_state(repository, runtime)
    finally:
        runtime.close()


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(150)
def test_persistent_oracle_rejects_missing_aof_on_recovery(tmp_path: Path) -> None:
    runtime = PersistentJavaOracleRuntime(tmp_path / "missing-aof-oracle")
    try:
        runtime.start()
        runtime.shutdown()
        manifest = runtime.persistent_workspace / "redis-data/appendonlydir/appendonly.aof.manifest"
        manifest.rename(manifest.with_suffix(".missing"))

        with pytest.raises(HarnessError, match="AOF or RDB persistence is missing"):
            runtime.recover()
        _assert_state(runtime, PersistentRuntimeState.CRASHED)
    finally:
        runtime.close()


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(150)
def test_persistent_oracle_rejects_schema_drift_before_java_start(
    tmp_path: Path,
) -> None:
    runtime = PersistentJavaOracleRuntime(tmp_path / "schema-drift-oracle")
    try:
        runtime.start()
        assert runtime.ports is not None
        with psycopg.connect(
            host="127.0.0.1",
            port=runtime.ports.postgres,
            user="lmyzmail_test",
            dbname="lmyzmail",
            connect_timeout=5,
        ) as connection:
            connection.execute('ALTER TABLE "contact" DROP COLUMN "notes"')
        runtime.shutdown()

        with pytest.raises(HarnessError, match="schema drifted"):
            runtime.recover()
        _assert_state(runtime, PersistentRuntimeState.CRASHED)
    finally:
        runtime.close()


def test_persistent_runtime_rejects_symlinked_paths(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    os.symlink(real_parent, linked_parent, target_is_directory=True)
    with pytest.raises(HarnessError, match="parent is symlinked"):
        PersistentJavaOracleRuntime(linked_parent / "runtime")

    workspace = tmp_path / "marker-workspace"
    workspace.mkdir()
    marker_target = tmp_path / "marker-target"
    marker_target.write_text("{}", encoding="utf-8")
    os.symlink(
        marker_target,
        workspace / "lmyzmail-runtime-attestation.json",
    )
    with pytest.raises(HarnessError, match="attestation is not a real file"):
        PersistentJavaOracleRuntime(workspace)

    subdirectory_workspace = tmp_path / "subdirectory-workspace"
    subdirectory_workspace.mkdir()
    os.symlink(real_parent, subdirectory_workspace / "home", target_is_directory=True)
    runtime = PersistentJavaOracleRuntime(subdirectory_workspace)
    with pytest.raises(HarnessError, match="subdirectory is invalid"):
        runtime._prepare_workspace(new_workspace=False)


def test_cleanup_failure_retains_process_handles_and_blocks_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = PersistentJavaOracleRuntime(tmp_path / "cleanup-state")
    process = ManagedProcess("fake", ("true",), tmp_path / "fake.log")
    runtime._application = process
    runtime._allocate_ports()
    runtime.state = PersistentRuntimeState.RUNNING

    def fail_cleanup(*_: object, **__: object) -> None:
        raise RuntimeError("simulated cleanup deadline")

    monkeypatch.setattr(persistent_runtime_module, "kill_managed_processes", fail_cleanup)
    with pytest.raises(RuntimeError, match="simulated cleanup deadline"):
        runtime.crash()
    _assert_state(runtime, PersistentRuntimeState.CLEANUP_FAILED)
    assert runtime._application is process
    assert runtime._port_allocator is not None
    with pytest.raises(RuntimeError, match="cleanup_failed"):
        runtime.recover()

    monkeypatch.setattr(
        persistent_runtime_module,
        "kill_managed_processes",
        real_kill_managed_processes,
    )
    runtime.close()
    _assert_state(runtime, PersistentRuntimeState.CLOSED)
