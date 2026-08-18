from __future__ import annotations

import fcntl
import json
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import psycopg
import pytest
import redis

from lmyzmail_blackbox.protocols import http_exchange
from lmyzmail_blackbox.runtime import API_KEY, CandidateRuntime


_SENDER = "stress-sender@example.test"
_QUEUE_PREFIX = "botmail:mail:queue:"
_OBSERVER_PREFIX = "LMYZMAIL_OUTBOUND_BATCH_OBSERVER "
_STAGING_LEASE_RELATIVE = Path(".lmyzmail-quarantine/.lmyzmail-staging.lease")


@dataclass(slots=True)
class _FsyncOffStressRuntime(CandidateRuntime):
    email_size_kb: int = 10
    count: int = 256

    def _candidate_configuration(self) -> Path:
        path = CandidateRuntime._candidate_configuration(self)
        value = json.loads(path.read_text(encoding="utf-8"))
        value["storage"] = {"fsync_enabled": False}
        value["stress"] = {
            "enabled": True,
            "sender_prefix": "stress-sender",
            "receiver_prefix": "stress-receiver",
            "password": "StressBlackboxPass123!",
            "production_count": self.count,
            "warmup_count": self.count,
            "warmup_rounds": 1,
            "email_size_kb": self.email_size_kb,
        }
        value["limits"]["outbound_poll_interval_ms"] = 60_000
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def _application_environment(self) -> dict[str, str]:
        environment = CandidateRuntime._application_environment(self)
        environment["LMYZMAIL_STRESS_ENQUEUE_OBSERVER"] = "1"
        return environment


def _runtime(repository: Path, *, count: int, email_size_kb: int) -> CandidateRuntime:
    if os.environ.get("LMYZMAIL_CANDIDATE_COMMAND_JSON") is not None:
        runtime = cast(
            _FsyncOffStressRuntime,
            _FsyncOffStressRuntime.from_environment(),
        )
        runtime.count = count
        runtime.email_size_kb = email_size_kb
        runtime.shutdown_timeout = 30.0
        return runtime
    return _FsyncOffStressRuntime(
        command_template=(
            str(repository / "target/x86_64-unknown-linux-gnu/release/lmyzmail"),
            "--config",
            "{config}",
        ),
        count=count,
        email_size_kb=email_size_kb,
        shutdown_timeout=30.0,
    )


def _start(runtime: CandidateRuntime) -> None:
    assert runtime.ports is not None
    response = http_exchange(
        "127.0.0.1",
        runtime.ports.http,
        "POST",
        "/api/stress/start",
        headers=(("X-API-Key", API_KEY),),
    )
    assert response.status_code == 200, response.body


def _postgres(runtime: CandidateRuntime) -> psycopg.Connection[Any]:
    assert runtime.ports is not None
    return psycopg.connect(
        host="127.0.0.1",
        port=runtime.ports.postgres,
        dbname="lmyzmail",
        user="lmyzmail_test",
        password="",
        connect_timeout=3,
    )


def _queue_rows(runtime: CandidateRuntime) -> list[tuple[int, str]]:
    with _postgres(runtime) as connection:
        return [
            (cast(int, row[0]), cast(str, row[1]))
            for row in connection.execute(
                "SELECT id,status FROM outbound_mail_queue "
                "WHERE sender_address=%s ORDER BY id",
                (_SENDER,),
            ).fetchall()
        ]


def _pending_ids(runtime: CandidateRuntime) -> list[int]:
    assert runtime.ports is not None
    client: redis.Redis = redis.Redis(
        host="127.0.0.1",
        port=runtime.ports.redis,
        db=0,
        socket_connect_timeout=1.0,
        socket_timeout=1.0,
    )
    try:
        values = cast(list[bytes], client.lrange(_QUEUE_PREFIX + "pending", 0, -1))
        return [
            int(value)
            for value in values
            if value.isdigit()
            and client.get(f"{_QUEUE_PREFIX}task:{int(value)}") is not None
        ]
    finally:
        client.close()


def _wait_for(predicate: Any, description: str, *, timeout: float = 30.0) -> Any:
    deadline = time.monotonic() + timeout
    last: Any = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(0.01)
    raise AssertionError(f"timed out waiting for {description}; last={last!r}")


def _outbound_files(runtime: CandidateRuntime) -> list[Path]:
    assert runtime.workspace is not None
    root = runtime.workspace / "maildir/.lmyzmail-outbound"
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*") if path.is_file() or path.is_symlink())


def _outbound_data_files(runtime: CandidateRuntime) -> list[Path]:
    assert runtime.workspace is not None
    root = runtime.workspace / "maildir/.lmyzmail-outbound"
    lease = root / _STAGING_LEASE_RELATIVE
    return [path for path in _outbound_files(runtime) if path != lease]


def _assert_released_staging_lease(runtime: CandidateRuntime) -> None:
    assert runtime.workspace is not None
    root = runtime.workspace / "maildir/.lmyzmail-outbound"
    quarantine = root / _STAGING_LEASE_RELATIVE.parent
    lease = root / _STAGING_LEASE_RELATIVE
    assert _outbound_files(runtime) == [lease]

    root_metadata = root.lstat()
    quarantine_metadata = quarantine.lstat()
    lease_metadata = lease.lstat()
    assert stat.S_ISDIR(root_metadata.st_mode)
    assert stat.S_ISDIR(quarantine_metadata.st_mode)
    assert stat.S_ISREG(lease_metadata.st_mode)
    assert not stat.S_ISLNK(lease_metadata.st_mode)
    assert lease_metadata.st_uid == quarantine_metadata.st_uid == root_metadata.st_uid
    assert stat.S_IMODE(quarantine_metadata.st_mode) == 0o700
    assert stat.S_IMODE(lease_metadata.st_mode) == 0o600
    assert lease_metadata.st_size == 0
    assert lease_metadata.st_nlink == 1

    descriptor = os.open(
        lease,
        os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        opened = os.fstat(descriptor)
        rebound = lease.lstat()
        assert (opened.st_dev, opened.st_ino) == (rebound.st_dev, rebound.st_ino)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _stress_files(runtime: CandidateRuntime) -> list[Path]:
    assert runtime.workspace is not None
    root = runtime.workspace / "maildir/.lmyzmail-stress"
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*") if path.is_file() or path.is_symlink())


def _stop(runtime: CandidateRuntime) -> None:
    application = runtime._application
    assert application is not None
    application.stop(timeout=30.0, kill_timeout=3.0)


def _latest_batch_observation(runtime: CandidateRuntime) -> dict[str, Any] | None:
    application = runtime._application
    assert application is not None
    observations = [
        json.loads(line.split(_OBSERVER_PREFIX, maxsplit=1)[1])
        for line in application.log_tail(max_bytes=2 * 1024 * 1024).splitlines()
        if _OBSERVER_PREFIX in line
    ]
    return observations[-1] if observations else None


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_fsync_off_batch_persists_every_authority_and_observes_coalescing() -> None:
    repository = Path(__file__).resolve().parents[2]
    count = 256
    with _runtime(repository, count=count, email_size_kb=10) as runtime:
        _start(runtime)
        rows = cast(
            list[tuple[int, str]],
            _wait_for(
                lambda: (
                    observed
                    if len(observed := _queue_rows(runtime)) == count
                    else []
                ),
                "fsync-off PostgreSQL queue rows",
            ),
        )
        task_ids = [row[0] for row in rows]
        assert len(task_ids) == len(set(task_ids)) == count
        with _postgres(runtime) as connection:
            counts = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM outbound_mail_queue WHERE id=ANY(%s)),"
                "(SELECT count(*) FROM lmyzmail_outbound_spool WHERE task_id=ANY(%s) "
                " AND spool_kind='RUST' AND cleanup_state='OWNED'),"
                "(SELECT count(*) FROM lmyzmail_outbound_content WHERE task_id=ANY(%s) "
                " AND source_root='SPOOL'),"
                "(SELECT count(*) FROM email_index WHERE mailbox_address=%s "
                " AND folder='sent')",
                (task_ids, task_ids, task_ids, _SENDER),
            ).fetchone()
        assert counts == (count, count, count, count)
        pending = cast(
            list[int],
            _wait_for(
                lambda: (
                    observed
                    if len(observed := _pending_ids(runtime)) == count
                    else []
                ),
                "fsync-off Redis publication",
            ),
        )
        assert sorted(pending) == sorted(task_ids)
        observation = cast(
            dict[str, Any],
            _wait_for(
                lambda: _latest_batch_observation(runtime),
                "batch observer snapshot",
            ),
        )
        assert observation["schema"] == "lmyzmail.outbound-batch-observation.v1"
        assert observation["rows"] == count
        assert 1 < observation["max_rows"] <= 64
        assert observation["batches"] < observation["rows"]
        assert observation["uncertain_batches"] == 0


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(240)
def test_fsync_off_sigterm_before_batch_mutation_removes_owned_state() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _runtime(repository, count=64, email_size_kb=32) as runtime:
        blocker = _postgres(runtime)
        try:
            blocker.execute(
                "SELECT pg_advisory_lock(hashtextextended(%s::text, 0))",
                ("lmyzmail:outbound:queue",),
            )
            _start(runtime)
            assert _wait_for(
                lambda: _outbound_data_files(runtime),
                "materialization waiting for batch admission",
            )
            assert _queue_rows(runtime) == []
            assert _pending_ids(runtime) == []
            _stop(runtime)
        finally:
            blocker.close()

        assert _stress_files(runtime) == []
        assert _outbound_data_files(runtime) == []
        _assert_released_staging_lease(runtime)
        with _postgres(runtime) as connection:
            counts = connection.execute(
                "SELECT "
                "(SELECT count(*) FROM outbound_mail_queue WHERE sender_address=%s),"
                "(SELECT count(*) FROM email_index WHERE mailbox_address IN (%s,%s))",
                (_SENDER, _SENDER, "stress-receiver@example.test"),
            ).fetchone()
        assert counts == (0, 0)
        assert _pending_ids(runtime) == []
