# ruff: noqa: S101

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import cast

import psycopg
import pytest
import redis
from lmyzmail_blackbox.runtime import QA_ADDRESS, QA_PASSWORD, CandidateRuntime

from blackbox.tests.test_candidate_outbound_http_golden import (
    _API_HEADERS,
    _candidate,
    _json_request,
)


def _hard_restart_application(candidate: CandidateRuntime) -> None:
    if candidate._application is None:
        raise RuntimeError("candidate application is not running")
    candidate._application.kill(timeout=candidate.shutdown_kill_timeout)
    candidate._application = None
    CandidateRuntime._start_application(candidate)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(240)
def test_rust_candidate_republishes_committed_outbound_after_sigkill_restart() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository, "--lmyzmail.queue.poll-interval-ms=60000") as candidate:
        response = _json_request(
            candidate,
            "POST",
            "/api/mail/send",
            headers=_API_HEADERS,
            value={
                "from": QA_ADDRESS,
                "password": QA_PASSWORD,
                "to": ["restart-recovery@example.invalid"],
                "subject": "Committed outbound restart recovery",
                "text": "PostgreSQL and Maildir are the durable recovery source.",
                "async": True,
            },
        )
        assert response.status_code == 202
        payload = json.loads(response.body)
        queue_id = int(payload["queueId"])
        message_id = str(payload["messageId"])
        assert candidate.ports is not None
        assert candidate.workspace is not None

        with psycopg.connect(
            host="127.0.0.1",
            port=candidate.ports.postgres,
            dbname="lmyzmail",
            user="lmyzmail_test",
            password="",
        ) as connection:
            row = connection.execute(
                """
                UPDATE outbound_mail_queue
                   SET next_retry_at = current_timestamp + interval '1 hour'
                 WHERE id = %s
             RETURNING sent_file_name, sent_subdirectory
                """,
                (queue_id,),
            ).fetchone()
            assert row is not None
            sent_file_name = cast(str, row[0])
            sent_subdirectory = cast(int, row[1])

        client = redis.Redis(
            host="127.0.0.1",
            port=candidate.ports.redis,
            decode_responses=False,
            socket_connect_timeout=5.0,
            socket_timeout=5.0,
        )
        task_key = f"botmail:mail:queue:task:{queue_id}"
        domain_key = f"botmail:mail:queue:domains:{queue_id}"
        try:
            pipeline = client.pipeline(transaction=True)
            pipeline.delete(task_key, domain_key)
            pipeline.lrem("botmail:mail:queue:pending", 0, queue_id)
            pipeline.srem("botmail:mail:queue:processing", queue_id)
            pipeline.hdel("botmail:mail:queue:processing_time", queue_id)
            pipeline.zrem("botmail:mail:queue:retry", queue_id)
            pipeline.hdel("botmail:mail:queue:sentfile_index", sent_file_name)
            pipeline.execute()
            assert client.exists(task_key, domain_key) == 0
            assert client.lpos("botmail:mail:queue:pending", queue_id) is None

            _hard_restart_application(candidate)

            deadline = time.monotonic() + 20.0
            while True:
                task_json = client.get(task_key)
                domain_count = client.hlen(domain_key)
                pending_position = client.lpos("botmail:mail:queue:pending", queue_id)
                indexed_id = client.hget("botmail:mail:queue:sentfile_index", sent_file_name)
                if (
                    isinstance(task_json, bytes)
                    and domain_count == 1
                    and pending_position is not None
                    and indexed_id == str(queue_id).encode()
                ):
                    break
                assert time.monotonic() < deadline, (
                    "committed outbound task was not republished after SIGKILL; "
                    f"task={task_json!r}, domains={domain_count}, "
                    f"pending={pending_position!r}, sent_index={indexed_id!r}"
                )
                time.sleep(0.02)

            parsed_task = json.loads(task_json)
            assert parsed_task["id"] == queue_id
            assert parsed_task["messageId"] == message_id
            assert 600_000 < client.ttl(task_key) <= 7 * 24 * 60 * 60
            assert 600_000 < client.ttl(domain_key) <= 7 * 24 * 60 * 60
        finally:
            client.close()

        with psycopg.connect(
            host="127.0.0.1",
            port=candidate.ports.postgres,
            dbname="lmyzmail",
            user="lmyzmail_test",
            password="",
        ) as connection:
            queue_rows = connection.execute(
                "SELECT count(*) FROM outbound_mail_queue WHERE id = %s",
                (queue_id,),
            ).fetchone()
            index_rows = connection.execute(
                """
                SELECT count(*) FROM email_index
                 WHERE mailbox_address = %s AND folder = 'sent'
                   AND subdirectory = %s AND file_name = %s
                """,
                (QA_ADDRESS, sent_subdirectory, sent_file_name),
            ).fetchone()
        assert queue_rows == (1,)
        assert index_rows == (1,)
        sent_files = list((candidate.workspace / "maildir").rglob(sent_file_name))
        assert len(sent_files) == 1
