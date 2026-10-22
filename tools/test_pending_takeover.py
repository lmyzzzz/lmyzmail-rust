"""Bidirectional handoff of real pending memory/file-mode outbound tasks.

Run in an isolated user/network namespace with 93.184.216.34 on loopback,
as in blackbox/bin/run-outbound-probe.sh. No queue rows are manufactured.
"""
from __future__ import annotations

import base64
import email.policy
import hashlib
import json
import os
import time
from pathlib import Path
from email.parser import BytesParser

import httpx
import psycopg
import pytest
import redis

from lmyzmail_blackbox.outbound_oracle_probe import (
    OutboundOracleRuntime, _candidate_dns_server, _FAKE_IP,
)
from lmyzmail_blackbox.runtime import API_KEY, CandidateRuntime, JavaOracleRuntime, QA_PASSWORD
from lmyzmail_blackbox.scripted_smtp import ScriptedSmtpServer, SmtpScenario

PREFIX = "botmail:mail:queue:"


class HandoffRuntime(OutboundOracleRuntime):
    rust_phase = False

    def _application_arguments(self):
        if self.rust_phase:
            config = CandidateRuntime._candidate_configuration(self)
            return [os.environ["LMYZMAIL_TAKEOVER_BINARY"], "--config", str(config),
                    "--lmyzmail.queue.poll-interval-ms=30000",
                    "--lmyzmail.queue.batch-size=4",
                    "--lmyzmail.outbound.pool-enabled=false",
                    "--lmyzmail.outbound.dns.query-timeout-seconds=1"]
        return ["--botmail.queue.poll-interval-ms=30000"
                if argument == "--botmail.queue.poll-interval-ms=3000" else argument
                for argument in super()._application_arguments()]

    def _start_application(self):
        if self.rust_phase:
            JavaOracleRuntime._start_application(self)
        else:
            super()._start_application()


def wait_for(predicate, description, seconds=45):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out: {description}")


@pytest.mark.timeout(300)
def test_pending_memory_and_file_tasks_survive_both_runtime_handoffs(tmp_path):
    binary = Path(os.environ["LMYZMAIL_TAKEOVER_BINARY"]).resolve(strict=True)
    with binary.open("rb") as source:
        binary_sha256 = hashlib.file_digest(source, "sha256").hexdigest()
    proof = {"binary_sha256": binary_sha256, "phases": []}
    runtime = HandoffRuntime(tmp_path / "pending-takeover")
    dns = _candidate_dns_server()
    smtp = ScriptedSmtpServer(SmtpScenario(), bind_host=_FAKE_IP, bind_port=25)
    cache = None
    try:
        dns.start()
        smtp.start()
        runtime.start()
        assert runtime.ports is not None
        cache = redis.Redis(host="127.0.0.1", port=runtime.ports.redis)
        for producer_rust in (False, True):
            assert runtime.rust_phase == producer_rust
            cache.set("dns:mx:outbound.fixture.test", b"outbound.fixture.test", ex=300)
            # Observe a scheduler tick using a real HTTP-created warmup task.
            # Rust correctly rejects negative sentinel IDs as corrupt queue
            # state; no manufactured queue member is needed for this handoff.
            warmup_before = len(smtp.messages())
            with httpx.Client(trust_env=False, timeout=10,
                              headers={"X-API-Key": API_KEY}) as client:
                warmup = client.post(f"http://127.0.0.1:{runtime.ports.http}/api/mail/send",
                    json={"from": "qa@example.test", "password": QA_PASSWORD,
                          "to": ["recipient@outbound.fixture.test"],
                          "subject": f"handoff warmup {producer_rust}",
                          "text": "scheduler boundary", "async": True})
                assert warmup.status_code == 202, warmup.text
            wait_for(lambda: len(smtp.messages()) == warmup_before + 1, "scheduler warmup")
            before = len(smtp.messages())
            tasks = []
            with httpx.Client(trust_env=False, timeout=10,
                              headers={"X-API-Key": API_KEY}) as client:
                for label, body in (("memory", "handoff small body"),
                                    ("file", "L" * (12 * 1024))):
                    response = client.post(f"http://127.0.0.1:{runtime.ports.http}/api/mail/send",
                        json={"from": "qa@example.test", "password": QA_PASSWORD,
                              "to": ["recipient@outbound.fixture.test"],
                              "subject": f"handoff {producer_rust} {label}",
                              "text": body, "async": True})
                    assert response.status_code == 202, response.text
                    task_id = response.json()["queueId"]
                    key = PREFIX + f"task:{task_id}"
                    detail = json.loads(cache.get(key))
                    assert detail["status"] == "PENDING", detail
                    assert str(task_id).encode() in cache.lrange(PREFIX + "pending", 0, -1)
                    if label == "memory":
                        assert detail.get("signedContentBase64") is not None
                        message = base64.b64decode(detail["signedContentBase64"], validate=True)
                    else:
                        assert detail.get("messageFilePath") is not None
                        message = Path(detail["messageFilePath"]).read_bytes()
                    ttl = cache.ttl(key)
                    assert 604770 <= ttl <= 604800, ttl
                    tasks.append((task_id, detail["messageId"], body.encode(), message, label))
            assert len(smtp.messages()) == before, "producer delivered before handoff"
            runtime.rust_phase = not producer_rust
            runtime.restart_application()
            wait_for(lambda: len(smtp.messages()) == before + len(tasks), "consumer SMTP delivery")
            attempts = smtp.messages()[before:]
            assert len(attempts) == 2 and all(attempt.accepted for attempt in attempts)
            for task_id, message_id, body, message, label in tasks:
                matches = [attempt for attempt in attempts if message_id.encode() in attempt.data]
                assert len(matches) == 1, (task_id, message_id, attempts)
                # SMTP DATA must end on a CRLF boundary before its dot
                # terminator. Neither producer appends that boundary to its
                # queued MIME buffer, so assert the exact wire transformation.
                wire_message = message if message.endswith(b"\r\n") else message + b"\r\n"
                assert matches[0].data == wire_message, (label, "queued message bytes changed")
                decoded = BytesParser(policy=email.policy.default).parsebytes(
                    matches[0].data).get_payload(decode=True)
                assert decoded.removesuffix(b"\r\n") == body
            with psycopg.connect(host="127.0.0.1", port=runtime.ports.postgres,
                                 dbname="lmyzmail", user="lmyzmail_test", autocommit=True) as db:
                ids = [task[0] for task in tasks]
                def archived():
                    rows = db.execute("SELECT id,status,retry_count FROM outbound_mail_queue "
                                      "WHERE id=ANY(%s) ORDER BY id", (ids,)).fetchall()
                    return rows == [(task_id, "SENT", 0) for task_id in sorted(ids)]
                wait_for(archived, "exactly-once PostgreSQL SENT archive")
            wait_for(lambda: all(cache.get(PREFIX + f"task:{task_id}") is None
                                 for task_id, *_ in tasks), "terminal task cleanup")
            assert not any(str(task[0]).encode() in cache.lrange(PREFIX + "pending", 0, -1)
                           for task in tasks)
            proof["phases"].append({"producer": "rust" if producer_rust else "java",
                "consumer": "java" if producer_rust else "rust",
                "tasks": [{"mode": label, "bytes": len(message),
                           "sha256": hashlib.sha256(message).hexdigest()}
                          for _, _, _, message, label in tasks],
                "accepted": 2, "retries": 0, "duplicates": 0})
        accepted = len(smtp.messages())
        runtime.rust_phase = True
        runtime.restart_application()
        # Cover a complete 30s scheduler interval after Java has finished Rust's
        # tasks, so stale Rust auxiliary rows cannot silently resurrect them.
        until = time.monotonic() + 35
        while time.monotonic() < until:
            assert len(smtp.messages()) == accepted, "completed task resurrected after Rust restart"
            time.sleep(0.05)
        proof["phases"].append({"phase": "rust-reopen-after-java-completion",
                                 "observed_seconds": 35, "duplicates": 0})
    finally:
        if cache is not None:
            cache.close()
        runtime.close()
        smtp.stop()
        dns.stop()
    proof["status"] = "passed"
    proof["managed_process_cleanup"] = "passed"
    output = Path(os.environ["LMYZMAIL_PENDING_TAKEOVER_OUTPUT"])
    with output.open("x", encoding="utf-8") as target:
        json.dump(proof, target, indent=2, sort_keys=True)
        target.write("\n")
