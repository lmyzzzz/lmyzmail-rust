"""Real Java -> Rust -> Java -> Rust takeover over one durable data set."""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import httpx
import psycopg

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "blackbox/tests"))

from test_candidate_web_multipart_golden import _Part, _data, _multipart, _request
from test_persistent_runtime import _assert_http_takeover
from lmyzmail_blackbox.persistent_runtime import LEGACY_SESSION_TOKEN, PersistentJavaOracleRuntime
from lmyzmail_blackbox.protocols import smtp_data_transaction
from lmyzmail_blackbox.runtime import CandidateRuntime, JavaOracleRuntime


class TakeoverRuntime(PersistentJavaOracleRuntime):
    rust_phase = False

    def _application_arguments(self):
        if self.rust_phase:
            config = CandidateRuntime._candidate_configuration(self)
            return [os.environ["LMYZMAIL_TAKEOVER_BINARY"], "--config", str(config),
                    "--lmyzmail.queue.poll-interval-ms=60000",
                    "--lmyzmail.queue.batch-size=1"]
        return [*super()._application_arguments(), "--botmail.queue.poll-interval-ms=60000",
                "--botmail.queue.batch-size=1"]

    def _start_application(self):
        if self.rust_phase:
            JavaOracleRuntime._start_application(self)
        else:
            super()._start_application()


def test_ordinary_maildir_survives_bidirectional_takeover(tmp_path):
    binary = Path(os.environ["LMYZMAIL_TAKEOVER_BINARY"]).resolve(strict=True)
    assert binary.is_file()
    runtime = TakeoverRuntime(tmp_path / "durable-takeover", shutdown_timeout=20)
    message = (b"From: sender@sender.invalid\r\nTo: qa@example.test\r\n"
               b"Subject: Rust takeover inbound\r\nMessage-ID: <takeover-inbound@example.test>\r\n"
               b"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
               b"Retained across Java Rust Java Rust.\r\n")
    with binary.open("rb") as stream:
        binary_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
    proof = {"scope": "ordinary ASCII mailbox; ambiguous names and pending outbound takeover remain separate gates",
             "binary_sha256": binary_sha256,
             "phases": []}
    expected_raw = {}
    try:
        runtime.start()
        _assert_http_takeover(ROOT, runtime)
        proof["phases"].append("initial-java-legacy-reads")
        runtime.rust_phase = True
        runtime.restart_application()
        _assert_http_takeover(ROOT, runtime)
        assert runtime.ports is not None and runtime.workspace is not None
        transcript = smtp_data_transaction(
            "127.0.0.1", runtime.ports.smtp, sender="",
            recipient="qa@example.test", message=message,
        )
        assert transcript.data_ready[0].startswith(b"354")
        assert transcript.accepted[0].startswith(b"250"), transcript
        response = _request(runtime, _multipart((
            _data({"to": ["recipient@multipart.invalid"], "subject": "Rust takeover sent",
                   "text": "retained sent body", "async": True}),
            _Part("attachments", b"retained attachment\x00", filename="takeover.bin"),
        )))
        assert response.status_code == 202, response
        sent_name = json.loads(response.body)["sentFileName"]
        with psycopg.connect(host="127.0.0.1", port=runtime.ports.postgres,
                             user="lmyzmail_test", dbname="lmyzmail") as connection:
            inbound = connection.execute(
                "SELECT folder,file_name FROM email_index WHERE message_id=%s",
                ("<takeover-inbound@example.test>",),
            ).fetchall()
        assert len(inbound) == 1, inbound
        references = [tuple(inbound[0]), ("sent", sent_name)]
        for folder, name in references:
            matches = list((runtime.workspace / "maildir/qa@example.test" / folder).rglob(name))
            assert len(matches) == 1, matches
            expected_raw[(folder, name)] = matches[0].read_bytes()
        proof["phases"].append("rust-reads-legacy-and-publishes-inbound-and-attachment-sent")

        for rust_phase, phase in ((False, "java-reads-rust-publications"), (True, "rust-reopens-after-java")):
            runtime.rust_phase = rust_phase
            runtime.restart_application()
            with httpx.Client(trust_env=False, timeout=10) as client:
                for (folder, name), expected in expected_raw.items():
                    response = client.get(
                        f"http://127.0.0.1:{runtime.ports.http}/web/mail/raw/{folder}/{name}",
                        headers={"X-Session-Token": LEGACY_SESSION_TOKEN},
                    )
                    assert response.status_code == 200, response.text
                    assert response.content == expected
            proof["phases"].append(phase)
        proof["messages"] = [
            {"folder": folder, "file_name": name, "bytes": len(raw),
             "sha256": hashlib.sha256(raw).hexdigest()}
            for (folder, name), raw in expected_raw.items()
        ]
    finally:
        runtime.close()
    proof["status"] = "passed"
    proof["managed_process_cleanup"] = "passed"
    output = Path(os.environ["LMYZMAIL_TAKEOVER_OUTPUT"])
    with output.open("x", encoding="utf-8") as stream:
        json.dump(proof, stream, indent=2, sort_keys=True)
        stream.write("\n")
