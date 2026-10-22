"""Real legacy ambiguous-name takeover and lossy-alias ownership boundary."""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import httpx
import psycopg
import pytest

from lmyzmail_blackbox.protocols import RawSmtpClient
from lmyzmail_blackbox.persistent_runtime import LEGACY_SESSION_TOKEN
from test_release_takeover import TakeoverRuntime

ADDRESSES = (
    "under_score@example.test",
    "user..dots@example.test",
    "v1-qa@example.test",
    "邮箱@example.test",
)
# Public isolated fixture hash, also used by the multi-domain legacy fixture.
PASSWORD_HASH = "$2a$10$KMejGNeOXWSJBM831XMwmeVrw.16AhD65yYCs7vxZIM0osXpoyPsm"  # noqa: S105


def _db(runtime):
    assert runtime.ports is not None
    return psycopg.connect(host="127.0.0.1", port=runtime.ports.postgres,
                          user="lmyzmail_test", dbname="lmyzmail", autocommit=True)


def _seed(runtime, address):
    token = "isolated-takeover-" + hashlib.sha256(address.encode()).hexdigest()
    digest = hashlib.sha256(token.encode()).hexdigest()
    with _db(runtime) as db:
        db.execute("INSERT INTO mailbox (address,password_hash,created_at) "
                   "VALUES (%s,%s,CURRENT_TIMESTAMP)", (address, PASSWORD_HASH))
        db.execute("INSERT INTO user_session "
                   "(mailbox_address,token_hash,created_at,expires_at) "
                   "VALUES (%s,%s,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+interval '1 day')",
                   (address, digest))
    return token


def _deliver(runtime, address, number):
    assert runtime.ports is not None
    message_id = f"<ambiguous-takeover-{number}@example.test>"
    message = (f"From: sender@sender.invalid\r\nTo: {address}\r\n"
               f"Subject: Ambiguous takeover {number}\r\nMessage-ID: {message_id}\r\n"
               "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
               "Independent legacy ownership fixture.\r\n").encode()
    with RawSmtpClient.connect("127.0.0.1", runtime.ports.smtp, timeout=10) as client:
        assert client.command(b"EHLO takeover.example")[0].startswith(b"250")
        assert client.command(b"MAIL FROM:<>")[0].startswith(b"250")
        assert client.command(f"RCPT TO:<{address}>".encode())[0].startswith(b"250")
        ready, accepted = client.data(message)
        assert ready[0].startswith(b"354")
        assert accepted[0].startswith(b"250")
        assert client.quit()[0].startswith(b"221")
    deadline = time.monotonic() + 15
    with _db(runtime) as db:
        while time.monotonic() < deadline:
            rows = db.execute("SELECT folder,file_name FROM email_index "
                              "WHERE mailbox_address=%s AND message_id=%s",
                              (address, message_id)).fetchall()
            if rows:
                assert len(rows) == 1
                return tuple(rows[0])
            time.sleep(0.05)
    raise AssertionError(f"missing indexed delivery for {address}")


def _raw(runtime, token, reference):
    assert runtime.ports is not None
    folder, name = reference
    with httpx.Client(trust_env=False, timeout=10) as client:
        return client.get(f"http://127.0.0.1:{runtime.ports.http}/web/mail/raw/{folder}/{name}",
                          headers={"X-Session-Token": token})


@pytest.mark.timeout(240)
def test_unique_legacy_ambiguous_names_and_collision_fail_closed(tmp_path):
    binary = Path(os.environ["LMYZMAIL_TAKEOVER_BINARY"]).resolve(strict=True)
    with binary.open("rb") as stream:
        binary_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
    proof = {"binary_sha256": binary_sha256,
             "scope": "legacy reads and ownership collision; new v2 rollback is a separate gate",
             "addresses": [], "phases": []}
    runtime = TakeoverRuntime(tmp_path / "ambiguous-takeover", shutdown_timeout=20)
    originals = {}
    tokens = {}
    references = {}
    try:
        runtime.start()
        for number, address in enumerate(ADDRESSES):
            tokens[address] = _seed(runtime, address)
            references[address] = _deliver(runtime, address, number)
            response = _raw(runtime, tokens[address], references[address])
            # Frozen Java's writer preserves interior dots, while its reader
            # replaces them. Independently capture the delivered Maildir bytes
            # and retain that 404 as bug evidence; Rust must recover the mail.
            expected_status = 404 if ".." in address else 200
            assert response.status_code == expected_status, (address, response.text)
            matches = list((runtime.workspace / "maildir").rglob(references[address][1]))
            assert len(matches) == 1
            originals[address] = matches[0].read_bytes()
            if response.status_code == 200:
                assert response.content == originals[address]
            proof["addresses"].append({"address": address,
                "java_raw_status": response.status_code,
                "raw_sha256": hashlib.sha256(originals[address]).hexdigest(),
                "bytes": len(originals[address])})
        proof["phases"].append("java-creates-and-reads-four-legacy-address-classes")
        runtime.rust_phase = True
        runtime.restart_application()
        for address in ADDRESSES:
            response = _raw(runtime, tokens[address], references[address])
            assert response.status_code == 200, (address, response.text)
            assert response.content == originals[address]
        proof["phases"].append("rust-byte-exact-legacy-takeover")

        # The early Rust v1 namespace shares a flat directory component with
        # literal Java addresses starting with "v1-". Even an indexed filename
        # must not let qa read v1-qa's legacy publication through that fallback.
        v1_folder, v1_name = references[ADDRESSES[2]]
        with _db(runtime) as db:
            db.execute("INSERT INTO email_index (has_attachments,subdirectory,indexed_at,"
                       "received_at,size_bytes,folder,from_address,message_id,subject,"
                       "to_addresses,file_name,mailbox_address) "
                       "SELECT has_attachments,subdirectory,indexed_at,received_at,size_bytes,"
                       "folder,from_address,message_id,subject,to_addresses,file_name,%s "
                       "FROM email_index WHERE mailbox_address=%s AND folder=%s AND file_name=%s",
                       ("qa@example.test", ADDRESSES[2], v1_folder, v1_name))
        assert _raw(runtime, LEGACY_SESSION_TOKEN, (v1_folder, v1_name)).status_code == 404
        proof["phases"].append("rust-denies-v1-namespace-cross-owner-fallback")

        attacker = "under/score@example.test"
        attacker_token = _seed(runtime, attacker)
        folder, name = references[ADDRESSES[0]]
        with _db(runtime) as db:
            db.execute("INSERT INTO email_index (has_attachments,subdirectory,indexed_at,"
                       "received_at,size_bytes,folder,from_address,message_id,subject,"
                       "to_addresses,file_name,mailbox_address) "
                       "SELECT has_attachments,subdirectory,indexed_at,received_at,size_bytes,"
                       "folder,from_address,message_id,subject,to_addresses,file_name,%s "
                       "FROM email_index WHERE mailbox_address=%s AND folder=%s AND file_name=%s",
                       (attacker, ADDRESSES[0], folder, name))
        for token in (tokens[ADDRESSES[0]], attacker_token):
            assert _raw(runtime, token, (folder, name)).status_code == 404
        for address in ADDRESSES[1:]:
            assert _raw(runtime, tokens[address], references[address]).content == originals[address]
        proof["phases"].append("rust-denies-registered-lossy-alias-with-index-row")

        runtime.rust_phase = False
        runtime.restart_application()
        for token in (tokens[ADDRESSES[0]], attacker_token):
            response = _raw(runtime, token, (folder, name))
            assert response.status_code == 200, response.text
            assert response.content == originals[ADDRESSES[0]]
        proof["phases"].append("frozen-java-reproduces-cross-mailbox-alias-disclosure")
        runtime.rust_phase = True
        runtime.restart_application()
        for token in (tokens[ADDRESSES[0]], attacker_token):
            assert _raw(runtime, token, (folder, name)).status_code == 404
        proof["phases"].append("rust-restart-preserves-fail-closed-ownership")
    finally:
        runtime.close()
    proof["status"] = "passed"
    proof["managed_process_cleanup"] = "passed"
    output = Path(os.environ["LMYZMAIL_AMBIGUOUS_TAKEOVER_OUTPUT"])
    with output.open("x", encoding="utf-8") as stream:
        json.dump(proof, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
