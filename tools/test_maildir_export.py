"""Actual new-v2 mail rollback through frozen Java without source mutations."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from export_java_maildir import export_maildir
from test_ambiguous_takeover import ADDRESSES, _db, _deliver, _raw, _seed
from test_release_takeover import TakeoverRuntime


class ExportRuntime(TakeoverRuntime):
    export_path = None

    def _application_arguments(self):
        arguments = super()._application_arguments()
        if self.export_path is None:
            return arguments
        prefix = "--lmyzmail.maildir.base=" if self.rust_phase else "--botmail.maildir.base="
        return [value for value in arguments if not value.startswith(prefix)] + [
            prefix + str(self.export_path)]


def snapshot(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*") if path.is_file()}


@pytest.mark.timeout(300)
def test_new_v2_maildir_exports_for_java_and_reopens_in_rust(tmp_path):
    binary = Path(os.environ["LMYZMAIL_TAKEOVER_BINARY"]).resolve(strict=True)
    proof = {"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "phases": []}
    runtime = ExportRuntime(tmp_path / "export-takeover", shutdown_timeout=20)
    try:
        runtime.start()
        tokens = {address: _seed(runtime, address) for address in ADDRESSES}
        runtime.rust_phase = True
        runtime.restart_application()
        references = {address: _deliver(runtime, address, index + 10)
                      for index, address in enumerate(ADDRESSES)}
        original_bytes = {}
        for address in ADDRESSES:
            response = _raw(runtime, tokens[address], references[address])
            assert response.status_code == 200, response.text
            original_bytes[address] = response.content
        proof["phases"].append("rust-creates-and-reads-four-new-v2-address-classes")
        assert runtime._application is not None and runtime.ports is not None
        runtime._application.stop(timeout=20, kill_timeout=2)
        source = runtime.workspace / "maildir"
        before = snapshot(source)
        dsn = (f"host=127.0.0.1 port={runtime.ports.postgres} "
               "user=lmyzmail_test dbname=lmyzmail")
        with _db(runtime) as db:
            rows_before = db.execute("SELECT * FROM email_index ORDER BY id").fetchall()
        # Failed budgets and symlink/collision cases must never publish output.
        with pytest.raises(ValueError, match="disk budget"):
            export_maildir(source, tmp_path / "budget-rejected", dsn,
                           offline=True, max_bytes=1)
        assert not (tmp_path / "budget-rejected").exists()
        with pytest.raises(ValueError, match="offline"):
            export_maildir(source, tmp_path / "not-offline", dsn,
                           offline=False, max_bytes=1024 * 1024)
        proof["export"] = export_maildir(source, tmp_path / "java-rollback", dsn,
                                        offline=True, max_bytes=1024 * 1024)
        assert snapshot(source) == before
        with _db(runtime) as db:
            assert db.execute("SELECT * FROM email_index ORDER BY id").fetchall() == rows_before
        proof["phases"].append("offline-streamed-copy-with-unchanged-source-and-database")
        runtime.export_path = Path(proof["export"]["output"])
        runtime.rust_phase = False
        runtime.restart_application()
        for address in ADDRESSES:
            response = _raw(runtime, tokens[address], references[address])
            assert response.status_code == 200, (address, response.text)
            assert response.content == original_bytes[address]
        proof["phases"].append("frozen-java-byte-exact-reads-of-all-exported-v2-mail")
        runtime.rust_phase = True
        runtime.restart_application()
        for address in ADDRESSES:
            response = _raw(runtime, tokens[address], references[address])
            assert response.status_code == 200 and response.content == original_bytes[address]
        proof["phases"].append("rust-byte-exact-reopen-after-java-rollback")
        runtime._application.stop(timeout=20, kill_timeout=2)
        with _db(runtime) as db:
            db.execute("INSERT INTO mailbox(address,password_hash,created_at) "
                       "SELECT %s,password_hash,created_at FROM mailbox WHERE address=%s",
                       ("under/score@example.test", ADDRESSES[0]))
        with pytest.raises(ValueError, match="unsafe Java mailbox alias"):
            export_maildir(source, tmp_path / "collision-rejected", dsn,
                           offline=True, max_bytes=1024 * 1024)
        assert not (tmp_path / "collision-rejected").exists()
        symlink = source / "untrusted-alias"
        symlink.symlink_to(tmp_path, target_is_directory=True)
        with pytest.raises(ValueError, match="symlinked source"):
            export_maildir(source, tmp_path / "symlink-rejected", dsn,
                           offline=True, max_bytes=1024 * 1024)
        assert not (tmp_path / "symlink-rejected").exists()
        proof["phases"].append("lossy-owner-collision-and-symlink-export-fail-closed")
    finally:
        runtime.close()
    proof["status"] = "passed"
    proof["managed_process_cleanup"] = "passed"
    output = Path(os.environ["LMYZMAIL_EXPORT_TAKEOVER_OUTPUT"])
    with output.open("x", encoding="utf-8") as target:
        json.dump(proof, target, ensure_ascii=False, indent=2, sort_keys=True)
        target.write("\n")
