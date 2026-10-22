"""Bounded source verification rejects special files and expired deadlines."""
import hashlib
import os
import time

import pytest

import export_java_maildir as exporter


def test_digest_streams_regular_file_with_exact_sha256(tmp_path):
    path = tmp_path / "message.eml"
    data = b"message bytes\r\n" * 100_000
    path.write_bytes(data)
    assert exporter.digest(path, deadline=time.monotonic() + 5) == hashlib.sha256(data).hexdigest()


@pytest.mark.timeout(2)
def test_digest_refuses_fifo_without_waiting_for_a_writer(tmp_path):
    path = tmp_path / "unexpected-fifo"
    os.mkfifo(path)
    with pytest.raises(ValueError, match="not a regular file"):
        exporter.digest(path, deadline=time.monotonic() + 1)


def test_digest_refuses_symlink(tmp_path):
    target = tmp_path / "message.eml"
    target.write_bytes(b"private mail")
    link = tmp_path / "unexpected-link"
    link.symlink_to(target)
    with pytest.raises(OSError):
        exporter.digest(link, deadline=time.monotonic() + 1)


def test_digest_checks_deadline_between_bounded_reads(tmp_path, monkeypatch):
    path = tmp_path / "message.eml"
    path.write_bytes(b"m" * (2 * 1024 * 1024))
    ticks = iter((0.0, 2.0))
    monkeypatch.setattr(exporter.time, "monotonic", lambda: next(ticks))
    with pytest.raises(TimeoutError, match="deadline exceeded"):
        exporter.digest(path, deadline=1.0)
