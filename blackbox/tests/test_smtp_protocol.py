from __future__ import annotations

import socket
import threading
import time
from queue import Queue

import pytest

from lmyzmail_blackbox.protocols import smtp_data_transaction


def _read_line(connection: socket.socket) -> bytes:
    value = bytearray()
    while not value.endswith(b"\n"):
        chunk = connection.recv(1)
        if not chunk:
            raise AssertionError("client disconnected")
        value.extend(chunk)
    return bytes(value)


def test_smtp_data_body_waits_for_354() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = int(listener.getsockname()[1])
    body_arrived_before_354 = threading.Event()
    server_errors: Queue[BaseException] = Queue()
    received_data: Queue[list[bytes]] = Queue()

    def server() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                connection.sendall(b"220 test ESMTP\r\n")
                assert _read_line(connection) == b"EHLO blackbox.example\r\n"
                connection.sendall(b"250-test\r\n250 PIPELINING\r\n")
                assert _read_line(connection).startswith(b"MAIL FROM:")
                connection.sendall(b"250 ok\r\n")
                assert _read_line(connection).startswith(b"RCPT TO:")
                connection.sendall(b"250 ok\r\n")
                assert _read_line(connection) == b"DATA\r\n"
                connection.setblocking(False)
                try:
                    if connection.recv(1):
                        body_arrived_before_354.set()
                except BlockingIOError:
                    pass
                finally:
                    connection.setblocking(True)
                time.sleep(0.05)
                connection.sendall(b"354 continue\r\n")
                lines: list[bytes] = []
                while lines[-1:] != [b".\r\n"]:
                    lines.append(_read_line(connection))
                received_data.put(lines)
                connection.sendall(b"250 queued\r\n")
                assert _read_line(connection) == b"QUIT\r\n"
                connection.sendall(b"221 bye\r\n")
        except BaseException as error:
            server_errors.put(error)

    thread = threading.Thread(target=server)
    thread.start()
    try:
        transcript = smtp_data_transaction(
            "127.0.0.1",
            port,
            sender="sender@example.test",
            recipient="qa@example.test",
            message=b"Subject: test\r\n\r\nbody\r\n.\r\n\r\n",
        )
    finally:
        thread.join(timeout=2)
        listener.close()

    assert not thread.is_alive()
    if not server_errors.empty():
        raise server_errors.get()
    assert not body_arrived_before_354.is_set()
    assert transcript.data_ready == (b"354 continue\r\n",)
    assert transcript.accepted == (b"250 queued\r\n",)
    assert received_data.get_nowait() == [
        b"Subject: test\r\n",
        b"\r\n",
        b"body\r\n",
        b"..\r\n",
        b"\r\n",
        b".\r\n",
    ]


def test_smtp_data_rejects_bare_line_endings_before_connecting() -> None:
    with pytest.raises(ValueError, match="CRLF"):
        smtp_data_transaction(
            "127.0.0.1",
            1,
            sender="sender@example.test",
            recipient="qa@example.test",
            message=b"Subject: test\n\nbody",
        )
