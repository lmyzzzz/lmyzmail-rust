from __future__ import annotations

import socket
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from queue import Queue
from typing import cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from lmyzmail_blackbox.errors import ProtocolError
from lmyzmail_blackbox.protocols import (
    BoundedSocket,
    RawSmtpClient,
    _encode_smtp_data,
    read_smtp_reply,
    smtp_data_transaction,
)


def _read_line(connection: socket.socket) -> bytes:
    value = bytearray()
    while not value.endswith(b"\n"):
        chunk = connection.recv(1)
        if not chunk:
            raise AssertionError("client disconnected")
        value.extend(chunk)
    return bytes(value)


def _read_exact(connection: socket.socket, size: int) -> bytes:
    value = bytearray()
    while len(value) < size:
        chunk = connection.recv(size - len(value))
        if not chunk:
            raise AssertionError("client disconnected")
        value.extend(chunk)
    return bytes(value)


def _socket_stream(
    *, max_received: int = 1024, timeout: float = 2.0
) -> tuple[BoundedSocket, socket.socket]:
    client, peer = socket.socketpair()
    return (
        BoundedSocket(
            client,
            deadline=time.monotonic() + timeout,
            max_received=max_received,
        ),
        peer,
    )


class _FakeTlsContext:
    def __init__(self, error: BaseException | None = None) -> None:
        self.error = error
        self.calls: list[tuple[socket.socket, str]] = []

    def wrap_socket(self, sock: socket.socket, *, server_hostname: str) -> socket.socket:
        self.calls.append((sock, server_hostname))
        if self.error is not None:
            raise self.error
        return sock


def _tls_contexts(tmp_path: Path) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "smtp.example.test")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=5))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("smtp.example.test")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    certificate_path = tmp_path / "smtp-cert.pem"
    key_path = tmp_path / "smtp-key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certificate_path, key_path)
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    return client_context, server_context


def test_read_smtp_reply_accepts_only_strict_crlf_multiline_replies() -> None:
    stream, peer = _socket_stream()
    try:
        peer.sendall(b"250-first\r\n250-second\r\n250 done\r\n")
        assert read_smtp_reply(stream) == (
            b"250-first\r\n",
            b"250-second\r\n",
            b"250 done\r\n",
        )
    finally:
        stream.sock.close()
        peer.close()

    invalid_replies = (
        b"199 invalid code\r\n",
        b"250 bare LF\n",
        b"250-first\r\n251 changed\r\n",
        b"250-first\r\n250 second\n",
    )
    for reply in invalid_replies:
        stream, peer = _socket_stream()
        try:
            peer.sendall(reply)
            with pytest.raises(ProtocolError):
                read_smtp_reply(stream)
        finally:
            stream.sock.close()
            peer.close()


def test_read_smtp_reply_enforces_line_and_receive_budgets() -> None:
    stream, peer = _socket_stream()
    try:
        peer.sendall(b"250-first\r\n250 second\r\n")
        with pytest.raises(ProtocolError, match="exceeded 1 lines"):
            read_smtp_reply(stream, max_lines=1)
    finally:
        stream.sock.close()
        peer.close()

    stream, peer = _socket_stream(max_received=5)
    try:
        peer.sendall(b"250 too much\r\n")
        with pytest.raises(ProtocolError, match="receive budget"):
            read_smtp_reply(stream)
    finally:
        stream.sock.close()
        peer.close()

    with pytest.raises(ValueError, match="line budget"):
        stream, peer = _socket_stream()
        try:
            read_smtp_reply(stream, max_lines=0)
        finally:
            stream.sock.close()
            peer.close()


def test_smtp_data_empty_body_is_only_end_of_data_marker() -> None:
    assert _encode_smtp_data(b"") == b".\r\n"


def test_raw_smtp_client_pipelines_and_frames_bdat_without_copying_commands() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = int(listener.getsockname()[1])
    server_errors: Queue[BaseException] = Queue()
    received_chunks: Queue[bytes] = Queue()

    def server() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                connection.sendall(b"220 test ESMTP\r\n")
                assert _read_line(connection) == b"EHLO blackbox.example\r\n"
                connection.sendall(b"250-test\r\n250 PIPELINING\r\n")
                assert [_read_line(connection) for _ in range(3)] == [
                    b"MAIL FROM:<>\r\n",
                    b"RCPT TO:<qa@example.test>\r\n",
                    b"DATA\r\n",
                ]
                connection.sendall(b"250 sender ok\r\n250 recipient ok\r\n354 send body\r\n")
                assert _read_line(connection) == b"Subject: pipelined\r\n"
                assert _read_line(connection) == b"\r\n"
                assert _read_line(connection) == b"..dot-stuffed\r\n"
                assert _read_line(connection) == b".\r\n"
                connection.sendall(b"250 data accepted\r\n")

                assert _read_line(connection) == b"BDAT 5\r\n"
                received_chunks.put(_read_exact(connection, 5))
                connection.sendall(b"250 chunk ok\r\n")
                assert _read_line(connection) == b"BDAT 0 LAST\r\n"
                connection.sendall(b"250 message accepted\r\n")
                assert _read_line(connection) == b"QUIT\r\n"
                connection.sendall(b"221 bye\r\n")
        except BaseException as error:
            server_errors.put(error)

    thread = threading.Thread(target=server)
    thread.start()
    try:
        with RawSmtpClient.connect("127.0.0.1", port) as client:
            assert client.command(b"EHLO blackbox.example") == (
                b"250-test\r\n",
                b"250 PIPELINING\r\n",
            )
            assert client.pipeline(
                (
                    b"MAIL FROM:<>",
                    b"RCPT TO:<qa@example.test>",
                    b"DATA",
                )
            ) == (
                (b"250 sender ok\r\n",),
                (b"250 recipient ok\r\n",),
                (b"354 send body\r\n",),
            )
            assert client.data_body(b"Subject: pipelined\r\n\r\n.dot-stuffed\r\n") == (
                b"250 data accepted\r\n",
            )
            assert client.bdat(b"a\x00b\r\n") == (b"250 chunk ok\r\n",)
            assert client.bdat(b"", last=True) == (b"250 message accepted\r\n",)
            assert client.quit() == (b"221 bye\r\n",)
            with pytest.raises(ProtocolError, match="closed"):
                client.command(b"NOOP")
    finally:
        thread.join(timeout=2)
        listener.close()

    assert not thread.is_alive()
    if not server_errors.empty():
        raise server_errors.get()
    assert received_chunks.get_nowait() == b"a\x00b\r\n"


def test_raw_smtp_client_quit_rejects_buffered_trailing_bytes() -> None:
    stream, peer = _socket_stream()
    peer.sendall(b"220 test ESMTP\r\n")
    greeting = read_smtp_reply(stream)
    client = RawSmtpClient(stream=stream, greeting=greeting)
    server_errors: Queue[BaseException] = Queue()

    def server() -> None:
        try:
            assert _read_line(peer) == b"QUIT\r\n"
            peer.sendall(b"221 bye\r\ntrailing plaintext")
        except BaseException as error:
            server_errors.put(error)
        finally:
            peer.close()

    thread = threading.Thread(target=server)
    thread.start()
    try:
        with pytest.raises(ProtocolError, match="after the 221 reply"):
            client.quit()
        assert client._closed
    finally:
        thread.join(timeout=2)
        client.close()

    assert not thread.is_alive()
    if not server_errors.empty():
        raise server_errors.get()


def test_raw_smtp_client_quit_requires_server_eof_before_closing() -> None:
    stream, peer = _socket_stream(timeout=0.5)
    peer.sendall(b"220 test ESMTP\r\n")
    greeting = read_smtp_reply(stream)
    client = RawSmtpClient(stream=stream, greeting=greeting)
    server_errors: Queue[BaseException] = Queue()
    release_server = threading.Event()

    def server() -> None:
        try:
            assert _read_line(peer) == b"QUIT\r\n"
            peer.sendall(b"221 bye\r\n")
            release_server.wait(timeout=2)
        except BaseException as error:
            server_errors.put(error)
        finally:
            peer.close()

    thread = threading.Thread(target=server)
    thread.start()
    try:
        with pytest.raises(ProtocolError, match="did not close"):
            client.quit()
        assert client._closed
    finally:
        release_server.set()
        thread.join(timeout=2)
        client.close()

    assert not thread.is_alive()
    if not server_errors.empty():
        raise server_errors.get()


def test_raw_smtp_client_rejects_injection_and_unbounded_inputs_before_send() -> None:
    stream, peer = _socket_stream()
    client = RawSmtpClient(stream=stream, greeting=(b"220 test\r\n",))
    try:
        with pytest.raises(ValueError, match="without CR, LF, or NUL"):
            client.pipeline((b"NOOP", b"MAIL FROM:<>\r\nRCPT TO:<victim@example.test>"))
        with pytest.raises(ValueError, match="512-octet"):
            client.command(b"X" * 511)
        with pytest.raises(ValueError, match="100-command"):
            client.pipeline((b"NOOP",) * 101)

        peer.setblocking(False)
        with pytest.raises(BlockingIOError):
            peer.recv(1)
    finally:
        client.close()
        peer.close()


def test_raw_smtp_client_validates_connection_budgets_before_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_connect(*_: object, **__: object) -> socket.socket:
        raise AssertionError("network connection should not be attempted")

    monkeypatch.setattr(socket, "create_connection", unexpected_connect)
    for timeout in (0.0, -1.0, float("inf"), float("nan")):
        with pytest.raises(ValueError, match="timeout"):
            RawSmtpClient.connect("127.0.0.1", 1, timeout=timeout)
    with pytest.raises(ValueError, match="receive budget"):
        RawSmtpClient.connect("127.0.0.1", 1, max_received=0)


def test_raw_smtp_client_start_tls_allows_post_upgrade_ehlo(tmp_path: Path) -> None:
    stream, peer = _socket_stream()
    peer.sendall(b"220 test ESMTP\r\n")
    greeting = read_smtp_reply(stream)
    client = RawSmtpClient(stream=stream, greeting=greeting)
    client_context, server_context = _tls_contexts(tmp_path)
    server_errors: Queue[BaseException] = Queue()

    def server() -> None:
        try:
            assert _read_line(peer) == b"STARTTLS\r\n"
            peer.sendall(b"220 ready for TLS\r\n")
            with server_context.wrap_socket(peer, server_side=True) as tls_peer:
                assert _read_line(tls_peer) == b"EHLO blackbox.example\r\n"
                tls_peer.sendall(b"250-test\r\n250 PIPELINING\r\n")
                assert _read_line(tls_peer) == b"QUIT\r\n"
                tls_peer.sendall(b"221 bye\r\n")
        except BaseException as error:
            server_errors.put(error)
        finally:
            peer.close()

    thread = threading.Thread(target=server)
    thread.start()
    try:
        assert client.start_tls(
            client_context,
            server_hostname="smtp.example.test",
        ) == (b"220 ready for TLS\r\n",)
        assert client.command(b"EHLO blackbox.example") == (
            b"250-test\r\n",
            b"250 PIPELINING\r\n",
        )
        assert client.quit() == (b"221 bye\r\n",)
    finally:
        thread.join(timeout=2)
        client.close()

    assert not thread.is_alive()
    if not server_errors.empty():
        raise server_errors.get()


def test_raw_smtp_client_start_tls_refusal_keeps_connection_open() -> None:
    stream, peer = _socket_stream()
    peer.sendall(b"220 test ESMTP\r\n")
    greeting = read_smtp_reply(stream)
    client = RawSmtpClient(stream=stream, greeting=greeting)
    context = _FakeTlsContext()
    server_errors: Queue[BaseException] = Queue()

    def server() -> None:
        try:
            assert _read_line(peer) == b"STARTTLS\r\n"
            peer.sendall(b"454 TLS temporarily unavailable\r\n")
            assert _read_line(peer) == b"NOOP\r\n"
            peer.sendall(b"250 noop\r\n")
            assert _read_line(peer) == b"QUIT\r\n"
            peer.sendall(b"221 bye\r\n")
        except BaseException as error:
            server_errors.put(error)
        finally:
            peer.close()

    thread = threading.Thread(target=server)
    thread.start()
    try:
        with pytest.raises(ProtocolError, match="STARTTLS was not accepted"):
            client.start_tls(
                cast(ssl.SSLContext, context),
                server_hostname="smtp.example.test",
            )
        assert not client._closed
        assert context.calls == []
        assert client.command(b"NOOP") == (b"250 noop\r\n",)
        assert client.quit() == (b"221 bye\r\n",)
    finally:
        thread.join(timeout=2)
        client.close()

    assert not thread.is_alive()
    if not server_errors.empty():
        raise server_errors.get()


def test_raw_smtp_client_start_tls_rejects_buffered_plaintext() -> None:
    stream, peer = _socket_stream()
    peer.sendall(b"220 test ESMTP\r\n")
    greeting = read_smtp_reply(stream)
    client = RawSmtpClient(stream=stream, greeting=greeting)
    context = _FakeTlsContext()
    server_errors: Queue[BaseException] = Queue()

    def server() -> None:
        try:
            assert _read_line(peer) == b"STARTTLS\r\n"
            peer.sendall(b"220 ready for TLS\r\nunexpected plaintext")
        except BaseException as error:
            server_errors.put(error)
        finally:
            peer.close()

    thread = threading.Thread(target=server)
    thread.start()
    try:
        with pytest.raises(ProtocolError, match="plaintext bytes remained"):
            client.start_tls(
                cast(ssl.SSLContext, context),
                server_hostname="smtp.example.test",
            )
        assert client._closed
        assert context.calls == []
    finally:
        thread.join(timeout=2)
        client.close()

    assert not thread.is_alive()
    if not server_errors.empty():
        raise server_errors.get()


def test_raw_smtp_client_start_tls_handshake_failure_closes_socket() -> None:
    stream, peer = _socket_stream()
    peer.sendall(b"220 test ESMTP\r\n")
    greeting = read_smtp_reply(stream)
    client = RawSmtpClient(stream=stream, greeting=greeting)
    context = _FakeTlsContext(ssl.SSLError("TLS handshake failed"))
    server_errors: Queue[BaseException] = Queue()

    def server() -> None:
        try:
            assert _read_line(peer) == b"STARTTLS\r\n"
            peer.sendall(b"220 ready for TLS\r\n")
            assert peer.recv(1) == b""
        except BaseException as error:
            server_errors.put(error)
        finally:
            peer.close()

    thread = threading.Thread(target=server)
    thread.start()
    try:
        with pytest.raises(ssl.SSLError, match="TLS handshake failed"):
            client.start_tls(
                cast(ssl.SSLContext, context),
                server_hostname="smtp.example.test",
            )
        assert client._closed
        assert stream.sock.fileno() == -1
        assert len(context.calls) == 1
    finally:
        thread.join(timeout=2)
        client.close()

    assert not thread.is_alive()
    if not server_errors.empty():
        raise server_errors.get()


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
