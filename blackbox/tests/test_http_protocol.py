from __future__ import annotations

import socket
import threading
from queue import Queue

import pytest

from lmyzmail_blackbox.errors import ProtocolError
from lmyzmail_blackbox.protocols import (
    build_http_request,
    http_exchange,
    parse_http_response,
)


def test_http_exchange_preserves_wire_headers_and_decodes_chunks() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = int(listener.getsockname()[1])
    server_errors: Queue[BaseException] = Queue()

    def server() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    request.extend(connection.recv(4096))
                assert request.startswith(b"GET /wire?q=1 HTTP/1.1\r\n")
                assert b"Connection: close\r\n" in request
                connection.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"X-Repeated: first\r\n"
                    b"X-Repeated: second\r\n"
                    b"Transfer-Encoding: chunked\r\n\r\n"
                    b"4;extension=yes\r\ntest\r\n"
                    b"3\r\n123\r\n"
                    b"0\r\nX-Trailer: kept-on-wire\r\n\r\n"
                )
        except BaseException as error:
            server_errors.put(error)

    thread = threading.Thread(target=server)
    thread.start()
    try:
        response = http_exchange("127.0.0.1", port, "GET", "/wire?q=1")
    finally:
        thread.join(timeout=2)
        listener.close()

    assert not thread.is_alive()
    if not server_errors.empty():
        raise server_errors.get()
    assert response.status_line == b"HTTP/1.1 200 OK"
    assert response.status_code == 200
    assert response.header_values(b"x-repeated") == (b"first", b"second")
    assert response.body == b"test123"
    assert response.raw.endswith(b"X-Trailer: kept-on-wire\r\n\r\n")


@pytest.mark.parametrize(
    ("headers", "target"),
    [
        ((("X-Test", "ok\r\nInjected: yes"),), "/"),
        ((), "/ok\r\nInjected: yes"),
    ],
)
def test_http_request_rejects_crlf_injection(
    headers: tuple[tuple[str, str], ...], target: str
) -> None:
    with pytest.raises(ValueError, match="CR or LF"):
        build_http_request("GET", target, host="example.test", headers=headers)


def test_http_parser_rejects_content_length_mismatch() -> None:
    with pytest.raises(ProtocolError, match="body length mismatch"):
        parse_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc",
        )


def test_http_request_rejects_ambiguous_or_incorrect_framing() -> None:
    with pytest.raises(ValueError, match="both Transfer-Encoding and Content-Length"):
        build_http_request(
            "POST",
            "/",
            host="example.test",
            headers=(("Transfer-Encoding", "chunked"), ("Content-Length", "4")),
            body=b"test",
        )
    with pytest.raises(ValueError, match="does not match"):
        build_http_request(
            "POST",
            "/",
            host="example.test",
            headers=(("Content-Length", "3"),),
            body=b"test",
        )
