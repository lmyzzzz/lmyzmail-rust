from __future__ import annotations

import socket
import time

import pytest

from lmyzmail_blackbox.errors import ProtocolError
from lmyzmail_blackbox.htcpcp_contract import _xml_snapshot
from lmyzmail_blackbox.protocols import BoundedSocket, RawHttpResponse, read_http_response


def _stream(payload: bytes, *, max_received: int = 4096) -> tuple[BoundedSocket, socket.socket]:
    client, server = socket.socketpair()
    server.sendall(payload)
    return (
        BoundedSocket(client, deadline=time.monotonic() + 1.0, max_received=max_received),
        server,
    )


def test_persistent_response_reader_preserves_pipelined_bytes() -> None:
    payload = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none"
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo"
    )
    stream, server = _stream(payload)
    try:
        first = read_http_response(stream, request_method="GET")
        second = read_http_response(stream, request_method="GET")
    finally:
        stream.sock.close()
        server.close()
    assert first.body == b"one"
    assert second.body == b"two"


def test_persistent_response_reader_enforces_header_and_body_bounds() -> None:
    stream, server = _stream(b"HTTP/1.1 200 OK\r\nX-Fill: " + b"x" * 128)
    try:
        with pytest.raises(ProtocolError, match="delimiter was not found"):
            read_http_response(stream, request_method="GET", max_header_bytes=64)
    finally:
        stream.sock.close()
        server.close()

    stream, server = _stream(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
    try:
        with pytest.raises(ProtocolError, match="exceeded body budget"):
            read_http_response(stream, request_method="GET", max_body_bytes=4)
    finally:
        stream.sock.close()
        server.close()


def test_persistent_response_reader_rejects_ambiguous_framing() -> None:
    payloads = (
        b"HTTP/1.1 200 OK\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    )
    for payload in payloads:
        stream, server = _stream(payload)
        try:
            with pytest.raises(ProtocolError):
                read_http_response(stream, request_method="GET")
        finally:
            stream.sock.close()
            server.close()


def test_propfind_snapshot_rejects_xml_declarations_with_entity_expansion() -> None:
    body = b'<!DOCTYPE x [<!ENTITY boom "expanded">]><x>&boom;</x>'
    response = RawHttpResponse(
        status_line=b"HTTP/1.1 207 Multi-Status",
        status_code=207,
        headers=((b"content-length", str(len(body)).encode("ascii")),),
        body=body,
        raw=b"",
    )
    with pytest.raises(ProtocolError, match="forbidden XML declaration"):
        _xml_snapshot(response)
