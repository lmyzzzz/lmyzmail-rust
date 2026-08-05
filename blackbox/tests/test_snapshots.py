from __future__ import annotations

import pytest

from lmyzmail_blackbox.errors import ProtocolError
from lmyzmail_blackbox.normalize import FieldRule, constant
from lmyzmail_blackbox.protocols import parse_http_response
from lmyzmail_blackbox.snapshots import HeaderRule, http_bytes_snapshot, http_json_snapshot


def test_byte_snapshot_preserves_header_and_body_wire_facts() -> None:
    response = parse_http_response(
        b"HTTP/1.1 200 OK\r\n"
        b"Date: Tue, 05 Aug 2026 12:00:00 GMT\r\n"
        b"X-Order: first\r\n"
        b"X-Order: second\r\n"
        b"Content-Length: 3\r\n\r\n"
        b"\x00\xffx"
    )

    snapshot = http_bytes_snapshot(response)

    assert snapshot["headers"] == [
        ["Date", "<http-date>"],
        ["X-Order", "first"],
        ["X-Order", "second"],
        ["Content-Length", "3"],
    ]
    assert snapshot["body"] == {
        "length": 3,
        "sha256": "3921e9d98be578053d67a667b4243aba8dc03e1c8fbcd8d747a8fec62cc7536a",
        "base64": "AP94",
    }


def test_json_snapshot_normalizes_only_selected_field_and_keeps_key_order() -> None:
    response = parse_http_response(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Content-Length: 49\r\n\r\n"
        b'{"token":"random","message":"token=random stays"}'
    )

    snapshot = http_json_snapshot(
        response,
        rules=[FieldRule(("token",), constant("<token>"))],
    )

    assert snapshot["body_json"] == {
        "token": "<token>",
        "message": "token=random stays",
    }


def test_json_snapshot_rejects_pretty_printed_or_reordered_whitespace() -> None:
    response = parse_http_response(
        b'HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{\n  "ok": 1\n}',
    )

    with pytest.raises(ProtocolError, match="compact oracle format"):
        http_json_snapshot(response)


def test_json_snapshot_normalizes_named_header_and_derived_content_length() -> None:
    response = parse_http_response(
        b"HTTP/1.1 200 OK\r\n"
        b"Access-Control-Allow-Origin: http://127.0.0.1:32123\r\n"
        b"Content-Length: 18\r\n\r\n"
        b'{"token":"random"}',
    )

    snapshot = http_json_snapshot(
        response,
        rules=[FieldRule(("token",), constant("<token>"))],
        header_rules=[HeaderRule(b"access-control-allow-origin", lambda _: b"<allowed-origin>")],
    )

    assert snapshot["headers"] == [
        ["Access-Control-Allow-Origin", "<allowed-origin>"],
        ["Content-Length", "19"],
    ]


def test_json_object_order_is_canonicalized_only_when_explicitly_enabled() -> None:
    response = parse_http_response(
        b'HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\n{"z":1,"nested":{"b":2,"a":1}}',
    )

    ordered = http_json_snapshot(response, canonicalize_object_order=True)

    assert ordered["body_json"] == {"nested": {"a": 1, "b": 2}, "z": 1}
