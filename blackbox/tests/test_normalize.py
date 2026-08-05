from lmyzmail_blackbox.normalize import (
    FieldRule,
    JsonValue,
    constant,
    normalize_http_date_header,
    normalize_json,
)


def test_json_normalization_is_limited_to_named_field() -> None:
    source: JsonValue = {
        "timestamp": "2026-08-05T12:00:00Z",
        "message": "timestamp=2026-08-05T12:00:00Z must remain",
    }

    normalized = normalize_json(
        source,
        [FieldRule(("timestamp",), constant("<timestamp>"))],
    )

    assert normalized == {
        "timestamp": "<timestamp>",
        "message": "timestamp=2026-08-05T12:00:00Z must remain",
    }


def test_http_date_normalizer_never_touches_body() -> None:
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Date: Tue, 05 Aug 2026 12:00:00 GMT\r\n"
        b"Content-Length: 35\r\n\r\n"
        b"Date: Tue, 05 Aug 2026 12:00:00 GMT"
    )

    normalized = normalize_http_date_header(response)

    assert b"Date: <http-date>" in normalized.split(b"\r\n\r\n", 1)[0]
    assert normalized.endswith(b"Date: Tue, 05 Aug 2026 12:00:00 GMT")
