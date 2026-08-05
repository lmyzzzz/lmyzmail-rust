from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import cast

from .errors import ProtocolError
from .normalize import FieldRule, JsonValue, normalize_http_date_value, normalize_json
from .protocols import RawHttpResponse


@dataclass(frozen=True, slots=True)
class HeaderRule:
    name: bytes
    normalize: Callable[[bytes], bytes]


def bytes_snapshot(value: bytes) -> dict[str, JsonValue]:
    return {
        "length": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
        "base64": base64.b64encode(value).decode("ascii"),
    }


def _header_snapshot(
    response: RawHttpResponse,
    *,
    rules: Sequence[HeaderRule] = (),
    content_length_override: int | None = None,
) -> list[JsonValue]:
    result: list[JsonValue] = []
    for name, value in response.headers:
        normalized = normalize_http_date_value(value) if name.lower() == b"date" else value
        if name.lower() == b"content-length" and content_length_override is not None:
            normalized = str(content_length_override).encode("ascii")
        for rule in rules:
            if name.lower() == rule.name.lower():
                normalized = rule.normalize(normalized)
        result.append(
            [
                name.decode("ascii", errors="strict"),
                normalized.decode("latin-1", errors="strict"),
            ]
        )
    return result


def http_bytes_snapshot(
    response: RawHttpResponse,
    *,
    header_rules: Sequence[HeaderRule] = (),
) -> dict[str, JsonValue]:
    return {
        "status_line": response.status_line.decode("ascii", errors="strict"),
        "status_code": response.status_code,
        "headers": _header_snapshot(response, rules=header_rules),
        "body": bytes_snapshot(response.body),
    }


def http_json_snapshot(
    response: RawHttpResponse,
    *,
    rules: Sequence[FieldRule] = (),
    header_rules: Sequence[HeaderRule] = (),
    canonicalize_object_order: bool = False,
) -> dict[str, JsonValue]:
    try:
        parsed = json.loads(response.body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtocolError("HTTP response body was not UTF-8 JSON") from error
    if not isinstance(parsed, type(None) | bool | int | float | str | list | dict):
        raise ProtocolError("HTTP response body was not a JSON value")
    value = cast(JsonValue, parsed)
    compact = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if compact != response.body:
        raise ProtocolError("HTTP JSON body was not encoded in the compact oracle format")

    normalized = normalize_json(value, rules)
    if canonicalize_object_order:
        normalized = _canonicalize_object_order(normalized)
    normalized_wire = json.dumps(
        normalized,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "status_line": response.status_line.decode("ascii", errors="strict"),
        "status_code": response.status_code,
        "headers": _header_snapshot(
            response,
            rules=header_rules,
            content_length_override=len(normalized_wire) if rules else None,
        ),
        "body_json": normalized,
        "normalized_body_wire": bytes_snapshot(normalized_wire),
    }


def _canonicalize_object_order(value: JsonValue) -> JsonValue:
    if isinstance(value, dict):
        return {key: _canonicalize_object_order(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_canonicalize_object_order(item) for item in value]
    return value
