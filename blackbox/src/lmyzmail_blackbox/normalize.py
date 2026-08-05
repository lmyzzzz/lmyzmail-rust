from __future__ import annotations

import copy
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]


@dataclass(frozen=True, slots=True)
class FieldRule:
    path: tuple[str | int, ...]
    normalize: Callable[[JsonValue], JsonValue]


def constant(value: JsonValue) -> Callable[[JsonValue], JsonValue]:
    return lambda _: value


def normalize_json(value: JsonValue, rules: Sequence[FieldRule]) -> JsonValue:
    result = copy.deepcopy(value)
    for rule in rules:
        cursor: Any = result
        for component in rule.path[:-1]:
            if isinstance(component, int):
                if not isinstance(cursor, list) or component >= len(cursor):
                    raise KeyError(f"normalization path absent: {rule.path!r}")
            elif not isinstance(cursor, Mapping) or component not in cursor:
                raise KeyError(f"normalization path absent: {rule.path!r}")
            cursor = cursor[component]
        leaf = rule.path[-1]
        if isinstance(leaf, int):
            if not isinstance(cursor, list) or leaf >= len(cursor):
                raise KeyError(f"normalization path absent: {rule.path!r}")
        elif not isinstance(cursor, dict) or leaf not in cursor:
            raise KeyError(f"normalization path absent: {rule.path!r}")
        cursor[leaf] = rule.normalize(cursor[leaf])
    return result


_HTTP_DATE_LINE = re.compile(
    rb"(?i)^(date:\s*)[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} "
    rb"\d{2}:\d{2}:\d{2} GMT$"
)
_HTTP_DATE_VALUE = re.compile(rb"^[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT$")


def normalize_http_date_value(value: bytes) -> bytes:
    if _HTTP_DATE_VALUE.fullmatch(value):
        return b"<http-date>"
    return value


def normalize_http_date_header(response: bytes) -> bytes:
    """Normalize only a syntactically valid HTTP Date field, never body bytes."""

    separator = response.find(b"\r\n\r\n")
    if separator < 0:
        return response
    head = response[:separator]
    body = response[separator:]
    normalized_lines = [
        _HTTP_DATE_LINE.sub(rb"\1<http-date>", line) for line in head.split(b"\r\n")
    ]
    return b"\r\n".join(normalized_lines) + body
