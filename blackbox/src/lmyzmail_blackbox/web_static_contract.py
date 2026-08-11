from __future__ import annotations

from typing import Any

from .differential import RuntimeTarget, Scenario
from .protocols import http_exchange
from .snapshots import http_bytes_snapshot

_CASES = (
    ("index", "GET", "/"),
    ("index-alias", "GET", "/index.html"),
    ("index-query", "GET", "/index.html?cache=1"),
    ("cringe", "GET", "/cringe.html"),
    ("favicon", "GET", "/favicon.ico"),
    (
        "badge",
        "GET",
        "/images/embed-badge-emailtest-internet.nl.svg",
    ),
    ("missing-image", "GET", "/images/missing.svg"),
    ("encoded-traversal", "GET", "/%2e%2e/application.properties"),
    ("literal-traversal", "GET", "/../application.properties"),
    ("prefixed-traversal", "GET", "/assets/../application.properties"),
    ("wrong-method", "POST", "/"),
)


def capture_web_static_matrix(target: RuntimeTarget) -> dict[str, Any]:
    if target.ports is None:
        raise AssertionError("runtime ports are unavailable")
    cases: list[dict[str, Any]] = []
    for name, method, path in _CASES:
        response = http_exchange("127.0.0.1", target.ports.http, method, path)
        snapshot = http_bytes_snapshot(response)
        body = snapshot["body"]
        if not isinstance(body, dict):
            raise AssertionError(f"invalid static snapshot body for {name!r}")
        body.pop("base64")
        cases.append(
            {
                "name": name,
                "method": method,
                "path": path,
                "response": snapshot,
            }
        )
    return {"cases": cases}


WEB_STATIC_SCENARIOS = (
    Scenario(
        "http/static/embedded-assets",
        capture_web_static_matrix,
        normalizers=("header:date:http-date",),
        contract={
            "protocol": "HTTP/1.1 raw sockets",
            "case_count": len(_CASES),
            "resources": [
                "/",
                "/index.html",
                "/cringe.html",
                "/favicon.ico",
                "/images/embed-badge-emailtest-internet.nl.svg",
            ],
            "routing": [
                "query-string handling",
                "missing static resources",
                "unsupported methods",
            ],
            "security": [
                "percent-encoded traversal",
                "literal traversal",
                "static-prefix traversal",
            ],
            "comparison": "status line, ordered headers, body length, and SHA-256",
        },
    ),
)
