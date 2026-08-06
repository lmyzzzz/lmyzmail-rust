from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.normalize import FieldRule, constant
from lmyzmail_blackbox.protocols import http_exchange
from lmyzmail_blackbox.runtime import (
    API_KEY,
    QA_ADDRESS,
    QA_PASSWORD,
    READ_ONLY_API_KEY,
    WRITE_ONLY_API_KEY,
    JavaOracleRuntime,
)
from lmyzmail_blackbox.smtp_contract import SMTP_SCENARIOS
from lmyzmail_blackbox.snapshots import (
    HeaderRule,
    http_bytes_snapshot,
    http_json_snapshot,
)


def _ports(target: RuntimeTarget) -> tuple[str, int]:
    assert target.ports is not None
    return "127.0.0.1", target.ports.http


def _capture_json(
    method: str,
    path: str,
    *,
    request_json: Any | None = None,
    headers: tuple[tuple[str, str], ...] = (),
    rules: tuple[FieldRule, ...] = (),
    header_rules: tuple[HeaderRule, ...] = (),
    canonicalize_object_order: bool = False,
) -> Callable[[RuntimeTarget], dict[str, Any]]:
    def capture(target: RuntimeTarget) -> dict[str, Any]:
        host, port = _ports(target)
        body = b""
        request_headers = list(headers)
        if request_json is not None:
            body = json.dumps(
                request_json,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            request_headers.append(("Content-Type", "application/json"))
        response = http_exchange(
            host,
            port,
            method,
            path,
            headers=request_headers,
            body=body,
        )
        return http_json_snapshot(
            response,
            rules=rules,
            header_rules=header_rules,
            canonicalize_object_order=canonicalize_object_order,
        )

    cast(Any, capture).__lmyzmail_contract__ = {
        "protocol": "http",
        "method": method,
        "target": path,
        "headers": [list(header) for header in headers],
        "json": request_json,
    }
    return capture


def _capture_bytes(
    method: str,
    path: str,
    *,
    headers: tuple[tuple[str, str], ...] = (),
    header_rules: tuple[HeaderRule, ...] = (),
    omit_body_base64: bool = False,
) -> Callable[[RuntimeTarget], dict[str, Any]]:
    def capture(target: RuntimeTarget) -> dict[str, Any]:
        host, port = _ports(target)
        response = http_exchange(host, port, method, path, headers=headers)
        snapshot = http_bytes_snapshot(response, header_rules=header_rules)
        if omit_body_base64:
            body = snapshot["body"]
            assert isinstance(body, dict)
            body.pop("base64")
        return snapshot

    cast(Any, capture).__lmyzmail_contract__ = {
        "protocol": "http",
        "method": method,
        "target": path,
        "headers": [list(header) for header in headers],
        "body": "empty",
    }
    return capture


def _allowed_cors_capture(target: RuntimeTarget) -> dict[str, Any]:
    assert target.ports is not None
    origin = f"http://127.0.0.1:{target.ports.http}"
    response = http_exchange(
        "127.0.0.1",
        target.ports.http,
        "OPTIONS",
        "/api/status",
        headers=(
            ("Origin", origin),
            ("Access-Control-Request-Method", "POST"),
        ),
    )
    return http_bytes_snapshot(
        response,
        header_rules=(HeaderRule(b"access-control-allow-origin", lambda _: b"<allowed-origin>"),),
    )


cast(Any, _allowed_cors_capture).__lmyzmail_contract__ = {
    "protocol": "http",
    "method": "OPTIONS",
    "target": "/api/status",
    "headers": [
        ["Origin", "<allowed-origin:ephemeral-port>"],
        ["Access-Control-Request-Method", "POST"],
    ],
    "body": "empty",
}


TIMESTAMP_RULES = (FieldRule(("timestamp",), constant("<timestamp>")),)
TOKEN_RULES = (FieldRule(("token",), constant("<session-token>")),)
DATE_NORMALIZER = ("header:date:http-date",)
MAP_OF_NORMALIZER = ("json-object-order:jdk-map-of",)


def _materialize_route(path: str) -> str:
    replacements = {
        "{address}": QA_ADDRESS,
        "{domain}": "example.invalid",
        "{file}": "missing.eml",
        "{fileName}": "missing.eml",
        "{folder}": "inbox",
        "{id}": "1",
        "{index}": "0",
        "{ipAddress}": "203.0.113.77",
        "{labelId}": "1",
        "{messageId}": "missing-message",
        "{minScore}": "1",
        "{queueId}": "1",
    }
    for name, value in replacements.items():
        path = path.replace(name, value)
    assert "{" not in path and "}" not in path
    return path


def _route_permission_matrix(target: RuntimeTarget) -> dict[str, Any]:
    repository = Path(__file__).resolve().parents[2]
    manifest_path = repository / "blackbox/manifests/http-routes.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    host, port = _ports(target)
    observations: list[dict[str, Any]] = []
    for route in manifest["routes"]:
        auth = route["auth"]
        if auth == "public":
            continue
        method = route["method"]
        path = _materialize_route(route["path"])
        headers: list[tuple[str, str]] = []
        body = b""
        if auth == "api_read":
            headers.append(("X-API-Key", WRITE_ONLY_API_KEY))
            expected_status = 403
        elif auth == "api_write":
            headers.append(("X-API-Key", READ_ONLY_API_KEY))
            expected_status = 403
        else:
            expected_status = 401
            if path == "/web/mail/send/multipart":
                headers.append(("Content-Type", "multipart/form-data; boundary=blackbox"))
                body = b"--blackbox--\r\n"
            elif method in {"POST", "PUT"}:
                headers.append(("Content-Type", "application/json"))
                body = b"{}"
        response = http_exchange(
            host,
            port,
            method,
            path,
            headers=headers,
            body=body,
            timeout=10.0,
        )
        assert response.status_code == expected_status, (
            route,
            response.status_line,
            response.body[:500],
        )
        content_types = response.header_values(b"content-type")
        if response.body and any(b"application/json" in value for value in content_types):
            snapshot = http_json_snapshot(response, canonicalize_object_order=True)
        else:
            snapshot = http_bytes_snapshot(response)
        observations.append(
            {
                "controller": route["controller"],
                "method": method,
                "path": route["path"],
                "auth": auth,
                "response": snapshot,
            }
        )
    return {"route_count": len(observations), "routes": observations}


_ROUTE_MANIFEST = Path(__file__).resolve().parents[2] / "blackbox/manifests/http-routes.json"
with _ROUTE_MANIFEST.open("rb") as _route_manifest_stream:
    _ROUTE_MANIFEST_SHA256 = hashlib.file_digest(_route_manifest_stream, "sha256").hexdigest()
cast(Any, _route_permission_matrix).__lmyzmail_contract__ = {
    "protocol": "http",
    "operation": "route-auth-permission-matrix",
    "manifest_sha256": _ROUTE_MANIFEST_SHA256,
    "session_strategy": "missing-token-must-match-route-and-return-401",
    "api_strategy": "opposite-permission-key-must-match-route-and-return-403",
}


def _skibidi_variant(target: RuntimeTarget) -> dict[str, Any]:
    repository = Path(__file__).resolve().parents[2]
    lore_path = repository / "blackbox/manifests/skibidi-lore.json"
    lore_manifest = json.loads(lore_path.read_text(encoding="utf-8"))
    lore = set(lore_manifest["lore"])
    host, port = _ports(target)
    response = http_exchange(host, port, "GET", "/api/skibidi")
    payload = json.loads(response.body)
    assert response.header_values(b"content-type") == (b"application/json; charset=UTF-8",)
    assert set(payload) in (
        {"status", "message", "timestamp"},
        {"status", "lore", "timestamp"},
    )
    timestamp = datetime.fromisoformat(payload["timestamp"].replace("Z", "+00:00"))
    assert abs((datetime.now(UTC) - timestamp).total_seconds()) < 30.0
    if response.status_code == 418:
        assert payload == {
            "status": "teapot",
            "message": "I'm a teapot",
            "timestamp": payload["timestamp"],
        }
    else:
        assert response.status_code == 200
        assert payload["status"] == "skibidi"
        assert payload["lore"] in lore
    return {
        "accepted_status_codes": [200, 418],
        "accepted_variants": ["lore-member", "teapot"],
        "lore_count": len(lore),
        "lore_manifest_sha256": hashlib.sha256(lore_path.read_bytes()).hexdigest(),
        "timestamp_contract": "current-utc-within-30s",
    }


_SKIBIDI_LORE_PATH = Path(__file__).resolve().parents[2] / "blackbox/manifests/skibidi-lore.json"
cast(Any, _skibidi_variant).__lmyzmail_contract__ = {
    "protocol": "http",
    "method": "GET",
    "target": "/api/skibidi",
    "random_contract": "teapot-or-member-of-frozen-233-lore-set",
    "lore_manifest_sha256": hashlib.sha256(_SKIBIDI_LORE_PATH.read_bytes()).hexdigest(),
}

HTTP_SCENARIOS = (
    Scenario(
        "http/public/health",
        _capture_json("GET", "/api/health", rules=TIMESTAMP_RULES),
        DATE_NORMALIZER + ("json:timestamp", "header:content-length:normalized-json"),
    ),
    Scenario(
        "http/public/skibidi-variant",
        _skibidi_variant,
        ("random:/api/skibidi:documented-variant-set", "json:timestamp"),
    ),
    Scenario(
        "http/api/missing-key",
        _capture_json("POST", "/api/status", request_json={}, canonicalize_object_order=True),
        DATE_NORMALIZER + MAP_OF_NORMALIZER,
    ),
    Scenario(
        "http/api/wrong-key",
        _capture_json(
            "POST",
            "/api/status",
            request_json={},
            headers=(("X-API-Key", "wrong-key"),),
            canonicalize_object_order=True,
        ),
        DATE_NORMALIZER + MAP_OF_NORMALIZER,
    ),
    Scenario(
        "http/api/status",
        _capture_json(
            "POST",
            "/api/status",
            request_json={},
            headers=(("X-API-Key", API_KEY),),
            rules=TIMESTAMP_RULES,
        ),
        DATE_NORMALIZER + ("json:timestamp", "header:content-length:normalized-json"),
    ),
    Scenario(
        "http/api/unknown-before-routing",
        _capture_json("GET", "/api/does-not-exist", canonicalize_object_order=True),
        DATE_NORMALIZER + MAP_OF_NORMALIZER,
    ),
    Scenario(
        "http/routing/not-found",
        _capture_json("GET", "/does-not-exist", canonicalize_object_order=True),
        DATE_NORMALIZER + MAP_OF_NORMALIZER,
    ),
    Scenario(
        "http/routing/wrong-method-is-not-found",
        _capture_json("POST", "/api/health", request_json={}, canonicalize_object_order=True),
        DATE_NORMALIZER + MAP_OF_NORMALIZER,
    ),
    Scenario(
        "http/cors/allowed-preflight",
        _allowed_cors_capture,
        DATE_NORMALIZER + ("header:access-control-allow-origin:ephemeral-port",),
    ),
    Scenario(
        "http/cors/rejected-preflight",
        _capture_json(
            "OPTIONS",
            "/api/status",
            headers=(("Origin", "https://evil.example"),),
            canonicalize_object_order=True,
        ),
        DATE_NORMALIZER + MAP_OF_NORMALIZER,
    ),
    Scenario(
        "http/web/login-success",
        _capture_json(
            "POST",
            "/web/login",
            request_json={"address": QA_ADDRESS, "password": QA_PASSWORD},
            rules=TOKEN_RULES,
        ),
        DATE_NORMALIZER + ("json:session-token", "header:content-length:normalized-json"),
    ),
    Scenario(
        "http/web/login-invalid",
        _capture_json(
            "POST",
            "/web/login",
            request_json={"address": QA_ADDRESS, "password": "wrong-password"},
            canonicalize_object_order=True,
        ),
        DATE_NORMALIZER + MAP_OF_NORMALIZER,
    ),
    Scenario(
        "http/web/register-existing",
        _capture_json(
            "POST",
            "/web/register",
            request_json={"address": QA_ADDRESS, "password": QA_PASSWORD},
            canonicalize_object_order=True,
        ),
        DATE_NORMALIZER + MAP_OF_NORMALIZER,
    ),
    Scenario(
        "http/web/logout-without-token",
        _capture_json("POST", "/web/logout", request_json={}, canonicalize_object_order=True),
        DATE_NORMALIZER + MAP_OF_NORMALIZER,
    ),
    Scenario(
        "http/web/domains",
        _capture_json("GET", "/web/domains", canonicalize_object_order=True),
        DATE_NORMALIZER + MAP_OF_NORMALIZER,
    ),
    Scenario(
        "http/web/config",
        _capture_json("GET", "/web/config", canonicalize_object_order=True),
        DATE_NORMALIZER + MAP_OF_NORMALIZER,
    ),
    Scenario(
        "http/static/index",
        _capture_bytes("GET", "/", omit_body_base64=True),
        DATE_NORMALIZER,
    ),
    Scenario(
        "http/static/index-alias",
        _capture_bytes("GET", "/index.html", omit_body_base64=True),
        DATE_NORMALIZER,
    ),
    Scenario(
        "http/static/cringe",
        _capture_bytes("GET", "/cringe.html", omit_body_base64=True),
        DATE_NORMALIZER,
    ),
    Scenario(
        "http/static/favicon",
        _capture_bytes("GET", "/favicon.ico", omit_body_base64=True),
        DATE_NORMALIZER,
    ),
    Scenario(
        "http/static/path-traversal",
        _capture_json("GET", "/%2e%2e/application.properties", canonicalize_object_order=True),
        DATE_NORMALIZER + MAP_OF_NORMALIZER,
    ),
    Scenario(
        "http/routes/auth-permission-matrix",
        _route_permission_matrix,
        DATE_NORMALIZER + MAP_OF_NORMALIZER,
    ),
)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_all_protected_routes_reach_their_declared_auth_boundary() -> None:
    with JavaOracleRuntime() as oracle:
        observation = _route_permission_matrix(oracle)

    assert observation["route_count"] == 65


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.timeout(180)
def test_managed_java_http_and_smtp_golden(record_java_golden: bool) -> None:
    paths = JavaOracleRuntime().paths
    runner = DifferentialRunner(
        paths.repository,
        paths.repository / "blackbox/golden/java/managed-basic-v32",
        "managed-basic",
        record_java=record_java_golden,
    )
    scenarios = HTTP_SCENARIOS + SMTP_SCENARIOS
    with JavaOracleRuntime(paths=paths) as oracle:
        if record_java_golden:
            runner.record_from_java(scenarios, oracle)
        else:
            runner.verify_java(scenarios, oracle)
