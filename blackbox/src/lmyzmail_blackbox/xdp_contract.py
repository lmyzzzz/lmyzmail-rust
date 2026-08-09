from __future__ import annotations

from typing import Any, cast

from .differential import RuntimeTarget, Scenario
from .protocols import http_exchange
from .runtime import API_KEY
from .snapshots import http_bytes_snapshot, http_json_snapshot

_AUTH = (("X-API-Key", API_KEY),)
_NORMALIZERS = ("header:date:http-date", "json-object-order:jdk-map-of")


def _ports(target: RuntimeTarget) -> tuple[str, int]:
    if target.ports is None:
        raise AssertionError("XDP target is not started")
    return "127.0.0.1", target.ports.http


def _json(
    target: RuntimeTarget,
    method: str,
    path: str,
    *,
    status: int = 200,
) -> dict[str, Any]:
    host, port = _ports(target)
    response = http_exchange(host, port, method, path, headers=_AUTH)
    if response.status_code != status:
        raise AssertionError(
            f"XDP response status changed for {method} {path}: "
            f"{response.status_line!r}, body={response.body!r}"
        )
    return http_json_snapshot(response, canonicalize_object_order=True)


def capture_disabled_xdp_control_plane(target: RuntimeTarget) -> dict[str, Any]:
    host, port = _ports(target)
    stats = http_exchange(host, port, "GET", "/api/xdp-firewall/stats", headers=_AUTH)
    if stats.status_code != 404:
        raise AssertionError(
            f"disabled XDP stats status changed: {stats.status_line!r}, body={stats.body!r}"
        )
    return {
        "status": _json(target, "GET", "/api/xdp-firewall/status"),
        "ban": _json(
            target,
            "POST",
            "/api/xdp-firewall/ban?ip=203.0.113.77&reason=6",
        ),
        "unban": _json(
            target,
            "POST",
            "/api/xdp-firewall/unban?ip=203.0.113.77",
        ),
        "check": _json(
            target,
            "GET",
            "/api/xdp-firewall/check?ip=203.0.113.77",
        ),
        "whitelist": _json(
            target,
            "GET",
            "/api/xdp-firewall/whitelist/check?ip=127.0.0.1",
        ),
        "sync": _json(target, "POST", "/api/xdp-firewall/sync"),
        "clear": _json(target, "DELETE", "/api/xdp-firewall/clear"),
        "stats": http_bytes_snapshot(stats),
    }


cast(Any, capture_disabled_xdp_control_plane).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket",
    "authentication": "admin API key",
    "configuration": "botmail.xdp.enabled=false",
    "coverage": [
        "status",
        "IPv4 ban and unban",
        "ban and whitelist checks",
        "database synchronization",
        "clear all",
        "unavailable statistics",
    ],
}


def capture_xdp_parameter_errors(target: RuntimeTarget) -> dict[str, Any]:
    requests = (
        ("banMissingIp", "POST", "/api/xdp-firewall/ban", 200),
        (
            "banInvalidReason",
            "POST",
            "/api/xdp-firewall/ban?ip=203.0.113.77&reason=nope",
            500,
        ),
        ("unbanMissingIp", "POST", "/api/xdp-firewall/unban", 200),
        ("checkMissingIp", "GET", "/api/xdp-firewall/check", 500),
        ("whitelistMissingIp", "GET", "/api/xdp-firewall/whitelist/check", 500),
    )
    return {
        name: _json(target, method, path, status=status) for name, method, path, status in requests
    }


cast(Any, capture_xdp_parameter_errors).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket",
    "authentication": "admin API key",
    "configuration": "botmail.xdp.enabled=false",
    "coverage": [
        "disabled ban and unban readiness short-circuit before IP validation",
        "missing read-path IP",
        "non-integer reason",
        "controller binding errors",
    ],
}


XDP_SCENARIOS = (
    Scenario(
        "http/xdp/disabled-control-plane",
        capture_disabled_xdp_control_plane,
        _NORMALIZERS,
    ),
    Scenario(
        "http/xdp/parameter-errors",
        capture_xdp_parameter_errors,
        _NORMALIZERS,
    ),
)
