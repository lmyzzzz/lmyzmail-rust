from __future__ import annotations

import json
import socket
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from typing import Any, cast

from .differential import RuntimeTarget, Scenario
from .errors import ProtocolError
from .normalize import FieldRule, constant
from .protocols import (
    RawHttpResponse,
    build_http_request,
    connect_bounded,
    read_http_response,
)
from .snapshots import HeaderRule, bytes_snapshot, http_bytes_snapshot, http_json_snapshot

_HOST = "127.0.0.1"
_MAX_HEADER_BYTES = 64 * 1024
_MAX_BODY_BYTES = 128 * 1024
_TIMESTAMP = "<rfc3339-timestamp>"
_GENERATION = 0


def _contract(value: dict[str, Any]):
    def decorate(capture: Any) -> Any:
        capture.__lmyzmail_contract__ = value
        return capture

    return decorate


def _port(target: RuntimeTarget) -> int:
    if target.ports is None:
        raise ProtocolError("HTCPCP target is not started")
    return target.ports.htcpcp


def _request(
    target: RuntimeTarget,
    method: str,
    path: str,
    *,
    content_type: str | None = None,
    additions: str | None = None,
    body: bytes = b"",
    timeout: float = 5.0,
) -> RawHttpResponse:
    headers: list[tuple[str, str]] = []
    if content_type is not None:
        headers.append(("Content-Type", content_type))
    if additions is not None:
        headers.append(("Accept-Additions", additions))
    port = _port(target)
    stream = connect_bounded(_HOST, port, timeout=timeout, max_received=_MAX_BODY_BYTES)
    try:
        stream.sendall(
            build_http_request(
                method,
                path,
                host=f"{_HOST}:{port}",
                headers=headers,
                body=body,
            )
        )
        return read_http_response(
            stream,
            request_method=method,
            max_header_bytes=_MAX_HEADER_BYTES,
            max_body_bytes=_MAX_BODY_BYTES,
        )
    finally:
        stream.sock.close()


def htcpcp_exchange(
    target: RuntimeTarget,
    method: str,
    path: str,
    *,
    content_type: str | None = None,
    additions: str | None = None,
    body: bytes = b"",
    timeout: float = 5.0,
) -> RawHttpResponse:
    return _request(
        target,
        method,
        path,
        content_type=content_type,
        additions=additions,
        body=body,
        timeout=timeout,
    )


def _brew(
    target: RuntimeTarget,
    path: str,
    *,
    body: bytes = b"start",
    content_type: str = "message/coffeepot",
    additions: str | None = None,
    method: str = "BREW",
) -> RawHttpResponse:
    return _request(
        target,
        method,
        path,
        content_type=content_type,
        additions=additions,
        body=body,
    )


def _reset_pot(target: RuntimeTarget, path: str) -> None:
    _brew(target, path, body=b"stop")
    started = _brew(target, path)
    if started.status_code != 200:
        raise ProtocolError(f"HTCPCP reset brew failed for {path}: {started.status_line!r}")
    _wait_for_state(target, path.removeprefix("/"), "IDLE", 4.0)


def _state_snapshot(response: RawHttpResponse, *, root: bool = False) -> dict[str, Any]:
    if root:
        value = json.loads(response.body)
        if not isinstance(value, dict) or not isinstance(value.get("pots"), list):
            raise ProtocolError("HTCPCP root status did not contain a pots array")
        rules = tuple(
            FieldRule(("pots", index, "generation"), constant(_GENERATION))
            for index in range(len(value["pots"]))
        )
    else:
        value = json.loads(response.body)
        if not isinstance(value, dict):
            raise ProtocolError("HTCPCP pot status was not an object")
        rules_list = [FieldRule(("generation",), constant(_GENERATION))]
        for key in ("brewStartTime", "brewEndTime"):
            if key in value:
                rules_list.append(FieldRule((key,), constant(_TIMESTAMP)))
        rules = tuple(rules_list)
    return cast(dict[str, Any], http_json_snapshot(response, rules=rules))


def _xml_node(element: ET.Element) -> dict[str, Any]:
    local_name = element.tag.rsplit("}", 1)[-1]
    text = (element.text or "").strip()
    if local_name == "generation":
        text = str(_GENERATION)
    elif local_name in {"brew-start", "brew-end"}:
        text = _TIMESTAMP
    elif local_name in {"brew-duration", "brew-duration-seconds"}:
        text = "<duration>"
    return {
        "tag": element.tag,
        "attributes": sorted(element.attrib.items()),
        "text": text,
        "children": [_xml_node(child) for child in element],
    }


def _xml_snapshot(response: RawHttpResponse) -> dict[str, Any]:
    upper_body = response.body.upper()
    if b"<!DOCTYPE" in upper_body or b"<!ENTITY" in upper_body:
        raise ProtocolError("HTCPCP PROPFIND body contained a forbidden XML declaration")
    try:
        # RawHttpResponse is size-bounded and declarations capable of expansion are rejected above.
        root = ET.fromstring(response.body)  # noqa: S314
    except ET.ParseError as error:
        raise ProtocolError("HTCPCP PROPFIND body was not bounded XML") from error
    snapshot = http_bytes_snapshot(
        response,
        header_rules=(HeaderRule(b"content-length", lambda _: b"<normalized>"),),
    )
    snapshot["body"] = _xml_node(root)
    return cast(dict[str, Any], snapshot)


def _absolute_form_exchange(
    target: RuntimeTarget,
    method: str,
    uri: str,
    *,
    content_type: str,
    body: bytes,
) -> RawHttpResponse:
    request = (
        f"{method} {uri} HTTP/1.1\r\n"
        f"Host: {_HOST}:{_port(target)}\r\n"
        "Connection: close\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode("ascii") + body
    stream = connect_bounded(_HOST, _port(target), timeout=5.0, max_received=_MAX_BODY_BYTES)
    try:
        stream.sendall(request)
        return read_http_response(
            stream,
            request_method=method,
            max_header_bytes=_MAX_HEADER_BYTES,
            max_body_bytes=_MAX_BODY_BYTES,
        )
    finally:
        stream.sock.close()


@_contract(
    {
        "protocol": "htcpcp/http-raw",
        "profile": "capabilities-and-validation",
        "requests": [
            "GET /",
            "GET /pot-0",
            "HEAD /pot-0",
            "HEAD /missing",
            "OPTIONS /",
            "GET /missing",
            "PROPFIND /missing",
            "WHEN /missing",
            "DELETE /pot-0",
            "BREW content/body validation matrix",
        ],
    }
)
def capture_capabilities(target: RuntimeTarget) -> dict[str, Any]:
    invalid_bodies = {
        name: http_bytes_snapshot(
            _brew(target, "/pot-0", body=value),
        )
        for name, value in {
            "empty": b"",
            "uppercase": b"START",
            "trailing-space": b"start ",
            "unknown": b"explode",
        }.items()
    }
    return {
        "root": _state_snapshot(_request(target, "GET", "/"), root=True),
        "pot": _state_snapshot(_request(target, "GET", "/pot-0")),
        "head": http_bytes_snapshot(_request(target, "HEAD", "/pot-0")),
        "head_missing": http_bytes_snapshot(_request(target, "HEAD", "/missing")),
        "options": http_bytes_snapshot(_request(target, "OPTIONS", "/")),
        "get_missing": http_bytes_snapshot(_request(target, "GET", "/missing")),
        "propfind_missing": http_bytes_snapshot(_request(target, "PROPFIND", "/missing")),
        "when_missing": http_bytes_snapshot(_request(target, "WHEN", "/missing")),
        "method_not_allowed": http_bytes_snapshot(_request(target, "DELETE", "/pot-0")),
        "wrong_content_type": http_bytes_snapshot(
            _brew(target, "/pot-0", content_type="application/json")
        ),
        "invalid_bodies": invalid_bodies,
    }


@_contract(
    {
        "protocol": "htcpcp/http-raw",
        "profile": "brew-state-machine",
        "sequence": [
            "BREW start with milk",
            "GET BREWING",
            "PROPFIND BREWING",
            "duplicate BREW",
            "BREW stop",
            "GET POURED",
            "WHEN",
            "GET IDLE",
            "WHEN IDLE",
        ],
        "normalized": ["generation", "brew timestamps", "brew duration"],
    }
)
def capture_lifecycle(target: RuntimeTarget) -> dict[str, Any]:
    start = _brew(target, "/pot-0", additions="Cream;amount=2")
    brewing = _request(target, "GET", "/pot-0")
    propfind = _request(target, "PROPFIND", "/pot-0")
    duplicate = _brew(target, "/pot-0")
    stop = _brew(target, "/pot-0", body=b"stop")
    poured = _request(target, "GET", "/pot-0")
    when = _request(target, "WHEN", "/pot-0")
    idle = _request(target, "GET", "/pot-0")
    when_idle = _request(target, "WHEN", "/pot-0")
    return {
        "start": http_bytes_snapshot(start),
        "brewing": _state_snapshot(brewing),
        "propfind": _xml_snapshot(propfind),
        "duplicate": http_bytes_snapshot(duplicate),
        "stop": http_bytes_snapshot(stop),
        "poured": _state_snapshot(poured),
        "when": http_bytes_snapshot(when),
        "idle": _state_snapshot(idle),
        "when_idle": http_bytes_snapshot(when_idle),
    }


@_contract(
    {
        "protocol": "htcpcp/http-raw",
        "profile": "tea-additions-uri",
        "coverage": [
            "POST alias",
            "300 Alternates local/global",
            "403/406/418/503",
            "unknown tea",
            "header/query additions",
            "coffee and kava URI schemes",
            "wildcard addition",
        ],
    }
)
def capture_tea_additions_uri(target: RuntimeTarget) -> dict[str, Any]:
    post_start = _brew(
        target,
        "/pot-3",
        method="POST",
        content_type="Application/Coffee-Pot-Command; charset=UTF-8",
    )
    post_stop = _brew(target, "/pot-3", method="POST", body=b"stop")
    _reset_pot(target, "/pot-3")
    tea_local = _brew(target, "/pot-1", content_type="message/teapot")
    tea_global = _brew(target, "/", content_type="message/teapot")
    teapot = _brew(target, "/pot-1", content_type="message/coffeepot")
    coffee_only = _brew(target, "/pot-3/darjeeling", content_type="message/teapot")
    unknown_tea = _brew(target, "/pot-0/not-a-tea", content_type="message/teapot")
    unsupported = _brew(target, "/pot-6", additions="Cream")
    forbidden = _brew(
        target,
        "/pot-7/green",
        content_type="message/teapot",
        additions="Cream",
    )
    accepted = _brew(
        target,
        "/pot-7/green",
        content_type="message/teapot; charset=UTF-8",
        additions="Sugar;amount=2",
    )
    accepted_stop = _brew(
        target,
        "/pot-7/green",
        content_type="message/teapot",
        body=b"stop",
    )
    _reset_pot(target, "/pot-7")
    coffee_uri = _absolute_form_exchange(
        target,
        "BREW",
        "coffee:/pot-0?Sugar",
        content_type="message/coffeepot",
        body=b"start",
    )
    coffee_uri_stop = _brew(target, "/pot-0", body=b"stop")
    _reset_pot(target, "/pot-0")
    kava_uri = _absolute_form_exchange(
        target,
        "BREW",
        "kava://coffee.example/pot-0?*",
        content_type="message/coffeepot",
        body=b"start",
    )
    kava_uri_stop = _brew(target, "/pot-0", body=b"stop")
    _reset_pot(target, "/pot-0")
    return {
        "post_start": http_bytes_snapshot(post_start),
        "post_stop": http_bytes_snapshot(post_stop),
        "tea_local": http_bytes_snapshot(tea_local),
        "tea_global": http_bytes_snapshot(tea_global),
        "teapot": http_bytes_snapshot(teapot),
        "coffee_only": http_bytes_snapshot(coffee_only),
        "unknown_tea": http_bytes_snapshot(unknown_tea),
        "unsupported": http_bytes_snapshot(unsupported),
        "forbidden": http_bytes_snapshot(forbidden),
        "accepted": http_bytes_snapshot(accepted),
        "accepted_stop": http_bytes_snapshot(accepted_stop),
        "coffee_uri": http_bytes_snapshot(coffee_uri),
        "coffee_uri_stop": http_bytes_snapshot(coffee_uri_stop),
        "kava_uri": http_bytes_snapshot(kava_uri),
        "kava_uri_stop": http_bytes_snapshot(kava_uri_stop),
    }


def _raw_snapshot(request: bytes, port: int, *, timeout: float = 5.0) -> dict[str, Any]:
    stream = connect_bounded(_HOST, port, timeout=timeout, max_received=_MAX_BODY_BYTES)
    try:
        stream.sendall(request)
        response = read_http_response(
            stream,
            request_method="GET",
            max_header_bytes=_MAX_HEADER_BYTES,
            max_body_bytes=_MAX_BODY_BYTES,
        )
        return cast(dict[str, Any], bytes_snapshot(response.raw))
    finally:
        stream.sock.close()


@_contract(
    {
        "protocol": "htcpcp/http-raw",
        "profile": "framing-and-limits",
        "coverage": [
            "no banner",
            "keep-alive pipeline",
            "fragmentation",
            "chunked request",
            "Expect 100-continue",
            "65536/65537 aggregate boundary",
            "oversized initial/header",
            "partial disconnect recovery",
        ],
    }
)
def capture_transport(target: RuntimeTarget) -> dict[str, Any]:
    port = _port(target)
    silent = False
    probe = socket.create_connection((_HOST, port), timeout=1.0)
    try:
        probe.settimeout(0.15)
        try:
            value = probe.recv(1)
            silent = value == b""
        except TimeoutError:
            silent = True
    finally:
        probe.close()

    stream = connect_bounded(_HOST, port, timeout=5.0, max_received=_MAX_BODY_BYTES)
    try:
        first_request = build_http_request(
            "GET",
            "/pot-0",
            host=f"{_HOST}:{port}",
            headers=(("Connection", "keep-alive"),),
        )
        second_request = build_http_request(
            "OPTIONS",
            "/",
            host=f"{_HOST}:{port}",
            headers=(("Connection", "close"),),
        )
        stream.sendall(first_request + second_request)
        first = read_http_response(stream, request_method="GET")
        second = read_http_response(stream, request_method="OPTIONS")
    finally:
        stream.sock.close()

    fragmented = connect_bounded(_HOST, port, timeout=5.0, max_received=_MAX_BODY_BYTES)
    try:
        request = build_http_request("GET", "/pot-0", host=f"{_HOST}:{port}")
        for offset in range(0, len(request), 7):
            fragmented.sendall(request[offset : offset + 7])
            time.sleep(0.005)
        fragmented_response = read_http_response(fragmented, request_method="GET")
    finally:
        fragmented.sock.close()

    chunked_request = (
        f"BREW /pot-4 HTTP/1.1\r\nHost: {_HOST}:{port}\r\n"
        "Connection: close\r\nContent-Type: message/coffeepot\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "5\r\nstart\r\n0\r\n\r\n"
    ).encode("ascii")
    chunked_stream = connect_bounded(_HOST, port, timeout=5.0, max_received=_MAX_BODY_BYTES)
    try:
        chunked_stream.sendall(chunked_request)
        chunked = read_http_response(chunked_stream, request_method="BREW")
    finally:
        chunked_stream.sock.close()
    _reset_pot(target, "/pot-4")

    expect = connect_bounded(_HOST, port, timeout=5.0, max_received=_MAX_BODY_BYTES)
    try:
        expect.sendall(
            (
                f"BREW /pot-4 HTTP/1.1\r\nHost: {_HOST}:{port}\r\n"
                "Connection: keep-alive\r\nContent-Type: message/coffeepot\r\n"
                "Content-Length: 5\r\nExpect: 100-continue\r\n\r\n"
            ).encode("ascii")
        )
        interim = read_http_response(expect, request_method="BREW")
        expect.sendall(b"start")
        final = read_http_response(expect, request_method="BREW")
    finally:
        expect.sock.close()
    _reset_pot(target, "/pot-4")

    at_limit = _brew(target, "/pot-6", body=b"x" * 65_536)
    over_limit = _brew(target, "/pot-6", body=b"x" * 65_537)
    initial_line = (
        b"GET /" + b"x" * 16_000 + b" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    oversized_header = (
        b"GET /missing HTTP/1.1\r\nHost: x\r\nX-Fill: "
        + b"x" * 20_000
        + b"\r\nConnection: close\r\n\r\n"
    )
    partial = socket.create_connection((_HOST, port), timeout=1.0)
    partial.sendall(b"BREW /pot-0 HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nst")
    partial.close()
    recovery = _request(target, "GET", "/pot-0")
    return {
        "silent_before_request": silent,
        "pipeline": {
            "first": _state_snapshot(first),
            "second": http_bytes_snapshot(second),
        },
        "fragmented": _state_snapshot(fragmented_response),
        "chunked": http_bytes_snapshot(chunked),
        "expect_continue": {
            "interim": http_bytes_snapshot(interim),
            "final": http_bytes_snapshot(final),
        },
        "aggregate_limit": http_bytes_snapshot(at_limit),
        "aggregate_over_limit": http_bytes_snapshot(over_limit),
        "oversized_initial_line_raw": _raw_snapshot(initial_line, port),
        "oversized_header_raw": _raw_snapshot(oversized_header, port),
        "partial_disconnect_recovery": _state_snapshot(recovery),
    }


def _wait_for_state(
    target: RuntimeTarget, pot: str, expected: str, timeout: float
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: RawHttpResponse | None = None
    while time.monotonic() < deadline:
        last = _request(target, "GET", f"/{pot}")
        value = json.loads(last.body)
        if isinstance(value, dict) and value.get("state") == expected:
            return _state_snapshot(last)
        time.sleep(0.05)
    raise ProtocolError(
        f"HTCPCP pot {pot} did not reach {expected}: {None if last is None else last.body!r}"
    )


@_contract(
    {
        "protocol": "htcpcp/http-raw",
        "profile": "concurrency-and-timers",
        "coverage": [
            "same-pot concurrent CAS",
            "cross-pot independence",
            "automatic completion",
            "stale timer generation guard",
        ],
    }
)
def capture_concurrency_timers(target: RuntimeTarget) -> dict[str, Any]:
    def start_same(_: int) -> int:
        return _brew(target, "/pot-4").status_code

    with ThreadPoolExecutor(max_workers=8) as executor:
        same_pot = sorted(executor.map(start_same, range(8)))
    _reset_pot(target, "/pot-4")

    def start_path(path: str) -> tuple[str, int]:
        return path, _brew(target, path).status_code

    paths = ("/pot-0", "/pot-3", "/pot-4", "/pot-6")
    with ThreadPoolExecutor(max_workers=4) as executor:
        independent = sorted(executor.map(start_path, paths))
    for path in paths:
        _reset_pot(target, path)

    timer_start = _brew(target, "/pot-3")
    timer_idle = _wait_for_state(target, "pot-3", "IDLE", 4.0)

    stale_first = _brew(target, "/pot-0", additions="Sugar")
    time.sleep(0.6)
    stale_stop = _brew(target, "/pot-0", body=b"stop")
    stale_second = _brew(target, "/pot-0", additions="Sugar")
    time.sleep(0.55)
    stale_state = _request(target, "GET", "/pot-0")
    _reset_pot(target, "/pot-0")
    return {
        "same_pot_statuses": same_pot,
        "independent_statuses": independent,
        "timer_start": http_bytes_snapshot(timer_start),
        "timer_idle": timer_idle,
        "stale_timer": {
            "first": http_bytes_snapshot(stale_first),
            "stop": http_bytes_snapshot(stale_stop),
            "second": http_bytes_snapshot(stale_second),
            "state_after_old_deadline": _state_snapshot(stale_state),
        },
    }


@_contract(
    {
        "protocol": "htcpcp/tcp",
        "profile": "read-idle-timeout",
        "request": "connect and send no bytes",
        "deadline_seconds": 65,
        "expected": "server-driven EOF after the 60-second read-idle boundary",
    }
)
def capture_idle_timeout(target: RuntimeTarget) -> dict[str, Any]:
    stream = connect_bounded(_HOST, _port(target), timeout=65.0, max_received=1)
    try:
        return {"server_closed": stream.recv_some(1) == b""}
    finally:
        stream.sock.close()


@_contract(
    {
        "protocol": "htcpcp/http-raw",
        "profile": "oracle-connection-close-evidence",
        "request": "GET /pot-0 HTTP/1.1 with Connection: close",
        "observation_window_ms": 250,
        "candidate_requirement": "send EOF immediately after the framed response",
    }
)
def capture_oracle_connection_close_evidence(target: RuntimeTarget) -> dict[str, Any]:
    port = _port(target)
    stream = connect_bounded(_HOST, port, timeout=2.0, max_received=_MAX_BODY_BYTES)
    try:
        stream.sendall(build_http_request("GET", "/pot-0", host=f"{_HOST}:{port}"))
        response = read_http_response(stream, request_method="GET")
        stream.sock.settimeout(0.25)
        try:
            closed = stream.sock.recv(1) == b""
        except TimeoutError:
            closed = False
        return {
            "response": _state_snapshot(response),
            "server_closed_within_window": closed,
        }
    finally:
        stream.sock.close()


@_contract(
    {
        "protocol": "htcpcp/http-raw",
        "profile": "oracle-ambiguous-framing-evidence",
        "request": "BREW with conflicting duplicate Content-Length fields",
        "candidate_requirement": "reject before body dispatch or 100 Continue",
    }
)
def capture_oracle_ambiguous_framing_evidence(target: RuntimeTarget) -> dict[str, Any]:
    request = (
        b"BREW /pot-0 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
        b"Content-Type: message/coffeepot\r\nContent-Length: 5\r\n"
        b"Content-Length: 4\r\n\r\nstart"
    )
    return {"conflicting_content_length_raw": _raw_snapshot(request, _port(target))}


HTCPCP_SCENARIOS = (
    Scenario("capabilities", capture_capabilities),
    Scenario(
        "lifecycle",
        capture_lifecycle,
        normalizers=("json:generation", "json:rfc3339", "xml:brew-dynamic-fields"),
    ),
    Scenario("tea-additions-uri", capture_tea_additions_uri),
    Scenario("transport", capture_transport, normalizers=("json:generation",)),
    Scenario("concurrency-timers", capture_concurrency_timers, normalizers=("json:generation",)),
    Scenario("idle-timeout", capture_idle_timeout),
)

HTCPCP_ORACLE_EVIDENCE_SCENARIOS = (
    Scenario("connection-close-not-honored", capture_oracle_connection_close_evidence),
    Scenario("ambiguous-content-length", capture_oracle_ambiguous_framing_evidence),
)


__all__ = [
    "HTCPCP_ORACLE_EVIDENCE_SCENARIOS",
    "HTCPCP_SCENARIOS",
    "htcpcp_exchange",
]
