from __future__ import annotations

import hashlib
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote

import pytest
from playwright.sync_api import expect, sync_playwright
from test_candidate_cringe_api_golden import (
    _ADMIN_HEADERS, _READ_ONLY_HEADERS, _WRITE_ONLY_HEADERS,
    _candidate, _OracleTarget, _seed_cringe_fixture,
)
from test_candidate_cringe_list_golden import _connection, _state

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.protocols import http_exchange
from lmyzmail_blackbox.snapshots import bytes_snapshot, http_json_snapshot
from lmyzmail_blackbox.web_ui_contract import _new_context, _pinned_resources, _settle_page

_PROFILE = "managed-cringe-detail"
_GOLDEN = "blackbox/golden/java/managed-cringe-detail-v5"
_RAW = "\t203.0.113.88%2F\n"
_COLLISION = "\t203.0.113.77%2F\n"


def _request(target: RuntimeTarget, address: str, headers: Any = _ADMIN_HEADERS) -> Any:
    assert target.ports is not None
    return http_exchange(
        "127.0.0.1", target.ports.http, "GET", "/api/cringe-ips/" + address,
        headers=headers, timeout=12.0, max_response=20 * 1024 * 1024,
    )


def _seed(target: RuntimeTarget) -> None:
    _seed_cringe_fixture(target)
    with _connection(target) as connection:
        for address in (
            _RAW, _COLLISION, "2001:DB8::AA", "plus+ip", "plus ip", "?ip#",
            "\ufffd", "\ufffd\ufffd", "\ufffd\ufffd\ufffd", "\ufffd\ufffd\ufffd\ufffd", "\ufffdA",
        ):
            connection.execute(
                """INSERT INTO skibidi_cringe_ip (
                    ip_address,total_score,current_score,activity_count,
                    first_seen_at,last_seen_at,last_decay_at,
                    self_spoofing_count,open_relay_count,auth_probe_count,
                    illegal_domain_count,spamhaus_count,http_on_smtp_count,
                    ssh_on_smtp_count,http_port_scanning_count,honeypot_hit_count,
                    other_count,pps_overlimit_count,syn_flood_count,ssh_bruteforce_count)
                SELECT %s,99,98,97,first_seen_at,last_seen_at,NULL,
                       self_spoofing_count,open_relay_count,auth_probe_count,
                       illegal_domain_count,spamhaus_count,http_on_smtp_count,
                       ssh_on_smtp_count,http_port_scanning_count,honeypot_hit_count,
                       other_count,pps_overlimit_count,syn_flood_count,ssh_bruteforce_count
                FROM skibidi_cringe_ip WHERE ip_address='203.0.113.77'""",
                (address,),
            )
        for n, address in enumerate((_RAW, _COLLISION)):
            connection.execute(
                """INSERT INTO skibidi_cringe_ip_activity
                (id,ip_address,activity_type,score,timestamp,response_message)
                VALUES (%s,%s,'SELF_SPOOFING',3,'2024-01-02T00:00:00Z',%s)""",
                (930000 + n, address, "legacy activity " + str(n)),
            )


def _activities_state(target: RuntimeTarget) -> list[Any]:
    with _connection(target) as connection:
        return connection.execute(
            "SELECT row_to_json(a)::text FROM skibidi_cringe_ip_activity a ORDER BY id"
        ).fetchall()


def _capture_detail(target: RuntimeTarget) -> dict[str, Any]:
    _seed(target)
    before = (_state(target), _activities_state(target))
    observed: dict[str, Any] = {}
    cases = {
        "ipv4": "203.0.113.77", "null_decay": "198.51.100.9",
        "ipv6_empty": "2001:DB8::AA", "ipv6_encoded": "2001%3ADB8%3A%3AAA",
        "ipv6_case_sensitive": "2001:db8::aa", "missing": "192.0.2.123",
        "legacy_fallback": quote(_RAW, safe=""),
        "canonical_does_not_find_legacy": "203.0.113.88",
        "canonical_precedence": quote(_COLLISION, safe=""),
        "spaces_controls": "%20%09%7F203.0.113.77%0A%20",
        "percent_garbage": "203.0.113.77%252F",
        "percent_one_hex": "203.0.113.77%25A",
        "percent_no_hex": "203.0.113.77%25",
        "control_inside_percent": "203.0.113.77%25%0932",
        "unicode_not_trimmed": "%C2%A0203.0.113.77%C2%A0",
        "sql_text": quote("x' OR true --", safe=""),
        "plus_literal": "plus+ip", "plus_encoded": "plus%2Bip", "space_encoded": "plus%20ip",
        "question_hash_encoded": "%3Fip%23", "invalid_utf8": "%FF",
        "encoded_slash": "203.0.113.77%2Fextra", "extra_segment": "203.0.113.77/extra",
        "query_ignored": "203.0.113.77?unused=x",
        "malformed_percent_empty": "203.0.113.77%",
        "malformed_percent_short": "203.0.113.77%2",
        "malformed_percent_hex": "203.0.113.77%GG",
        "malformed_percent_half_hex": "203.0.113.77%0G",
        "utf8_encoded_replacement": "%EF%BF%BD",
        "utf8_surrogate": "%ED%A0%80",
        "utf8_truncated_surrogate": "%ED%A0",
        "utf8_surrogate_then_ascii": "%ED%A0A",
        "utf8_surrogate_then_invalid": "%ED%A0%FF",
        "utf8_two_surrogates": "%ED%A0%80%ED%BF%BF",
        "utf8_truncated_multibyte": "%E2%82",
        "utf8_overlong_pair": "%C0%AF",
        "utf8_above_unicode_max": "%F4%90%80%80",
        "utf8_overlong_quad": "%F0%80%80%80",
    }
    for name, path in cases.items():
        response = _request(target, path)
        observed[name] = http_json_snapshot(response)
    for name, headers in (("read_only", _READ_ONLY_HEADERS), ("no_key", ()), ("write_only", _WRITE_ONLY_HEADERS)):
        response = _request(target, "203.0.113.77", headers)
        observed[name] = http_json_snapshot(response, canonicalize_object_order=response.status_code != 200)
    for name, headers in (("malformed_no_key", ()), ("malformed_write_only", _WRITE_ONLY_HEADERS)):
        observed[name] = http_json_snapshot(_request(target, "203.0.113.77%", headers))
    detail = json.loads(_request(target, "203.0.113.77").body)
    assert len(detail["activities"]) == 4
    assert detail["summary"]["activityCount"] == 4
    assert json.loads(_request(target, quote(_RAW, safe="")).body)["activities"][0]["ipAddress"] == _RAW
    assert json.loads(_request(target, quote(_COLLISION, safe="")).body) == detail
    assert (_state(target), _activities_state(target)) == before
    return observed


cast(Any, _capture_detail).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket",
    "sequence": [
        "seed scores, null/empty/Unicode activity fields, legacy raw identities and collision",
        "query clean-first/raw-fallback, raw-identity activities, URI decoding and authorization",
        "verify both database tables unchanged and preserve successful wire bytes",
    ],
    "normalization": "HTTP Date and established JDK Map.of API-key error order only",
}


def _seed_history(target: RuntimeTarget, count: int, metadata: str = "") -> None:
    with _connection(target) as connection:
        connection.execute("DELETE FROM skibidi_cringe_ip_activity")
        connection.execute(
            """INSERT INTO skibidi_cringe_ip_activity
            (id,ip_address,activity_type,score,timestamp,metadata)
            SELECT 940000+n,'203.0.113.77','SELF_SPOOFING',1,
                   '2024-01-01T00:00:00Z'::timestamptz + n * interval '1 microsecond',%s
            FROM generate_series(1,%s) AS n""", (metadata, count),
        )


def _digest(response: Any, count: int) -> dict[str, Any]:
    assert response.status_code == 200
    body = json.loads(response.body)
    assert len(body["activities"]) == count
    assert body["activities"][0]["id"] == 940000 + count
    assert body["activities"][-1]["id"] == 940001
    return {"count": count, "length": len(response.body), "sha256": hashlib.sha256(response.body).hexdigest()}


def _capture_history(target: RuntimeTarget) -> dict[str, Any]:
    _seed(target)
    observed = {}
    for count in (501, 10000):
        _seed_history(target, count)
        observed[str(count)] = _digest(_request(target, "203.0.113.77"), count)
    return observed


cast(Any, _capture_history).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket", "sequence": ["read entire 501 and 10000 row histories in descending timestamp order"],
    "normalization": "none; compare full body SHA256 and byte length, not just parsed entities",
}


def _capture_boundaries(target: RuntimeTarget) -> dict[str, Any]:
    _seed(target)
    observed = {}
    for name, count, metadata in (("row_overflow", 10001, ""), ("byte_overflow", 1600, "\x01" * 1024)):
        _seed_history(target, count, metadata)
        observed[name] = _digest(_request(target, "203.0.113.77"), count)
    assert observed["byte_overflow"]["length"] > 8 * 1024 * 1024
    return observed


cast(Any, _capture_boundaries).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket", "evidence_only": True,
    "difference_id": "cringe-detail-response-budgets",
    "sequence": ["prove frozen Java returns 10001 rows and over 8MiB JSON without a response budget"],
}


def _capture_ui(target: RuntimeTarget) -> dict[str, Any]:
    repository = Path(__file__).resolve().parents[2]
    assert target.ports is not None
    _seed(target)
    with _connection(target) as connection:
        connection.execute("DELETE FROM skibidi_cringe_ip_activity WHERE id>=930000")
        connection.execute("DELETE FROM skibidi_cringe_ip WHERE ip_address NOT IN ('203.0.113.77','198.51.100.9','2001:DB8::AA')")
    origin = f"http://127.0.0.1:{target.ports.http}"
    unexpected: list[str] = []
    errors: list[str] = []
    requests: list[str] = []
    observed: dict[str, Any] = {}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=str(repository / ".blackbox/ms-playwright/chromium-1181/chrome-linux/chrome"),
            headless=True, chromium_sandbox=False,
            args=["--disable-gpu", "--disable-lcd-text", "--font-render-hinting=none"],
        )
        context = _new_context(
            browser, {"width": 1440, "height": 1100}, application_origin=origin,
            resources=_pinned_resources(repository), used_resources=set(), unexpected_urls=unexpected,
        )
        page = context.new_page()
        for url in ("https://ipwho.is/**", "https://ipwhois.app/json/**"):
            page.route(url, lambda route: route.abort())
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("request", lambda request: requests.append(request.url.removeprefix(origin)))
        page.goto(origin + "/cringe.html")
        page.get_by_placeholder("API Key", exact=True).fill(_READ_ONLY_HEADERS[0][1])
        page.get_by_role("button", name="Connect", exact=True).click()
        expect(page.locator("tbody tr")).to_have_count(3)
        for address, count in (("203.0.113.77", 4), ("2001:DB8::AA", 0)):
            page.locator("tbody tr").filter(has=page.get_by_text(address, exact=True)).click()
            expect(page.locator(".detail-header h2")).to_contain_text(address)
            expect(page.locator(".detail-panel .activity-item")).to_have_count(count)
            expect(page.locator(".ip-info-error")).to_be_visible()
            _settle_page(page)
            observed[address] = {
                "text": page.locator(".detail-panel").inner_text(),
                "links": page.locator(".detail-panel a").evaluate_all("els => els.map(e => e.href)"),
                "png": bytes_snapshot(page.screenshot(animations="disabled")),
            }
            page.get_by_role("button", name="Close", exact=True).click()
            expect(page.locator(".detail-panel")).to_have_count(0)
        assert errors == []
        assert unexpected == []
        observed["detail_requests"] = [url for url in requests if url in (
            "/api/cringe-ips/203.0.113.77", "/api/cringe-ips/2001%3ADB8%3A%3AAA",
        )]
        assert len(observed["detail_requests"]) == 2
        context.close()
        browser.close()
    return observed


cast(Any, _capture_ui).__lmyzmail_contract__ = {
    "protocol": "http/playwright/chromium-1181",
    "sequence": ["connect real read-only API; open IPv4 four-activity detail, close, open empty IPv6 detail, close"],
    "normalization": "origin port only; UTC zh-CN 1440x1100; animations disabled; external geo requests aborted",
    "state": "real application APIs without local mocking; pinned Vue/fonts resources",
}

_SCENARIOS = {
    "api": (Scenario("http/cringe/detail", _capture_detail, normalizers=("json-object-order:jdk-map-of:cringe-api-key-errors",)),),
    "history": (Scenario("http/cringe/detail-history", _capture_history),),
    "boundaries": (Scenario("http/cringe/detail-budgets", _capture_boundaries),),
    "ui": (Scenario("http/cringe/detail-ui", _capture_ui),),
}


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.parametrize("profile", tuple(_SCENARIOS))
@pytest.mark.timeout(180)
def test_frozen_java_cringe_detail_golden(tmp_path: Path, record_java_golden: bool, profile: str) -> None:
    repository = Path(__file__).resolve().parents[2]
    with PersistentJavaOracleRuntime(tmp_path / ("java-detail-" + profile)) as oracle:
        runner = DifferentialRunner(repository, repository / (_GOLDEN + "-" + profile), _PROFILE + "-" + profile, record_java=record_java_golden)
        if record_java_golden:
            runner.record_from_java(_SCENARIOS[profile], _OracleTarget(oracle))
        else:
            runner.verify_java(_SCENARIOS[profile], _OracleTarget(oracle))


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.parametrize("profile", ("api", "history", "ui"))
@pytest.mark.timeout(180)
def test_candidate_cringe_detail_matches_frozen_java(profile: str) -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository) as candidate:
        DifferentialRunner(repository, repository / (_GOLDEN + "-" + profile), _PROFILE + "-" + profile).verify_candidate(_SCENARIOS[profile], candidate)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_candidate_detail_budgets_concurrency_and_cancellation() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository, "--lmyzmail.postgres.pool.max-size=1") as candidate:
        _seed(candidate)
        for count, metadata in ((10001, ""), (1600, "\x01" * 1024)):
            _seed_history(candidate, count, metadata)
            response = _request(candidate, "203.0.113.77")
            assert response.status_code == 500
            assert json.loads(response.body) == {"error": "internal_error"}
            _seed_history(candidate, 501)
            _digest(_request(candidate, "203.0.113.77"), 501)
        with ThreadPoolExecutor(max_workers=8) as workers:
            responses = list(workers.map(lambda _: _request(candidate, "203.0.113.77"), range(24)))
        assert all(response.status_code == 200 for response in responses)
        # Four large responses remain backpressured at the TCP send buffer.
        # A fifth request must hit admission's absolute deadline, then all slots
        # must recover when the readers disconnect. No local API is mocked.
        assert candidate.ports is not None
        _seed_history(candidate, 1200, "\x01" * 1024)
        readers: list[socket.socket] = []
        try:
            for _ in range(4):
                sock = socket.socket()
                readers.append(sock)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                sock.settimeout(12)
                sock.connect(("127.0.0.1", candidate.ports.http))
                sock.sendall(("GET /api/cringe-ips/203.0.113.77 HTTP/1.1\r\nHost: localhost\r\nX-API-Key: " + _ADMIN_HEADERS[0][1] + "\r\n\r\n").encode())
                head = b""
                while b"\r\n\r\n" not in head:
                    head += sock.recv(512)
                    assert len(head) < 4096
                assert head.startswith(b"HTTP/1.1 200 OK\r\n")
            start = time.monotonic()
            stalled = _request(candidate, "203.0.113.77")
            assert stalled.status_code == 500
            assert json.loads(stalled.body) == {"error": "internal_error"}
            assert 7.0 <= time.monotonic() - start <= 11.0
        finally:
            for sock in readers:
                sock.close()
        _seed_history(candidate, 501)
        _digest(_request(candidate, "203.0.113.77"), 501)
        for table in ("skibidi_cringe_ip", "skibidi_cringe_ip_activity"):
            with _connection(candidate) as blocker:
                blocker.execute(f"LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE")
                start = time.monotonic()
                assert _request(candidate, "203.0.113.77", _WRITE_ONLY_HEADERS).status_code == 403
                assert time.monotonic() - start < 2.0
                start = time.monotonic()
                assert _request(candidate, "203.0.113.77").status_code == 500
                assert 7.0 <= time.monotonic() - start <= 11.0
                blocker.rollback()
            _digest(_request(candidate, "203.0.113.77"), 501)
        assert candidate.ports is not None
        with _connection(candidate) as blocker:
            blocker.execute("LOCK TABLE skibidi_cringe_ip_activity IN ACCESS EXCLUSIVE MODE")
            with socket.create_connection(("127.0.0.1", candidate.ports.http), timeout=2) as sock:
                sock.sendall(("GET /api/cringe-ips/203.0.113.77 HTTP/1.1\r\nHost: localhost\r\nX-API-Key: " + _ADMIN_HEADERS[0][1] + "\r\n\r\n").encode())
                # Observe the blocked query before disconnecting; no guessed delay.
                with _connection(candidate) as probe:
                    deadline = time.monotonic() + 4
                    while True:
                        waiting = probe.execute("SELECT count(*) FROM pg_stat_activity WHERE datname='lmyzmail' AND wait_event_type='Lock' AND query LIKE '%skibidi_cringe_ip_activity%'").fetchone()[0]
                        if waiting:
                            break
                        assert time.monotonic() < deadline
                        time.sleep(0.02)
            blocker.rollback()
        _digest(_request(candidate, "203.0.113.77"), 501)
        with _connection(candidate) as connection:
            assert connection.execute("SELECT count(*) FROM pg_stat_activity WHERE datname='lmyzmail' AND pid<>pg_backend_pid() AND state='active' AND query LIKE 'SELECT %skibidi_cringe_ip%'").fetchone() == (0,)
