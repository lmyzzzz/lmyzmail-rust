from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast

import pytest
from playwright.sync_api import expect, sync_playwright
from test_candidate_cringe_api_golden import (
    _ADMIN_HEADERS,
    _READ_ONLY_HEADERS,
    _WRITE_ONLY_HEADERS,
    _candidate,
    _OracleTarget,
    _seed_cringe_fixture,
)
from test_candidate_cringe_list_golden import _connection, _seed_list, _state

from lmyzmail_blackbox.differential import DifferentialRunner, RuntimeTarget, Scenario
from lmyzmail_blackbox.persistent_runtime import PersistentJavaOracleRuntime
from lmyzmail_blackbox.protocols import http_exchange
from lmyzmail_blackbox.snapshots import bytes_snapshot, http_json_snapshot
from lmyzmail_blackbox.web_ui_contract import _new_context, _pinned_resources, _settle_page

_PROFILE = "managed-cringe-stats"
_GOLDEN = "blackbox/golden/java/managed-cringe-stats-v2"


class _CustomDecayOracle(PersistentJavaOracleRuntime):
    def _application_arguments(self) -> list[str]:
        return [
            *super()._application_arguments(),
            "--botmail.cringe.decay.interval=5400001ms",
            "--botmail.cringe.decay.amount=7",
        ]


def _request(target: RuntimeTarget, headers: Any = _ADMIN_HEADERS) -> Any:
    assert target.ports is not None
    return http_exchange(
        "127.0.0.1", target.ports.http, "GET", "/api/cringe-ips/stats",
        headers=headers, timeout=12.0,
    )


def _capture_stats(target: RuntimeTarget) -> dict[str, Any]:
    with _connection(target) as connection:
        connection.execute("DELETE FROM skibidi_cringe_ip_activity")
        connection.execute("DELETE FROM skibidi_cringe_ip")
    observed = {"empty": http_json_snapshot(_request(target))}
    _seed_cringe_fixture(target)
    with _connection(target) as connection:
        connection.execute(
            "UPDATE skibidi_cringe_ip SET total_score=-1,current_score=51 "
            "WHERE ip_address='203.0.113.77'"
        )
        connection.execute(
            "UPDATE skibidi_cringe_ip SET total_score=0,current_score=0 "
            "WHERE ip_address='198.51.100.9'"
        )
        for i, (total, current) in enumerate(((1, -1), (49, 50), (50, 49), (51, 1))):
            connection.execute(
                """INSERT INTO skibidi_cringe_ip (
                    ip_address,total_score,current_score,activity_count,
                    first_seen_at,last_seen_at,last_decay_at,
                    self_spoofing_count,open_relay_count,auth_probe_count,
                    illegal_domain_count,spamhaus_count,http_on_smtp_count,
                    ssh_on_smtp_count,http_port_scanning_count,honeypot_hit_count,
                    other_count,pps_overlimit_count,syn_flood_count,ssh_bruteforce_count)
                SELECT 'stats-' || %s, %s, %s, 100,
                       first_seen_at,last_seen_at,last_decay_at,
                       self_spoofing_count,open_relay_count,auth_probe_count,
                       illegal_domain_count,spamhaus_count,http_on_smtp_count,
                       ssh_on_smtp_count,http_port_scanning_count,honeypot_hit_count,
                       other_count,pps_overlimit_count,syn_flood_count,ssh_bruteforce_count
                FROM skibidi_cringe_ip WHERE ip_address='203.0.113.77'""",
                (str(i), total, current),
            )
    before = _state(target)
    for label, headers in (
        ("populated", _ADMIN_HEADERS), ("read_only", _READ_ONLY_HEADERS),
        ("missing", ()), ("write_only", _WRITE_ONLY_HEADERS),
    ):
        response = _request(target, headers)
        observed[label] = http_json_snapshot(
            response, canonicalize_object_order=response.status_code != 200,
        )
    assert _state(target) == before
    body = json.loads(_request(target).body)
    assert {key: body[key] for key in (
        "totalIPs", "highRiskByTotal", "highRiskByCurrent", "activeThreats", "totalActivities",
    )} == dict(zip(
        ("totalIPs", "highRiskByTotal", "highRiskByCurrent", "activeThreats", "totalActivities"),
        (6, 2, 2, 4, 5), strict=True,
    ))
    with _connection(target) as connection:
        assert connection.execute(
            "SELECT count(*) FROM skibidi_cringe_ip_activity"
        ).fetchone() == (5,)
    return observed


cast(Any, _capture_stats).__lmyzmail_contract__ = {
    "protocol": "http/raw-socket",
    "sequence": [
        "query empty isolated database",
        "seed independent total/current scores -1,0,1,49,50,51 and five actual activities",
        "query admin/read-only/missing/write-only and verify database unchanged",
    ],
    "state": "direct-write mode, XDP disabled, fixed fixture timestamps",
    "normalization": "HTTP Date and established JDK Map.of API-key error order only",
}
_STATS = (Scenario(
    "http/cringe/stats", _capture_stats,
    normalizers=("json-object-order:jdk-map-of:cringe-api-key-errors",),
),)


def _capture_dashboard(target: RuntimeTarget) -> dict[str, Any]:
    repository = Path(__file__).resolve().parents[2]
    assert target.ports is not None
    _seed_list(target)
    with _connection(target) as connection:
        for i in range(17):
            connection.execute(
                """INSERT INTO skibidi_cringe_ip (
                    ip_address,total_score,current_score,activity_count,
                    first_seen_at,last_seen_at,last_decay_at,
                    self_spoofing_count,open_relay_count,auth_probe_count,
                    illegal_domain_count,spamhaus_count,http_on_smtp_count,
                    ssh_on_smtp_count,http_port_scanning_count,honeypot_hit_count,
                    other_count,pps_overlimit_count,syn_flood_count,ssh_bruteforce_count)
                SELECT '192.0.2.' || %s,100+%s,100+%s,activity_count,
                       first_seen_at,last_seen_at,last_decay_at,
                       self_spoofing_count,open_relay_count,auth_probe_count,
                       illegal_domain_count,spamhaus_count,http_on_smtp_count,
                       ssh_on_smtp_count,http_port_scanning_count,honeypot_hit_count,
                       other_count,pps_overlimit_count,syn_flood_count,ssh_bruteforce_count
                FROM skibidi_cringe_ip WHERE ip_address='203.0.113.77'""",
                (str(i), i, i),
            )
    origin = f"http://127.0.0.1:{target.ports.http}"
    unexpected: list[str] = []
    errors: list[str] = []
    requests: list[str] = []
    observed: dict[str, Any] = {}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=str(
                repository / ".blackbox/ms-playwright/chromium-1181/chrome-linux/chrome"
            ),
            headless=True, chromium_sandbox=False,
            args=["--disable-gpu", "--disable-lcd-text", "--font-render-hinting=none"],
        )
        context = _new_context(
            browser, {"width": 1440, "height": 1100}, application_origin=origin,
            resources=_pinned_resources(repository), used_resources=set(),
            unexpected_urls=unexpected,
        )
        page = context.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("request", lambda request: requests.append(request.url.removeprefix(origin)))
        page.goto(origin + "/cringe.html")
        page.get_by_placeholder("API Key", exact=True).fill(_READ_ONLY_HEADERS[0][1])
        page.get_by_role("button", name="Connect", exact=True).click()
        expect(page.get_by_role("button", name="Disconnect", exact=True)).to_be_visible()
        expect(page.locator("tbody tr")).to_have_count(20)
        expect(page.locator(".pagination span")).to_have_text("Page 1 / 2 (21 total)")
        expect(page.locator(".stat-card .value").first).to_have_text("21")
        _settle_page(page)
        observed["connected_cards"] = page.locator(".stat-card").all_text_contents()
        observed["connected_rows"] = page.locator("tbody tr").all_text_contents()
        observed["connected_png"] = bytes_snapshot(page.screenshot(animations="disabled"))
        page.get_by_role("button", name="Next", exact=True).click()
        expect(page.locator("tbody tr")).to_have_count(1)
        expect(page.locator(".pagination span")).to_have_text("Page 2 / 2 (21 total)")
        observed["last_page"] = page.locator("tbody tr").all_text_contents()
        page.get_by_role("button", name="Prev", exact=True).click()
        expect(page.locator("tbody tr")).to_have_count(20)
        page.locator("th").filter(has_text="Total Score").click()
        _settle_page(page)
        observed["sorted"] = page.locator("tbody tr").all_text_contents()
        page.get_by_placeholder("🔍 Search IP address...").fill("DB8")
        page.get_by_role("button", name="🔍 Search", exact=True).click()
        expect(page.locator("tbody tr")).to_have_count(1)
        expect(page.locator(".pagination span")).to_have_text("Page 1 / 1 (1 total)")
        observed["searched"] = page.locator("tbody tr").all_text_contents()
        page.get_by_placeholder("🔍 Search IP address...").fill("absent-ip")
        page.get_by_role("button", name="🔍 Search", exact=True).click()
        expect(page.locator(".no-results")).to_contain_text('No IPs found matching "absent-ip"')
        observed["empty_search"] = page.locator(".no-results").inner_text()
        page.get_by_role("button", name="Disconnect", exact=True).click()
        expect(page.locator(".stats")).to_have_count(0)
        assert page.evaluate("localStorage.getItem('cringeApiKey')") is None
        assert errors == []
        assert unexpected == []
        assert "/api/cringe-ips/stats" in requests
        assert any(url.startswith("/api/cringe-ips?page=") for url in requests)
        observed["requests"] = [url for url in requests if url.startswith("/api/")]
        context.close()
        browser.close()
    return observed


cast(Any, _capture_dashboard).__lmyzmail_contract__ = {
    "protocol": "http/playwright/chromium-1181",
    "sequence": [
        "connect using real read-only API and real stats, list, decay, XDP responses",
        "check 21 rows across two pages, sort, IPv6 search, empty search and disconnect",
        "compare visible cards, rows, requests and exact connected screenshot bytes",
    ],
    "state": "fixed PostgreSQL fixture, direct writes, XDP disabled, pinned Vue CDN fixture",
    "normalization": "origin port only; UTC zh-CN viewport 1440x1100; animations disabled",
}
_UI = (Scenario("http/cringe/dashboard", _capture_dashboard),)


@pytest.mark.integration
@pytest.mark.oracle
@pytest.mark.parametrize("profile", ("default", "custom", "dashboard"))
@pytest.mark.timeout(180)
def test_frozen_java_cringe_stats_golden(
    tmp_path: Path, record_java_golden: bool, profile: str,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    runtime_type = _CustomDecayOracle if profile == "custom" else PersistentJavaOracleRuntime
    with runtime_type(tmp_path / ("java-cringe-stats-" + profile)) as oracle:
        runner = DifferentialRunner(
            repository, repository / (_GOLDEN + "-" + profile), _PROFILE + "-" + profile,
            record_java=record_java_golden,
        )
        scenarios = _UI if profile == "dashboard" else _STATS
        if record_java_golden:
            runner.record_from_java(scenarios, _OracleTarget(oracle))
        else:
            runner.verify_java(scenarios, _OracleTarget(oracle))


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.parametrize("profile", ("default", "custom", "dashboard"))
@pytest.mark.timeout(180)
def test_candidate_cringe_stats_matches_frozen_java(profile: str) -> None:
    repository = Path(__file__).resolve().parents[2]
    overrides = (
        "--botmail.cringe.decay.interval=1h", "--botmail.cringe.decay.amount=3",
        "--lmyzmail.cringe.decay.interval=5400001ms", "--lmyzmail.cringe.decay.amount=7",
    ) if profile == "custom" else ()
    with _candidate(repository, *overrides) as candidate:
        DifferentialRunner(
            repository, repository / (_GOLDEN + "-" + profile), _PROFILE + "-" + profile,
        ).verify_candidate(_UI if profile == "dashboard" else _STATS, candidate)


@pytest.mark.integration
@pytest.mark.candidate
@pytest.mark.timeout(180)
def test_candidate_stats_concurrent_timeout_and_pool_recovery() -> None:
    repository = Path(__file__).resolve().parents[2]
    with _candidate(repository, "--lmyzmail.postgres.pool.max-size=1") as candidate:
        _capture_stats(candidate)
        with ThreadPoolExecutor(max_workers=8) as workers:
            responses = list(workers.map(lambda _: _request(candidate), range(24)))
        assert all(response.status_code == 200 for response in responses)
        assert all(json.loads(response.body)["totalIPs"] == 6 for response in responses)
        for table in ("skibidi_cringe_ip", "skibidi_cringe_ip_activity"):
            with _connection(candidate) as blocker:
                blocker.execute(f"LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE")
                start = time.monotonic()
                forbidden = _request(candidate, _WRITE_ONLY_HEADERS)
                assert forbidden.status_code == 403
                assert time.monotonic() - start < 2.0
                start = time.monotonic()
                stalled = _request(candidate)
                assert stalled.status_code == 500
                assert json.loads(stalled.body) == {"error": "internal_error"}
                assert 7.0 <= time.monotonic() - start <= 11.0
                blocker.rollback()
            assert json.loads(_request(candidate).body)["totalActivities"] == 5
        with _connection(candidate) as connection:
            assert connection.execute(
                """SELECT count(*) FROM pg_stat_activity WHERE datname='lmyzmail'
                AND pid<>pg_backend_pid() AND state='active'
                AND query LIKE 'SELECT %skibidi_cringe_ip%'"""
            ).fetchone() == (0,)
