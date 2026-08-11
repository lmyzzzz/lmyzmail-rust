from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from playwright.sync_api import (
    Browser,
    BrowserContext,
    Page,
    Route,
    ViewportSize,
    sync_playwright,
)

from .differential import RuntimeTarget
from .errors import HarnessError

_CHROMIUM_REVISION = "1181"
_DESKTOP_VIEWPORT: ViewportSize = {"width": 1280, "height": 720}
_MOBILE_VIEWPORT: ViewportSize = {"width": 390, "height": 844}
_INTER_CSS_URL = "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap"
_MATERIAL_CSS_URL = "https://fonts.googleapis.com/icon?family=Material+Icons+Outlined"
_INTER_FONT_URL = "https://fonts.gstatic.com/s/inter/v20/UcC73FwrK3iLTeHuS_nVMrMxCp50SjIa1ZL7.woff2"
_MATERIAL_FONT_URL = (
    "https://fonts.gstatic.com/s/materialiconsoutlined/v110/"
    "gok-H7zzDkdnRel8-DQ6KAXJ69wP1tGnf4ZGhUce.woff2"
)
_VUE_URLS = {
    "https://unpkg.com/vue@3/dist/vue.global.prod.js",
    "https://unpkg.com/vue@3.5.41/dist/vue.global.prod.js",
}
_PINNED_FIXTURE_FILES = {
    "inter-latin-v20.woff2",
    "inter-v20.css",
    "material-icons-outlined-v110.css",
    "material-icons-outlined-v110.woff2",
    "vue.global.prod-3.5.41.js",
}
_DETERMINISTIC_RENDERING_CSS = """
*, *::before, *::after {
    animation-delay: 0s !important;
    animation-duration: 0s !important;
    caret-color: transparent !important;
    transition-delay: 0s !important;
    transition-duration: 0s !important;
}
"""


@dataclass(frozen=True, slots=True)
class WebUiCapture:
    observation: dict[str, Any]
    artifacts: tuple[tuple[str, bytes], ...]


@dataclass(frozen=True, slots=True)
class _PinnedResource:
    name: str
    path: Path
    content_type: str


def _repository() -> Path:
    return Path(__file__).resolve().parents[3]


def _verify_fixture_manifest(root: Path) -> None:
    manifest_path = root / "SOURCE.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise HarnessError(f"pinned browser fixture manifest is unavailable: {manifest_path}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        entries = manifest["resources"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise HarnessError(f"invalid pinned browser fixture manifest: {manifest_path}") from error
    if not isinstance(entries, list):
        raise HarnessError(f"invalid pinned browser fixture resource list: {manifest_path}")

    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise HarnessError(f"invalid pinned browser fixture entry: {entry!r}")
        name = entry.get("file")
        expected_size = entry.get("bytes")
        expected_sha256 = entry.get("sha256")
        if (
            not isinstance(name, str)
            or name not in _PINNED_FIXTURE_FILES
            or "/" in name
            or "\\" in name
            or name in seen
            or not isinstance(expected_size, int)
            or expected_size < 0
            or not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
        ):
            raise HarnessError(f"invalid pinned browser fixture entry: {entry!r}")
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise HarnessError(f"pinned browser fixture is missing or symlinked: {path}")
        with path.open("rb") as stream:
            actual_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
        if path.stat().st_size != expected_size or actual_sha256 != expected_sha256:
            raise HarnessError(f"pinned browser fixture does not match its manifest: {path}")
        seen.add(name)
    if seen != _PINNED_FIXTURE_FILES:
        raise HarnessError(
            "pinned browser fixture manifest is incomplete: "
            f"missing={sorted(_PINNED_FIXTURE_FILES - seen)!r}"
        )


def _pinned_resources(repository: Path) -> dict[str, _PinnedResource]:
    root = repository / "blackbox/fixtures/web-static/third-party"
    _verify_fixture_manifest(root)
    vue = _PinnedResource(
        "vue-3.5.41",
        root / "vue.global.prod-3.5.41.js",
        "text/javascript; charset=utf-8",
    )
    resources = {
        _INTER_CSS_URL: _PinnedResource(
            "inter-v20-css", root / "inter-v20.css", "text/css; charset=utf-8"
        ),
        _MATERIAL_CSS_URL: _PinnedResource(
            "material-icons-v110-css",
            root / "material-icons-outlined-v110.css",
            "text/css; charset=utf-8",
        ),
        _INTER_FONT_URL: _PinnedResource(
            "inter-v20-latin-font", root / "inter-latin-v20.woff2", "font/woff2"
        ),
        _MATERIAL_FONT_URL: _PinnedResource(
            "material-icons-v110-font",
            root / "material-icons-outlined-v110.woff2",
            "font/woff2",
        ),
    }
    resources.update((url, vue) for url in _VUE_URLS)
    for resource in resources.values():
        if resource.path.is_symlink() or not resource.path.is_file():
            raise HarnessError(f"pinned browser fixture is missing or symlinked: {resource.path}")
    return resources


def _install_network_policy(
    context: BrowserContext,
    *,
    application_origin: str,
    resources: dict[str, _PinnedResource],
    used_resources: set[str],
    unexpected_urls: list[str],
) -> None:
    resource_bytes = {url: resource.path.read_bytes() for url, resource in resources.items()}

    def route_request(route: Route) -> None:
        url = route.request.url
        if url == application_origin or url.startswith(f"{application_origin}/"):
            route.continue_()
            return
        resource = resources.get(url)
        if resource is not None:
            used_resources.add(resource.name)
            route.fulfill(
                status=200,
                body=resource_bytes[url],
                content_type=resource.content_type,
            )
            return
        unexpected_urls.append(url)
        route.abort("blockedbyclient")

    context.route("**/*", route_request)


def _new_context(
    browser: Browser,
    viewport: ViewportSize,
    *,
    application_origin: str,
    resources: dict[str, _PinnedResource],
    used_resources: set[str],
    unexpected_urls: list[str],
) -> BrowserContext:
    context = browser.new_context(
        viewport=viewport,
        device_scale_factor=1,
        locale="zh-CN",
        timezone_id="UTC",
        color_scheme="light",
        reduced_motion="reduce",
    )
    _install_network_policy(
        context,
        application_origin=application_origin,
        resources=resources,
        used_resources=used_resources,
        unexpected_urls=unexpected_urls,
    )
    return context


def _attach_error_capture(
    page: Page,
    console_errors: list[str],
    page_errors: list[str],
    request_failures: list[str],
) -> None:
    page.on(
        "console",
        lambda message: console_errors.append(message.text) if message.type == "error" else None,
    )
    page.on("pageerror", lambda error: page_errors.append(str(error)))
    page.on(
        "requestfailed",
        lambda request: request_failures.append(
            f"{request.method} {request.url}: {request.failure or 'unknown failure'}"
        ),
    )


def _settle_page(page: Page) -> None:
    page.wait_for_load_state("networkidle")
    page.evaluate("() => document.fonts.ready")
    page.evaluate(
        "() => {"
        " const active = document.activeElement;"
        " if (active instanceof HTMLElement) active.blur();"
        "}"
    )
    page.evaluate(
        "() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))"
    )


def _install_deterministic_rendering(page: Page) -> None:
    page.add_style_tag(content=_DETERMINISTIC_RENDERING_CSS)


def _capture_state(
    page: Page,
    name: str,
    anchor_selector: str,
    states: list[dict[str, Any]],
    artifacts: list[tuple[str, bytes]],
) -> None:
    _settle_page(page)
    anchor = page.locator(anchor_selector)
    anchor.wait_for(state="visible")
    bounding_box = anchor.bounding_box()
    if bounding_box is None:
        raise HarnessError(f"UI anchor has no bounding box: {anchor_selector}")
    visible_text = page.locator("body").inner_text()
    states.append(
        {
            "name": name,
            "title": page.title(),
            "path": urlsplit(page.url).path,
            "visible_text_sha256": hashlib.sha256(visible_text.encode("utf-8")).hexdigest(),
            "anchor": {
                "selector": anchor_selector,
                "x": round(bounding_box["x"], 3),
                "y": round(bounding_box["y"], 3),
                "width": round(bounding_box["width"], 3),
                "height": round(bounding_box["height"], 3),
            },
        }
    )
    artifacts.append(
        (
            f"{name}.png",
            page.screenshot(
                animations="disabled",
                caret="hide",
                full_page=False,
                scale="css",
                type="png",
            ),
        )
    )


def _capture_desktop(
    browser: Browser,
    application_origin: str,
    resources: dict[str, _PinnedResource],
    used_resources: set[str],
    unexpected_urls: list[str],
    console_errors: list[str],
    page_errors: list[str],
    request_failures: list[str],
    states: list[dict[str, Any]],
    artifacts: list[tuple[str, bytes]],
) -> None:
    context = _new_context(
        browser,
        _DESKTOP_VIEWPORT,
        application_origin=application_origin,
        resources=resources,
        used_resources=used_resources,
        unexpected_urls=unexpected_urls,
    )
    try:
        page = context.new_page()
        _attach_error_capture(page, console_errors, page_errors, request_failures)
        page.goto(application_origin, wait_until="networkidle")
        _install_deterministic_rendering(page)
        page.locator(".auth-tab").nth(1).wait_for(state="visible")
        _capture_state(page, "desktop-login", ".auth-card", states, artifacts)

        page.get_by_role("button", name="注册", exact=True).click()
        page.locator("form.auth-form input[type='text']").fill("pixel-user")
        password_inputs = page.locator("form.auth-form input[type='password']")
        password_inputs.nth(0).fill("BlackboxPass123!")
        password_inputs.nth(1).fill("DifferentPass123!")
        page.locator("form.auth-form").get_by_role("button", name="注册", exact=True).click()
        page.locator(".auth-error").wait_for(state="visible")
        password_inputs.nth(0).fill("")
        password_inputs.nth(1).fill("")
        _capture_state(
            page,
            "desktop-register-validation",
            ".auth-card",
            states,
            artifacts,
        )

        page.get_by_role("button", name="登录", exact=True).first.click()
        login_form = page.locator("form.auth-form")
        login_form.locator("input[type='text']").fill("qa@example.test")
        login_form.locator("input[type='password']").fill("BlackboxPass123!")
        with page.expect_response(
            lambda response: urlsplit(response.url).path == "/web/login"
            and response.request.method == "POST"
        ) as login_response_info:
            login_form.get_by_role("button", name="登录", exact=True).click()
        login_response = login_response_info.value
        if login_response.status != 200:
            raise HarnessError(
                "managed QA login failed: "
                f"status={login_response.status}, body={login_response.text()!r}"
            )
        page.locator(".app-layout").wait_for(state="visible")
        _capture_state(page, "desktop-inbox", ".app-layout", states, artifacts)

        page.locator(".btn-compose").click()
        page.locator(".compose-modal").wait_for(state="visible")
        _capture_state(page, "desktop-compose", ".compose-modal", states, artifacts)
    finally:
        context.close()


def _capture_mobile(
    browser: Browser,
    application_origin: str,
    resources: dict[str, _PinnedResource],
    used_resources: set[str],
    unexpected_urls: list[str],
    console_errors: list[str],
    page_errors: list[str],
    request_failures: list[str],
    states: list[dict[str, Any]],
    artifacts: list[tuple[str, bytes]],
) -> None:
    context = _new_context(
        browser,
        _MOBILE_VIEWPORT,
        application_origin=application_origin,
        resources=resources,
        used_resources=used_resources,
        unexpected_urls=unexpected_urls,
    )
    try:
        page = context.new_page()
        _attach_error_capture(page, console_errors, page_errors, request_failures)
        page.goto(application_origin, wait_until="networkidle")
        _install_deterministic_rendering(page)
        page.locator(".auth-tab").nth(1).wait_for(state="visible")
        _capture_state(page, "mobile-login", ".auth-card", states, artifacts)
    finally:
        context.close()


def capture_web_ui(target: RuntimeTarget) -> WebUiCapture:
    if target.ports is None:
        raise AssertionError("runtime ports are unavailable")
    repository = _repository()
    browser_executable = (
        repository
        / ".blackbox/ms-playwright"
        / f"chromium-{_CHROMIUM_REVISION}"
        / "chrome-linux/chrome"
    )
    if browser_executable.is_symlink() or not browser_executable.is_file():
        raise HarnessError(f"pinned Chromium executable is unavailable: {browser_executable}")

    application_origin = f"http://127.0.0.1:{target.ports.http}"
    resources = _pinned_resources(repository)
    used_resources: set[str] = set()
    unexpected_urls: list[str] = []
    console_errors: list[str] = []
    page_errors: list[str] = []
    request_failures: list[str] = []
    states: list[dict[str, Any]] = []
    artifacts: list[tuple[str, bytes]] = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=str(browser_executable),
            headless=True,
            chromium_sandbox=False,
            args=["--disable-gpu", "--disable-lcd-text", "--font-render-hinting=none"],
        )
        try:
            _capture_desktop(
                browser,
                application_origin,
                resources,
                used_resources,
                unexpected_urls,
                console_errors,
                page_errors,
                request_failures,
                states,
                artifacts,
            )
            _capture_mobile(
                browser,
                application_origin,
                resources,
                used_resources,
                unexpected_urls,
                console_errors,
                page_errors,
                request_failures,
                states,
                artifacts,
            )
        finally:
            browser.close()

    expected_resources = {resource.name for resource in resources.values()}
    if unexpected_urls:
        raise HarnessError(f"browser attempted unpinned network requests: {unexpected_urls!r}")
    if used_resources != expected_resources:
        missing = sorted(expected_resources - used_resources)
        raise HarnessError(f"browser did not consume pinned resources: {missing!r}")
    if console_errors or page_errors or request_failures:
        raise HarnessError(
            "browser errors were observed: "
            f"console={console_errors!r}, page={page_errors!r}, requests={request_failures!r}"
        )

    return WebUiCapture(
        observation={
            "browser": {
                "engine": "chromium",
                "revision": _CHROMIUM_REVISION,
                "locale": "zh-CN",
                "timezone": "UTC",
                "device_scale_factor": 1,
                "desktop_viewport": _DESKTOP_VIEWPORT,
                "mobile_viewport": _MOBILE_VIEWPORT,
            },
            "network": {
                "policy": "application origin plus exact pinned fixtures; all other URLs blocked",
                "pinned_resources": sorted(used_resources),
                "unexpected_urls": [],
            },
            "errors": {"console": [], "page": [], "requests": []},
            "states": states,
        },
        artifacts=tuple(artifacts),
    )


WEB_UI_CONTRACT = {
    "protocol": "Playwright 1.54.0 with pinned Chromium revision 1181",
    "states": [
        "desktop login",
        "desktop registration validation",
        "desktop authenticated inbox",
        "desktop compose",
        "mobile login",
    ],
    "interactions": [
        "registration tab and client-side password confirmation validation",
        "database-backed login with the managed QA account",
        "authenticated mailbox bootstrap",
        "compose window open",
    ],
    "rendering": (
        "exact PNG bytes at fixed viewports, scale, locale, timezone, fonts, motion, "
        "disabled CSS transitions, blurred focus, and cleared password fields after validation"
    ),
    "network": "exact pinned Vue/font fixtures with deny-by-default external requests",
}
