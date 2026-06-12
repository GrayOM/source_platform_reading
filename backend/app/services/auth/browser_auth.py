"""Browser-assisted authentication via Playwright.

The user sees a real Chromium window, logs in manually, then closes the
browser (or clicks 'Done' in the UI).  Playwright captures all cookies,
localStorage, and outgoing Authorization headers so the crawler can
impersonate the authenticated session.
"""
import asyncio
import json
import time
from dataclasses import dataclass, field

from playwright.async_api import BrowserContext, Page, async_playwright

from app.core.config import get_settings

settings = get_settings()


@dataclass
class CapturedSession:
    cookies: list[dict] = field(default_factory=list)
    local_storage: dict[str, str] = field(default_factory=dict)
    session_storage: dict[str, str] = field(default_factory=dict)
    extra_headers: dict[str, str] = field(default_factory=dict)


async def run_browser_auth_session(target_url: str, timeout_seconds: int = 300) -> CapturedSession:
    """
    Opens a headed Chromium window pointed at target_url.
    Waits for the user to authenticate, then captures the session.
    Returns when the user closes the browser or timeout is reached.
    """
    captured_headers: dict[str, str] = {}
    session_done = asyncio.Event()

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=False,
            args=["--no-sandbox", "--disable-blink-features=AutomationControlled"],
        )
        context: BrowserContext = await browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
        )

        async def on_request(request):
            auth = request.headers.get("authorization")
            if auth and auth not in captured_headers.values():
                captured_headers["Authorization"] = auth

        context.on("request", on_request)

        page: Page = await context.new_page()
        await page.goto(target_url, wait_until="domcontentloaded")

        # Inject a floating "Done" button the user clicks to end auth
        await page.evaluate("""
            const btn = document.createElement('button');
            btn.innerText = '✓ Done — Submit to SSS';
            btn.style.cssText = `
                position:fixed; bottom:20px; right:20px; z-index:99999;
                background:#00e676; color:#000; font-weight:bold;
                border:none; border-radius:8px; padding:12px 24px;
                cursor:pointer; font-size:15px; box-shadow:0 4px 12px rgba(0,0,0,0.3);
            `;
            btn.id = '__sss_done__';
            document.body.appendChild(btn);
        """)

        done_future: asyncio.Future = asyncio.get_event_loop().create_future()

        async def handle_done(msg):
            if not done_future.done():
                done_future.set_result(True)

        await page.expose_function("__sss_signal_done__", handle_done)
        await page.evaluate("""
            document.getElementById('__sss_done__').addEventListener('click', () => {
                window.__sss_signal_done__('done');
            });
        """)

        try:
            await asyncio.wait_for(done_future, timeout=timeout_seconds)
        except asyncio.TimeoutError:
            pass

        cookies = await context.cookies()
        local_storage = await page.evaluate(
            "() => Object.fromEntries(Object.entries(localStorage))"
        )
        session_storage = await page.evaluate(
            "() => Object.fromEntries(Object.entries(sessionStorage))"
        )

        await browser.close()

    return CapturedSession(
        cookies=cookies,
        local_storage=local_storage or {},
        session_storage=session_storage or {},
        extra_headers=captured_headers,
    )


def parse_cookies_json(raw: str) -> list[dict]:
    """Parse JSON array of cookies (Burp/DevTools format)."""
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "cookies" in data:
            return data["cookies"]
    except json.JSONDecodeError:
        pass
    return []


def parse_netscape_cookies(text: str) -> list[dict]:
    """Parse Netscape/curl cookie file format."""
    cookies = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 7:
            cookies.append({
                "domain": parts[0],
                "httpOnly": parts[1].lower() == "true",
                "path": parts[2],
                "secure": parts[3].lower() == "true",
                "expires": int(parts[4]) if parts[4].isdigit() else -1,
                "name": parts[5],
                "value": parts[6],
            })
    return cookies
