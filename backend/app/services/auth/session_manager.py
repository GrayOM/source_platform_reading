"""Load and inject a captured session into a Playwright browser context."""
import json

from playwright.async_api import BrowserContext

from app.core.security import decrypt_session_data
from app.models.scan import AuthMethod, ScanSession


async def apply_session_to_context(session: ScanSession, context: BrowserContext) -> None:
    """Inject stored auth data into a Playwright context before crawling."""
    if session.auth_method == AuthMethod.NONE:
        return

    if session.cookies_encrypted:
        raw = decrypt_session_data(session.cookies_encrypted)
        cookies: list[dict] = json.loads(raw.decode("utf-8"))
        if cookies:
            await context.add_cookies(cookies)

    if session.headers_encrypted:
        raw = decrypt_session_data(session.headers_encrypted)
        headers: dict[str, str] = json.loads(raw.decode("utf-8"))
        if headers:
            await context.set_extra_http_headers(headers)

    if session.storage_encrypted:
        raw = decrypt_session_data(session.storage_encrypted)
        storage: dict = json.loads(raw.decode("utf-8"))
        local_storage = storage.get("local_storage", {})
        session_storage = storage.get("session_storage", {})
        if local_storage or session_storage:
            # Inject via init script — runs on every page before any JS
            await context.add_init_script(f"""
                (function() {{
                    const localData = {json.dumps(local_storage)};
                    const sessionData = {json.dumps(session_storage)};
                    for (const [k, v] of Object.entries(localData)) {{
                        localStorage.setItem(k, v);
                    }}
                    for (const [k, v] of Object.entries(sessionData)) {{
                        sessionStorage.setItem(k, v);
                    }}
                }})();
            """)
