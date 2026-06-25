from types import SimpleNamespace

import pytest

from app.services.auth import browser_auth
from app.services.auth.browser_auth import CapturedSession, HEADED_BROWSER_ERROR
from app.services.crawler.crawler import PlaywrightCrawler


def _settings(**overrides):
    values = {
        "browser_auth_mode": "manual",
        "e2e_browser_auth_enabled": True,
        "environment": "development",
        "e2e_browser_auth_allowed_hosts_list": ["vulnerable-site", "localhost", "127.0.0.1"],
        "e2e_browser_auth_email": "demo@example.com",
        "e2e_browser_auth_password": "password123!",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_authenticated_crawler_metadata_marks_resources_after_login(tmp_path):
    session = SimpleNamespace(auth_method=SimpleNamespace(value="browser"))
    crawler = PlaywrightCrawler(
        scan_id="scan-id",
        target_url="http://vulnerable-site/login/",
        session=session,
        config={},
        output_dir=tmp_path,
    )

    assert crawler._resource_metadata()["auth_context"] == "authenticated"
    assert crawler._resource_metadata()["discovered_after_login"] is True


def test_e2e_auto_login_is_allowed_only_for_allowlisted_host():
    settings = _settings()

    assert browser_auth._should_use_e2e_auto_login("http://vulnerable-site/login/", settings) is True
    assert browser_auth._should_use_e2e_auto_login("http://localhost/login/", settings) is True
    assert browser_auth._should_use_e2e_auto_login("http://example.com/login/", settings) is False


def test_e2e_auto_login_is_disabled_outside_development_like_environments():
    settings = _settings(environment="production")

    assert browser_auth._should_use_e2e_auto_login("http://vulnerable-site/login/", settings) is False


@pytest.mark.asyncio
async def test_e2e_mode_rejects_non_allowlisted_target(monkeypatch):
    monkeypatch.setattr(
        browser_auth,
        "get_settings",
        lambda: _settings(browser_auth_mode="e2e"),
    )

    with pytest.raises(RuntimeError, match="not allowed"):
        await browser_auth.run_browser_auth_session("http://example.com/login/")


@pytest.mark.asyncio
async def test_manual_headed_mode_without_display_fails_clearly(monkeypatch):
    monkeypatch.delenv("DISPLAY", raising=False)

    with pytest.raises(RuntimeError, match="Headed browser requires DISPLAY/XServer"):
        await browser_auth.run_manual_browser_auth_session("http://vulnerable-site/login/")

    assert "allowed test targets" in HEADED_BROWSER_ERROR


@pytest.mark.asyncio
async def test_browser_auth_uses_headless_e2e_auto_login_for_allowed_target(monkeypatch):
    captured = CapturedSession(
        cookies=[{"name": "e2e_session", "value": "headless-login", "domain": "vulnerable-site", "path": "/"}],
        local_storage={"access_token": "e2e-headless-browser-login-token"},
        session_storage={"session_token": "e2e-headless-session-token"},
        extra_headers={"Authorization": "Bearer e2e-headless-browser-login-token"},
    )

    async def fake_auto_login(target_url, current_settings=None):
        assert target_url == "http://vulnerable-site/login/"
        return captured

    async def fail_manual(*args, **kwargs):
        raise AssertionError("manual headed mode should not run for allowlisted E2E target")

    monkeypatch.setattr(browser_auth, "get_settings", lambda: _settings())
    monkeypatch.setattr(browser_auth, "run_e2e_auto_login_session", fake_auto_login)
    monkeypatch.setattr(browser_auth, "run_manual_browser_auth_session", fail_manual)

    result = await browser_auth.run_browser_auth_session("http://vulnerable-site/login/")

    assert result.local_storage["access_token"] == "e2e-headless-browser-login-token"
    assert result.extra_headers["Authorization"].startswith("Bearer ")
