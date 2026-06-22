"""API smoke tests for MVP scan flows and schemas."""
from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.models.finding import Severity, VulnType
from app.schemas.finding import FindingCreate
from app.services.auth.browser_auth import normalize_cookies


async def _auth_headers(client: AsyncClient, email: str = "smoke@example.com") -> dict[str, str]:
    await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "strongpassword123", "full_name": "Smoke User"},
    )
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "strongpassword123"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.mark.asyncio
async def test_project_create_and_list():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        headers = await _auth_headers(client, "project-smoke@example.com")
        created = await client.post(
            "/api/v1/projects",
            json={"name": "Smoke Project", "description": "MVP smoke test"},
            headers=headers,
        )
        assert created.status_code == 201
        project = created.json()
        assert project["name"] == "Smoke Project"

        listed = await client.get("/api/v1/projects", headers=headers)
        assert listed.status_code == 200
        assert any(item["id"] == project["id"] for item in listed.json())


@pytest.mark.asyncio
async def test_scan_create_no_auth(monkeypatch):
    from app.api.v1 import scans as scans_api

    class DummyTask:
        id = "dummy-task-id"

    monkeypatch.setattr(scans_api.orchestrate_scan, "delay", lambda scan_id: DummyTask())

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        headers = await _auth_headers(client, "scan-smoke@example.com")
        project_response = await client.post(
            "/api/v1/projects",
            json={"name": "Scan Smoke"},
            headers=headers,
        )
        assert project_response.status_code == 201

        response = await client.post(
            "/api/v1/scans",
            json={
                "project_id": project_response.json()["id"],
                "target_url": "https://example.com",
                "auth": {"method": "none"},
            },
            headers=headers,
        )
        assert response.status_code == 201
        body = response.json()
        assert body["status"] == "pending"
        assert body["target_url"] == "https://example.com"


def test_cookie_normalize_accepts_devtools_and_netscape():
    devtools = '[{"name":"sid","value":"abc","domain":"example.com","path":"/","httpOnly":true}]'
    assert normalize_cookies(devtools)[0]["name"] == "sid"

    netscape = "example.com\tTRUE\t/\tFALSE\t0\tsid\tabc"
    cookies = normalize_cookies(netscape)
    assert cookies == [
        {
            "name": "sid",
            "value": "abc",
            "domain": "example.com",
            "path": "/",
            "expires": 0,
            "httpOnly": True,
            "secure": False,
        }
    ]


def test_finding_schema_accepts_poc_fields():
    finding = FindingCreate(
        agent_name="smoke",
        vulnerability_type=VulnType.XSS,
        severity=Severity.HIGH,
        title="DOM XSS candidate",
        description="Unsanitized hash is rendered into the DOM.",
        poc={"payload": "<img src=x onerror=alert(1)>"},
        reproduction_steps=["Open the page", "Set the hash payload"],
        code_snippet="output.innerHTML = location.hash",
    )
    assert finding.poc["payload"].startswith("<img")
    assert finding.reproduction_steps == ["Open the page", "Set the hash payload"]
