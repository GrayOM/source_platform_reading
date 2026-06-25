import json
import uuid
from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.main import app
from app.models.finding import Finding, Severity, TriageStatus, VulnType
from app.models.project import Project
from app.models.resource import Resource, ResourceType
from app.models.report import ReportFormat, ReportType
from app.models.scan import AuthMethod, Scan, ScanSession, ScanStatus
from app.models.user import User
from app.services.report.report_engine import ReportEngine
from app.services.scan_diff import build_cross_scan_diff


async def _auth_headers(client: AsyncClient, email: str) -> dict[str, str]:
    await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "strongpassword123", "full_name": "Report User"},
    )
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "strongpassword123"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def _create_completed_scan(project_id: uuid.UUID, target_url: str, auth_method: AuthMethod) -> uuid.UUID:
    async with AsyncSessionLocal() as db:
        scan = Scan(
            project_id=project_id,
            target_url=target_url,
            status=ScanStatus.COMPLETED,
            progress=100,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        await db.flush()
        db.add(ScanSession(scan_id=scan.id, auth_method=auth_method))
        await db.commit()
        return scan.id


async def _project_id_for(email: str) -> uuid.UUID:
    async with AsyncSessionLocal() as db:
        user = (await db.execute(select(User).where(User.email == email))).scalar_one()
        project = Project(user_id=user.id, name=f"Report project {email}")
        db.add(project)
        await db.flush()
        project_id = project.id
        await db.commit()
        return project_id


def _scan_pair() -> tuple[Scan, Scan, list[Finding]]:
    base = Scan(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        target_url="https://example.com/app",
        status=ScanStatus.COMPLETED,
    )
    base.session = ScanSession(scan_id=base.id, auth_method=AuthMethod.BROWSER)
    compare = Scan(
        id=uuid.uuid4(),
        project_id=base.project_id,
        target_url="https://example.com",
        status=ScanStatus.COMPLETED,
    )
    compare.session = ScanSession(scan_id=compare.id, auth_method=AuthMethod.NONE)
    compare.resources = [
        Resource(scan_id=compare.id, url="https://example.com/index.html", resource_type=ResourceType.HTML)
    ]
    base.resources = [
        Resource(scan_id=base.id, url="https://example.com/index.html", resource_type=ResourceType.HTML),
        Resource(scan_id=base.id, url="https://example.com/admin", resource_type=ResourceType.HTML),
        Resource(scan_id=base.id, url="https://example.com/app.js", resource_type=ResourceType.JS),
        Resource(scan_id=base.id, url="https://example.com/app.js.map", resource_type=ResourceType.SOURCE_MAP),
    ]
    finding = Finding(
        id=uuid.uuid4(),
        scan_id=base.id,
        agent_name="api_mapper",
        vulnerability_type=VulnType.OTHER,
        severity=Severity.HIGH,
        title="API endpoint candidate discovered",
        description="Endpoint candidate discovered.",
        affected_url="https://example.com/api/admin/users",
        evidence={"confidence": "high"},
        recommendation="Verify authorization requirements manually.",
    )
    base.findings = [finding]
    compare.findings = []
    return base, compare, [finding]


@pytest.mark.asyncio
async def test_report_generate_without_compare_scan_id_is_backward_compatible(monkeypatch):
    from app.api.v1 import reports as reports_api

    calls = []

    class DummyTask:
        id = "report-task"

    monkeypatch.setattr(reports_api.generate_report, "delay", lambda report_id, compare_scan_id=None: calls.append((report_id, compare_scan_id)) or DummyTask())

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        email = "report-no-compare@example.com"
        headers = await _auth_headers(client, email)
        project_id = await _project_id_for(email)
        scan_id = await _create_completed_scan(project_id, "https://example.com", AuthMethod.NONE)

        response = await client.post(
            f"/api/v1/reports/scans/{scan_id}/generate",
            json={"format": "json", "report_type": "full"},
            headers=headers,
        )

    assert response.status_code == 202
    assert calls and calls[0][1] is None


def test_json_report_includes_cross_scan_diff(tmp_path):
    base, compare, findings = _scan_pair()
    findings[0].triage_status = TriageStatus.VERIFIED
    diff = build_cross_scan_diff(base, compare)
    path = ReportEngine(base, findings, tmp_path, cross_scan_diff=diff).generate(ReportFormat.JSON, ReportType.FULL)
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["cross_scan_diff"]["included"] is True
    assert payload["cross_scan_diff"]["summary"]["verified_new_findings_count"] == 1
    assert payload["cross_scan_diff"]["new_findings"][0]["triage_status"] == "verified"
    assert payload["cross_scan_diff"]["new_api_endpoints"][0]["endpoint"].endswith("/api/admin/users")
    assert "ADMIN_SURFACE" in payload["cross_scan_diff"]["sensitive_endpoint_hints"]


def test_json_report_without_compare_marks_cross_scan_diff_not_included(tmp_path):
    base, _, findings = _scan_pair()
    path = ReportEngine(base, findings, tmp_path).generate(ReportFormat.JSON, ReportType.FULL)
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["cross_scan_diff"] == {"included": False}


def test_markdown_and_html_reports_include_cross_scan_auth_delta(tmp_path):
    base, compare, findings = _scan_pair()
    diff = build_cross_scan_diff(base, compare)
    engine = ReportEngine(base, findings, tmp_path, cross_scan_diff=diff)
    markdown = engine.generate(ReportFormat.MARKDOWN, ReportType.FULL).read_text(encoding="utf-8")
    html = engine.generate(ReportFormat.HTML, ReportType.FULL).read_text(encoding="utf-8")

    assert "## Cross-scan Auth Delta" in markdown
    assert "additional validation is required" in markdown
    assert "Cross-scan Auth Delta" in html
    assert "New authenticated API endpoints" in html


@pytest.mark.asyncio
async def test_report_compare_scan_rejects_other_user(monkeypatch):
    from app.api.v1 import reports as reports_api

    monkeypatch.setattr(reports_api.generate_report, "delay", lambda report_id, compare_scan_id=None: None)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        owner_email = "report-owner@example.com"
        other_email = "report-other@example.com"
        headers = await _auth_headers(client, owner_email)
        await _auth_headers(client, other_email)
        owner_project_id = await _project_id_for(owner_email)
        other_project_id = await _project_id_for(other_email)
        scan_id = await _create_completed_scan(owner_project_id, "https://example.com", AuthMethod.BROWSER)
        other_scan_id = await _create_completed_scan(other_project_id, "https://example.com", AuthMethod.NONE)

        response = await client.post(
            f"/api/v1/reports/scans/{scan_id}/generate",
            json={"format": "json", "report_type": "full", "compare_scan_id": str(other_scan_id)},
            headers=headers,
        )

    assert response.status_code == 422
    assert "compare_scan_id" in response.json()["detail"]


@pytest.mark.asyncio
async def test_report_compare_scan_rejects_different_origin(monkeypatch):
    from app.api.v1 import reports as reports_api

    monkeypatch.setattr(reports_api.generate_report, "delay", lambda report_id, compare_scan_id=None: None)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        email = "report-origin@example.com"
        headers = await _auth_headers(client, email)
        project_id = await _project_id_for(email)
        scan_id = await _create_completed_scan(project_id, "https://example.com/app", AuthMethod.BROWSER)
        compare_scan_id = await _create_completed_scan(project_id, "https://other.example.com/app", AuthMethod.NONE)

        response = await client.post(
            f"/api/v1/reports/scans/{scan_id}/generate",
            json={"format": "json", "report_type": "full", "compare_scan_id": str(compare_scan_id)},
            headers=headers,
        )

    assert response.status_code == 422
    assert "same normalized target origin" in response.json()["detail"]
