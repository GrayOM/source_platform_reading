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
from app.models.report import ReportFormat, ReportType
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.services.report.report_engine import ReportEngine


async def _auth_headers(client: AsyncClient, email: str) -> dict[str, str]:
    await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "strongpassword123", "full_name": "Triage User"},
    )
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "strongpassword123"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def _create_project_for(email: str) -> uuid.UUID:
    async with AsyncSessionLocal() as db:
        user = (await db.execute(select(User).where(User.email == email))).scalar_one()
        project = Project(user_id=user.id, name=f"Triage project {email}")
        db.add(project)
        await db.flush()
        project_id = project.id
        await db.commit()
        return project_id


async def _create_scan_with_finding(project_id: uuid.UUID) -> uuid.UUID:
    async with AsyncSessionLocal() as db:
        scan = Scan(
            project_id=project_id,
            target_url="https://example.com",
            status=ScanStatus.COMPLETED,
            progress=100,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        await db.flush()
        finding = Finding(
            scan_id=scan.id,
            agent_name="triage_test",
            vulnerability_type=VulnType.XSS,
            severity=Severity.HIGH,
            title="Reflected XSS candidate",
            description="A reflected XSS candidate was detected.",
            affected_url="https://example.com/search?q=test",
            evidence={"confidence": "high"},
            recommendation="Verify input handling and output encoding.",
        )
        db.add(finding)
        await db.flush()
        finding_id = finding.id
        await db.commit()
        return finding_id


@pytest.mark.asyncio
async def test_new_finding_defaults_to_candidate_triage_status():
    async with AsyncSessionLocal() as db:
        user = User(email="triage-default@example.com", password_hash="hash", full_name="Default Triage")
        project = Project(owner=user, name="Default triage project")
        scan = Scan(project=project, target_url="https://example.com", status=ScanStatus.COMPLETED)
        finding = Finding(
            scan=scan,
            agent_name="triage_test",
            vulnerability_type=VulnType.OTHER,
            severity=Severity.LOW,
            title="Candidate finding",
            description="Candidate.",
            recommendation="Review manually.",
        )
        db.add(finding)
        await db.flush()
        assert finding.triage_status == TriageStatus.CANDIDATE


@pytest.mark.asyncio
async def test_patch_triage_api_updates_review_metadata():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        email = "triage-owner@example.com"
        headers = await _auth_headers(client, email)
        project_id = await _create_project_for(email)
        finding_id = await _create_scan_with_finding(project_id)

        response = await client.patch(
            f"/api/v1/findings/{finding_id}/triage",
            json={
                "triage_status": "verified",
                "analyst_note": "Reproduced in browser.",
                "verification_note": "Confirmed with a safe test payload.",
            },
            headers=headers,
        )

    assert response.status_code == 200
    body = response.json()
    assert body["triage_status"] == "verified"
    assert body["analyst_note"] == "Reproduced in browser."
    assert body["verification_note"] == "Confirmed with a safe test payload."
    assert body["reviewed_at"]
    assert body["reviewed_by"]


@pytest.mark.asyncio
async def test_patch_triage_rejects_other_user_finding():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        owner_email = "triage-owner-deny@example.com"
        other_email = "triage-other-deny@example.com"
        await _auth_headers(client, owner_email)
        other_headers = await _auth_headers(client, other_email)
        project_id = await _create_project_for(owner_email)
        finding_id = await _create_scan_with_finding(project_id)

        response = await client.patch(
            f"/api/v1/findings/{finding_id}/triage",
            json={"triage_status": "false_positive", "analyst_note": "Not exploitable."},
            headers=other_headers,
        )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_patch_triage_rejects_invalid_status():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        email = "triage-invalid@example.com"
        headers = await _auth_headers(client, email)
        project_id = await _create_project_for(email)
        finding_id = await _create_scan_with_finding(project_id)

        response = await client.patch(
            f"/api/v1/findings/{finding_id}/triage",
            json={"triage_status": "confirmed"},
            headers=headers,
        )

    assert response.status_code == 422


def test_report_summary_counts_triage_and_separates_false_positive(tmp_path):
    scan = Scan(id=uuid.uuid4(), project_id=uuid.uuid4(), target_url="https://example.com", status=ScanStatus.COMPLETED)
    verified = Finding(
        id=uuid.uuid4(),
        scan_id=scan.id,
        agent_name="triage_test",
        vulnerability_type=VulnType.XSS,
        severity=Severity.HIGH,
        title="Verified XSS",
        description="Verified issue.",
        recommendation="Fix output encoding.",
        triage_status=TriageStatus.VERIFIED,
        analyst_note="Confirmed.",
        verification_note="Validated manually.",
    )
    false_positive = Finding(
        id=uuid.uuid4(),
        scan_id=scan.id,
        agent_name="triage_test",
        vulnerability_type=VulnType.OTHER,
        severity=Severity.LOW,
        title="False positive header issue",
        description="Not applicable.",
        recommendation="No action.",
        triage_status=TriageStatus.FALSE_POSITIVE,
        analyst_note="Header is set by upstream.",
    )
    findings = [verified, false_positive]

    json_path = ReportEngine(scan, findings, tmp_path).generate(ReportFormat.JSON, ReportType.FULL)
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    html = ReportEngine(scan, findings, tmp_path).generate(ReportFormat.HTML, ReportType.FULL).read_text(encoding="utf-8")

    assert payload["triage_summary"]["verified_findings_count"] == 1
    assert payload["triage_summary"]["false_positive_count"] == 1
    assert payload["findings"][0]["triage_status"] == "verified"
    assert "False Positives" in html
    assert "should not be read as confirmed vulnerabilities" in html
