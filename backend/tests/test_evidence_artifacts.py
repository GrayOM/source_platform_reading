import json
import uuid
from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.main import app
from app.models.finding import EvidenceArtifactType, Finding, FindingEvidenceArtifact, Severity, VulnType
from app.models.project import Project
from app.models.report import ReportFormat, ReportType
from app.models.resource import Resource, ResourceType
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.services.evidence.artifacts import build_resource_artifact, link_artifacts_for_finding
from app.services.evidence.redaction import redacted_preview
from app.services.report.report_engine import ReportEngine


async def _auth_headers(client: AsyncClient, email: str) -> dict[str, str]:
    await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "strongpassword123", "full_name": "Evidence User"},
    )
    response = await client.post("/api/v1/auth/login", json={"email": email, "password": "strongpassword123"})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def _create_scan_with_finding(email: str) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    async with AsyncSessionLocal() as db:
        user = (await db.execute(select(User).where(User.email == email))).scalar_one()
        project = Project(user_id=user.id, name=f"Evidence project {email}")
        scan = Scan(
            project=project,
            target_url="https://example.com",
            status=ScanStatus.COMPLETED,
            progress=100,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        finding = Finding(
            scan=scan,
            agent_name="evidence_test",
            vulnerability_type=VulnType.XSS,
            severity=Severity.MEDIUM,
            title="DOM XSS candidate",
            description="DOM sink candidate.",
            affected_url="https://example.com/app.js",
            code_snippet="el.innerHTML = location.hash",
            evidence={"line_number": 12, "code_snippet": "el.innerHTML = location.hash"},
            recommendation="Sanitize DOM writes.",
        )
        artifact = FindingEvidenceArtifact(
            scan=scan,
            finding=finding,
            artifact_type=EvidenceArtifactType.CODE_SNIPPET,
            title="Snippet",
            url="https://example.com/app.js",
            redacted_body_preview="el.innerHTML = location.hash",
            line_start=12,
            line_end=12,
            auth_context="anonymous",
        )
        db.add_all([project, scan, finding, artifact])
        await db.flush()
        ids = (scan.id, finding.id, artifact.id)
        await db.commit()
        return ids


@pytest.mark.asyncio
async def test_finding_evidence_artifact_creation_and_linking():
    async with AsyncSessionLocal() as db:
        user = User(email="evidence-link@example.com", password_hash="hash", full_name="Evidence Link")
        project = Project(owner=user, name="Evidence link project")
        scan = Scan(project=project, target_url="https://example.com", status=ScanStatus.COMPLETED)
        resource = Resource(
            scan=scan,
            url="https://example.com/app.js",
            resource_type=ResourceType.JS,
            file_path="/tmp/app.js",
            content_hash="a" * 64,
            mime_type="application/javascript",
            extra_metadata={"auth_context": "authenticated"},
        )
        db.add_all([user, project, scan, resource])
        await db.flush()
        db.add(build_resource_artifact(scan.id, resource))
        finding = Finding(
            scan=scan,
            agent_name="evidence_test",
            vulnerability_type=VulnType.XSS,
            severity=Severity.MEDIUM,
            title="DOM XSS candidate",
            description="DOM sink candidate.",
            affected_url=resource.url,
            code_snippet="el.innerHTML = location.hash",
            evidence={"line_number": 4, "code_snippet": "el.innerHTML = location.hash"},
            recommendation="Sanitize DOM writes.",
        )
        db.add(finding)
        await db.flush()

        await link_artifacts_for_finding(db, finding)
        await db.flush()

        artifacts = (await db.execute(select(FindingEvidenceArtifact).where(FindingEvidenceArtifact.finding_id == finding.id))).scalars().all()
        assert {artifact.artifact_type for artifact in artifacts} >= {
            EvidenceArtifactType.SOURCE_FILE,
            EvidenceArtifactType.CODE_SNIPPET,
            EvidenceArtifactType.REPRODUCTION,
        } - {EvidenceArtifactType.REPRODUCTION}
        assert any(artifact.content_hash == "a" * 64 for artifact in artifacts)


def test_artifact_redaction_removes_tokens_and_secrets():
    fake_secret = "sk_" + "live_" + ("1" * 24)
    preview = redacted_preview(
        {
            "access_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature",
            "Authorization": f"Bearer {fake_secret}",
            "public": "short-value",
        }
    )
    assert "eyJhbGci" not in preview
    assert fake_secret not in preview
    assert "<redacted>" in preview
    assert "short-value" in preview


@pytest.mark.asyncio
async def test_artifact_api_enforces_finding_and_scan_ownership():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        owner_headers = await _auth_headers(client, "artifact-owner@example.com")
        other_headers = await _auth_headers(client, "artifact-other@example.com")
        scan_id, finding_id, artifact_id = await _create_scan_with_finding("artifact-owner@example.com")

        ok = await client.get(f"/api/v1/findings/{finding_id}/artifacts", headers=owner_headers)
        assert ok.status_code == 200
        assert ok.json()[0]["id"] == str(artifact_id)
        assert ok.json()[0]["artifact_type"] == "code_snippet"

        forbidden_finding = await client.get(f"/api/v1/findings/{finding_id}/artifacts", headers=other_headers)
        assert forbidden_finding.status_code == 404

        scan_ok = await client.get(f"/api/v1/scans/{scan_id}/artifacts", headers=owner_headers)
        assert scan_ok.status_code == 200
        assert scan_ok.json()[0]["finding_id"] == str(finding_id)

        forbidden_scan = await client.get(f"/api/v1/scans/{scan_id}/artifacts", headers=other_headers)
        assert forbidden_scan.status_code == 404


def test_json_report_includes_evidence_artifacts(tmp_path):
    scan = Scan(id=uuid.uuid4(), project_id=uuid.uuid4(), target_url="https://example.com", status=ScanStatus.COMPLETED)
    finding = Finding(
        id=uuid.uuid4(),
        scan_id=scan.id,
        agent_name="report_test",
        vulnerability_type=VulnType.SENSITIVE_DATA,
        severity=Severity.INFO,
        title="API endpoint exposed in client-side flow",
        description="Endpoint candidate.",
        affected_url="https://example.com/api/users",
        evidence={},
        recommendation="Verify authorization.",
    )
    artifact = FindingEvidenceArtifact(
        id=uuid.uuid4(),
        scan_id=scan.id,
        finding_id=finding.id,
        artifact_type=EvidenceArtifactType.API_FLOW,
        title="API flow candidate",
        url="https://example.com/api/users",
        http_method="GET",
        status_code=200,
        redacted_body_preview='{"token":"<redacted>"}',
        content_hash="b" * 64,
        auth_context="authenticated",
        verification_required=True,
    )
    scan.evidence_artifacts = [artifact]
    finding.evidence_artifacts = [artifact]

    path = ReportEngine(scan, [finding], tmp_path).generate(ReportFormat.JSON, ReportType.FULL)
    data = json.loads(path.read_text(encoding="utf-8"))

    assert data["evidence_summary"]["total_artifacts_count"] == 1
    assert data["evidence_summary"]["api_flow_artifacts_count"] == 1
    assert data["evidence_summary"]["authenticated_artifacts_count"] == 1
    assert data["artifacts"][0]["content_hash"] == "b" * 64
    assert data["findings"][0]["artifact_count"] == 1
    assert data["findings"][0]["artifacts"][0]["redacted_body_preview"] == '{"token":"<redacted>"}'
