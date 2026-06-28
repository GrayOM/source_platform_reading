import json
import uuid
import zipfile
from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.models.finding import EvidenceArtifactType, Finding, FindingEvidenceArtifact, Severity, TriageStatus, VulnType
from app.models.project import Project
from app.models.report import ReportFormat, ReportType
from app.models.resource import Resource, ResourceType
from app.models.scan import AuthMethod, Scan, ScanSession, ScanStatus
from app.services.report.report_engine import ReportEngine
from app.services.scan_diff import build_cross_scan_diff


def _project() -> Project:
    return Project(id=uuid.uuid4(), user_id=uuid.uuid4(), name="KISA Project")


def _scan(project: Project | None = None) -> Scan:
    project = project or _project()
    scan = Scan(
        id=uuid.uuid4(),
        project_id=project.id,
        target_url="https://example.com/app",
        status=ScanStatus.COMPLETED,
        progress=100,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    scan.project = project
    scan.session = ScanSession(scan_id=scan.id, auth_method=AuthMethod.BROWSER)
    scan.resources = [
        Resource(scan_id=scan.id, url="https://example.com/app", resource_type=ResourceType.HTML),
        Resource(scan_id=scan.id, url="https://example.com/app.js", resource_type=ResourceType.JS),
        Resource(scan_id=scan.id, url="https://example.com/app.js.map", resource_type=ResourceType.SOURCE_MAP),
    ]
    return scan


def _finding(
    scan: Scan,
    title: str,
    triage_status: TriageStatus,
    severity: Severity = Severity.HIGH,
    vuln_type: VulnType = VulnType.XSS,
) -> Finding:
    finding = Finding(
        id=uuid.uuid4(),
        scan_id=scan.id,
        agent_name="kisa_test",
        vulnerability_type=vuln_type,
        severity=severity,
        title=title,
        description=f"{title} description.",
        affected_url="https://example.com/app.js",
        evidence={"confidence": "high", "source_pattern": "location.hash", "sink_pattern": "innerHTML"},
        code_snippet="el.innerHTML = location.hash",
        poc={"type": "manual_verification"},
        reproduction_steps=["Open the affected page.", "Review the highlighted data flow."],
        cwe_id=79,
        owasp_category="A03:2021",
        recommendation="Sanitize untrusted input before DOM insertion.",
        triage_status=triage_status,
    )
    artifact = FindingEvidenceArtifact(
        id=uuid.uuid4(),
        scan_id=scan.id,
        finding_id=finding.id,
        artifact_type=EvidenceArtifactType.CODE_SNIPPET,
        title="Redacted snippet",
        url=finding.affected_url,
        content_hash="c" * 64,
        redacted_body_preview="el.innerHTML = location.hash",
        auth_context="authenticated",
        verification_required=triage_status != TriageStatus.VERIFIED,
    )
    finding.evidence_artifacts = [artifact]
    return finding


def _report_fixture() -> tuple[Scan, list[Finding]]:
    scan = _scan()
    verified = _finding(scan, "Verified DOM XSS", TriageStatus.VERIFIED)
    candidate = _finding(scan, "Candidate API endpoint exposure", TriageStatus.CANDIDATE, Severity.INFO, VulnType.SENSITIVE_DATA)
    false_positive = _finding(scan, "False positive item", TriageStatus.FALSE_POSITIVE, Severity.MEDIUM)
    false_positive.analyst_note = "Reviewed as benign."
    findings = [verified, candidate, false_positive]
    scan.findings = findings
    scan.evidence_artifacts = [artifact for finding in findings for artifact in finding.evidence_artifacts]
    return scan, findings


def test_kisa_html_contains_required_sections_and_evidence_index(tmp_path):
    scan, findings = _report_fixture()
    html = ReportEngine(scan, findings, tmp_path).generate(ReportFormat.HTML, ReportType.KISA).read_text(encoding="utf-8")

    for section in (
        "1. 문서 정보",
        "2. 진단 개요",
        "3. Executive Summary",
        "4. 인증 전/후 공격 표면 비교",
        "5. 취약점 요약표",
        "6. 취약점 상세",
        "7. 증적 첨부",
        "8. 조치 우선순위",
        "9. 한계 및 주의사항",
    ):
        assert section in html
    assert "Evidence Artifact" in html
    assert "Redacted snippet" in html
    assert "민감정보 원문은 보고서에 포함하지 않습니다" in html


def test_kisa_html_uses_state_specific_wording_and_false_positive_separation(tmp_path):
    scan, findings = _report_fixture()
    html = ReportEngine(scan, findings, tmp_path).generate(ReportFormat.HTML, ReportType.KISA).read_text(encoding="utf-8")

    assert "취약점이 확인되었습니다." in html
    assert "취약 가능성이 확인되었습니다." in html
    assert "검토 결과 오탐으로 분류되었습니다." in html
    assert "False Positive 분리 항목" in html
    active_section = html.split("False Positive 분리 항목")[0]
    assert "False positive item" not in active_section


def test_kisa_html_includes_cross_scan_delta_without_falling_back_to_full_template(tmp_path):
    base, findings = _report_fixture()
    compare = _scan(base.project)
    compare.id = uuid.uuid4()
    compare.session = ScanSession(scan_id=compare.id, auth_method=AuthMethod.NONE)
    compare.resources = [Resource(scan_id=compare.id, url="https://example.com/app", resource_type=ResourceType.HTML)]
    compare.findings = []
    diff = build_cross_scan_diff(base, compare)

    html = ReportEngine(base, findings, tmp_path, cross_scan_diff=diff).generate(ReportFormat.HTML, ReportType.KISA).read_text(encoding="utf-8")

    assert "웹 취약점 점검 결과 보고서" in html
    assert "Cross-scan Auth Delta가 포함되었습니다" in html
    assert "권한 우회가 확인되었다는 의미는 아닙니다" in html
    assert "New API" in html


def test_json_report_includes_kisa_report_metadata(tmp_path):
    scan, findings = _report_fixture()
    path = ReportEngine(scan, findings, tmp_path).generate(ReportFormat.JSON, ReportType.KISA)
    payload = json.loads(path.read_text(encoding="utf-8"))

    metadata = payload["kisa_report_metadata"]
    assert metadata["target_url"] == scan.target_url
    assert metadata["project_name"] == "KISA Project"
    assert metadata["verified_findings_count"] == 1
    assert metadata["candidate_findings_count"] == 1
    assert metadata["false_positive_count"] == 1
    assert metadata["evidence_artifacts_count"] == 3
    assert metadata["redaction_applied"] is True


def test_kisa_markdown_and_existing_full_outputs_still_generate(tmp_path):
    scan, findings = _report_fixture()
    engine = ReportEngine(scan, findings, tmp_path)
    kisa_md = engine.generate(ReportFormat.MARKDOWN, ReportType.KISA).read_text(encoding="utf-8")
    full_md = engine.generate(ReportFormat.MARKDOWN, ReportType.FULL).read_text(encoding="utf-8")
    full_json = json.loads(engine.generate(ReportFormat.JSON, ReportType.FULL).read_text(encoding="utf-8"))
    full_html = engine.generate(ReportFormat.HTML, ReportType.FULL).read_text(encoding="utf-8")

    assert "웹 취약점 점검 결과 보고서" in kisa_md
    assert "## Security Findings" in full_md
    assert "findings" in full_json
    assert "Security Assessment Report" in full_html


@pytest.mark.asyncio
async def test_evidence_bundle_contains_kisa_report_and_artifact_index(monkeypatch, tmp_path):
    from app.api.v1 import reports as reports_api
    from app.core.database import AsyncSessionLocal
    from sqlalchemy import select

    monkeypatch.setattr(reports_api.settings, "scan_data_path", tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "kisa-bundle@example.com", "password": "strongpassword123", "full_name": "Bundle User"},
        )
        login = await client.post("/api/v1/auth/login", json={"email": "kisa-bundle@example.com", "password": "strongpassword123"})
        token = login.json()["access_token"]

    async with AsyncSessionLocal() as db:
        from app.models.project import Project
        from app.models.user import User

        user = (await db.execute(select(User).where(User.email == "kisa-bundle@example.com"))).scalar_one()
        project = Project(owner=user, name="Bundle Project")
        scan = Scan(id=uuid.uuid4(), project=project, target_url="https://example.com", status=ScanStatus.COMPLETED, progress=100)
        finding = _finding(scan, "Bundle verified finding", TriageStatus.VERIFIED)
        screenshot = FindingEvidenceArtifact(
            scan=scan,
            finding=finding,
            artifact_type=EvidenceArtifactType.SCREENSHOT,
            title="Screenshot",
            screenshot_path=str(tmp_path / "shot.png"),
            auth_context="authenticated",
        )
        (tmp_path / "shot.png").write_bytes(b"png")
        db.add_all([user, project, scan, finding, screenshot])
        await db.commit()
        scan_id = scan.id

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            f"/api/v1/reports/scans/{scan_id}/evidence-bundle",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    bundle_path = tmp_path / str(scan_id) / "reports" / f"evidence_bundle_{str(scan_id)[:8]}.zip"
    with zipfile.ZipFile(bundle_path) as zf:
        names = set(zf.namelist())
    assert "kisa_report.html" in names
    assert "kisa_summary.md" in names
    assert "artifact_index.json" in names
    assert "screenshots/shot.png" in names
