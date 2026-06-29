import json
import hashlib
import sys
import uuid
import zipfile
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.models.finding import EvidenceArtifactType, Finding, FindingEvidenceArtifact, Severity, TriageStatus, VulnType
from app.models.project import Project
from app.models.report import Report, ReportFormat, ReportType
from app.models.resource import Resource, ResourceType
from app.models.scan import AuthMethod, Scan, ScanSession, ScanStatus
from app.services.report.report_engine import ReportEngine
from app.services.scan_diff import build_cross_scan_diff
from app.services.scan_policy import ScanPolicyResolver


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
    scan.config = {
        "scan_policy": ScanPolicyResolver.resolve("https://example.com/app", {"intensity": "low", "excluded_paths": ["/logout"]}),
        "policy_events": [
            ScanPolicyResolver.policy_event("excluded_path_skipped", "https://example.com/logout", "URL path matches excluded path /logout.", "excluded_paths")
        ],
    }
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


def test_kisa_html_includes_print_css_and_pdf_safe_layout(tmp_path):
    scan, findings = _report_fixture()
    html = ReportEngine(scan, findings, tmp_path).generate(ReportFormat.HTML, ReportType.KISA).read_text(encoding="utf-8")

    for css in (
        "@page { size: A4;",
        "print-color-adjust: exact",
        "overflow-wrap: anywhere",
        "break-inside: avoid",
        "section-break",
        "artifact-index",
        "민감정보 원문은 보고서에 포함하지 않습니다",
        "border: 2px dashed #94a3b8",
    ):
        assert css in html


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
    report_metadata = {
        "report_title": "웹 애플리케이션 보안 진단 보고서",
        "client_name": "Example Corp",
        "service_name": "Example Partner Portal",
        "author": "M O",
        "document_version": "1.0",
        "assessment_scope": "브라우저에서 접근 가능한 웹 리소스 및 API 흐름",
    }
    path = ReportEngine(scan, findings, tmp_path, report_metadata=report_metadata).generate(ReportFormat.JSON, ReportType.KISA)
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["report_metadata"]["client_name"] == "Example Corp"
    assert payload["report_metadata"]["service_name"] == "Example Partner Portal"
    metadata = payload["kisa_report_metadata"]
    assert metadata["target_url"] == scan.target_url
    assert metadata["project_name"] == "KISA Project"
    assert metadata["client_name"] == "Example Corp"
    assert metadata["verified_findings_count"] == 1
    assert metadata["candidate_findings_count"] == 1
    assert metadata["false_positive_count"] == 1
    assert metadata["evidence_artifacts_count"] == 3
    assert metadata["redaction_applied"] is True


def test_kisa_markdown_and_existing_full_outputs_still_generate(tmp_path):
    scan, findings = _report_fixture()
    engine = ReportEngine(scan, findings, tmp_path, report_metadata={"client_name": "Markdown Client"})
    kisa_md = engine.generate(ReportFormat.MARKDOWN, ReportType.KISA).read_text(encoding="utf-8")
    full_md = engine.generate(ReportFormat.MARKDOWN, ReportType.FULL).read_text(encoding="utf-8")
    full_json = json.loads(engine.generate(ReportFormat.JSON, ReportType.FULL).read_text(encoding="utf-8"))
    full_html = engine.generate(ReportFormat.HTML, ReportType.FULL).read_text(encoding="utf-8")

    assert "웹 취약점 점검 결과 보고서" in kisa_md
    assert "Markdown Client" in kisa_md
    assert "## Report Metadata" in full_md
    assert "## Security Findings" in full_md
    assert "findings" in full_json
    assert "Security Assessment Report" in full_html


def test_pdf_success_path_writes_pdf_with_filename_convention(monkeypatch, tmp_path):
    scan, findings = _report_fixture()

    class FakeHTML:
        def __init__(self, filename: str):
            self.filename = filename

        def write_pdf(self, output_path: str):
            assert self.filename.endswith(".html")
            with open(output_path, "wb") as fh:
                fh.write(b"%PDF-1.4\n")

    monkeypatch.setitem(sys.modules, "weasyprint", SimpleNamespace(HTML=FakeHTML))
    path = ReportEngine(scan, findings, tmp_path).generate(ReportFormat.PDF, ReportType.KISA)

    assert path.name == f"sss_report_{str(scan.id)[:8]}_kisa.pdf"
    assert path.read_bytes().startswith(b"%PDF")


def test_pdf_failure_falls_back_to_html_with_error(monkeypatch, tmp_path):
    scan, findings = _report_fixture()

    class FakeHTML:
        def __init__(self, filename: str):
            self.filename = filename

        def write_pdf(self, output_path: str):
            raise RuntimeError("renderer unavailable")

    monkeypatch.setitem(sys.modules, "weasyprint", SimpleNamespace(HTML=FakeHTML))
    engine = ReportEngine(scan, findings, tmp_path)
    path = engine.generate(ReportFormat.PDF, ReportType.FULL)

    assert path.name == f"sss_report_{str(scan.id)[:8]}_full.html"
    assert "Security Assessment Report" in path.read_text(encoding="utf-8")
    assert engine.last_pdf_error == "renderer unavailable"


def test_pdf_renderer_diagnostic_reports_smoke_success(monkeypatch):
    class FakeHTML:
        def __init__(self, string: str):
            self.string = string

        def write_pdf(self, output_path: str):
            assert "한글 테스트" in self.string
            with open(output_path, "wb") as fh:
                fh.write(b"%PDF-1.4\n")

    monkeypatch.setitem(sys.modules, "weasyprint", SimpleNamespace(HTML=FakeHTML, __version__="test"))
    diagnostic = ReportEngine.pdf_renderer_diagnostic()

    assert diagnostic["available"] is True
    assert diagnostic["version"] == "test"
    assert diagnostic["smoke_bytes"] > 0
    assert diagnostic["error"] is None


def test_pdf_renderer_diagnostic_reports_import_or_runtime_failure(monkeypatch):
    class FakeHTML:
        def __init__(self, string: str):
            self.string = string

        def write_pdf(self, output_path: str):
            raise RuntimeError("missing native library")

    monkeypatch.setitem(sys.modules, "weasyprint", SimpleNamespace(HTML=FakeHTML, __version__="test"))
    diagnostic = ReportEngine.pdf_renderer_diagnostic()

    assert diagnostic["available"] is False
    assert diagnostic["smoke_bytes"] == 0
    assert "missing native library" in diagnostic["error"]


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
        scan = Scan(
            id=uuid.uuid4(),
            project=project,
            target_url="https://example.com",
            status=ScanStatus.COMPLETED,
            progress=100,
            config={
                "scan_policy": ScanPolicyResolver.resolve("https://example.com", {"intensity": "low", "excluded_paths": ["/logout"]}),
                "policy_events": [
                    ScanPolicyResolver.policy_event("excluded_path_skipped", "https://example.com/logout", "URL path matches excluded path /logout.", "excluded_paths")
                ],
            },
        )
        finding = _finding(scan, "Bundle verified finding", TriageStatus.VERIFIED)
        report = Report(
            scan=scan,
            format=ReportFormat.HTML,
            report_type=ReportType.KISA,
            report_metadata={"client_name": "Bundle Client", "service_name": "Bundle Service"},
        )
        screenshot = FindingEvidenceArtifact(
            scan=scan,
            finding=finding,
            artifact_type=EvidenceArtifactType.SCREENSHOT,
            title="Screenshot",
            screenshot_path=str(tmp_path / "shot.png"),
            auth_context="authenticated",
        )
        (tmp_path / "shot.png").write_bytes(b"png")
        db.add_all([user, project, scan, finding, screenshot, report])
        await db.commit()
        scan_id = scan.id

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            f"/api/v1/reports/scans/{scan_id}/evidence-bundle",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    bundle_path = tmp_path / str(scan_id) / "reports" / f"sss_evidence_bundle_{str(scan_id)[:8]}.zip"
    with zipfile.ZipFile(bundle_path) as zf:
        names = set(zf.namelist())
    assert {"manifest.json", "README.txt"}.issubset(names)
    assert "reports/full_report.html" in names
    assert "reports/kisa_report.html" in names
    assert "reports/summary.md" in names
    assert "reports/report.json" in names
    assert "reports/report_metadata.json" in names
    assert "reports/scan_policy.json" in names
    assert "reports/policy_events.json" in names
    assert "evidence/artifact_index.json" in names
    assert "evidence/screenshots/shot.png" in names
    assert "kisa_report.html" in names
    assert "kisa_summary.md" in names
    assert "artifact_index.json" in names
    assert "report_metadata.json" in names
    assert "scan_policy.json" in names
    assert "policy_events.json" in names
    assert "screenshots/shot.png" in names
    with zipfile.ZipFile(bundle_path) as zf:
        metadata = json.loads(zf.read("reports/report_metadata.json").decode("utf-8"))
        scan_policy = json.loads(zf.read("reports/scan_policy.json").decode("utf-8"))
        policy_events = json.loads(zf.read("reports/policy_events.json").decode("utf-8"))
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        readme = zf.read("README.txt").decode("utf-8")
    assert metadata["client_name"] == "Bundle Client"
    assert scan_policy["intensity"] == "low"
    assert policy_events[0]["event_type"] == "excluded_path_skipped"
    assert manifest["redaction_applied"] is True
    assert manifest["policy_event_count"] == 1
    assert manifest["formats_included"] == ["html", "markdown", "json"]
    assert manifest["artifact_count"] >= 1
    with zipfile.ZipFile(bundle_path) as zf:
        metadata_bytes = zf.read("reports/report_metadata.json")
        policy_bytes = zf.read("reports/scan_policy.json")
    assert manifest["checksums"]["reports/report_metadata.json"] == hashlib.sha256(metadata_bytes).hexdigest()
    assert manifest["checksums"]["reports/scan_policy.json"] == hashlib.sha256(policy_bytes).hexdigest()
    assert "Redaction notice" in readme
    assert "Scan policy:" in readme
    assert "evidence/artifact_index.json" in readme


@pytest.mark.asyncio
async def test_report_metadata_api_persists_and_validates_length(monkeypatch):
    from app.api.v1 import reports as reports_api
    from app.core.database import AsyncSessionLocal
    from app.models.user import User
    from sqlalchemy import select

    class DummyTask:
        id = "metadata-report-task"

    monkeypatch.setattr(reports_api.generate_report, "delay", lambda report_id, compare_scan_id=None: DummyTask())

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "metadata-api@example.com", "password": "strongpassword123", "full_name": "Metadata User"},
        )
        login = await client.post("/api/v1/auth/login", json={"email": "metadata-api@example.com", "password": "strongpassword123"})
        token = login.json()["access_token"]

    async with AsyncSessionLocal() as db:
        user = (await db.execute(select(User).where(User.email == "metadata-api@example.com"))).scalar_one()
        project = Project(owner=user, name="Metadata Project")
        scan = Scan(project=project, target_url="https://example.com", status=ScanStatus.COMPLETED, progress=100)
        db.add_all([project, scan])
        await db.commit()
        scan_id = scan.id

    payload = {
        "format": "html",
        "report_type": "kisa",
        "report_metadata": {
            "report_title": "웹 애플리케이션 보안 진단 보고서",
            "client_name": "Example Corp",
            "service_name": "Partner Portal",
            "author": "M O",
            "document_version": "1.0",
            "classification": "Confidential",
            "assessment_start_date": "2026-06-01",
            "assessment_end_date": "2026-06-02",
            "assessment_scope": "Browser-accessible resources",
            "limitations": ["No server source collection"],
        },
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(f"/api/v1/reports/scans/{scan_id}/generate", json=payload, headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 202
        report_id = response.json()["id"]
        too_long = await client.post(
            f"/api/v1/reports/scans/{scan_id}/generate",
            json={"format": "html", "report_type": "kisa", "report_metadata": {"client_name": "x" * 300}},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert too_long.status_code == 422

    async with AsyncSessionLocal() as db:
        report = await db.get(Report, uuid.UUID(report_id))
        assert report is not None
        assert report.report_metadata["client_name"] == "Example Corp"
        assert report.report_metadata["classification"] == "Confidential"


def test_report_metadata_renders_in_kisa_html_and_escapes_payload(tmp_path):
    scan, findings = _report_fixture()
    html = ReportEngine(
        scan,
        findings,
        tmp_path,
        report_metadata={
            "client_name": "<script>alert(1)</script>",
            "service_name": "Partner Portal",
            "author": "M O",
            "document_version": "2.0",
            "assessment_scope": "Submitted browser scope",
            "custom_notes": "<b>note</b>",
        },
    ).generate(ReportFormat.HTML, ReportType.KISA).read_text(encoding="utf-8")

    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html
    assert "Partner Portal" in html
    assert "M O" in html
    assert "2.0" in html
    assert "Submitted browser scope" in html
    assert "&lt;b&gt;note&lt;/b&gt;" in html


@pytest.mark.asyncio
async def test_report_download_uses_actual_media_type_and_filename(monkeypatch, tmp_path):
    from app.api.v1 import reports as reports_api
    from app.core.database import AsyncSessionLocal
    from app.models.user import User
    from sqlalchemy import select

    monkeypatch.setattr(reports_api.settings, "scan_data_path", tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/api/v1/auth/register",
            json={"email": "pdf-download@example.com", "password": "strongpassword123", "full_name": "PDF Download"},
        )
        login = await client.post("/api/v1/auth/login", json={"email": "pdf-download@example.com", "password": "strongpassword123"})
        token = login.json()["access_token"]

    async with AsyncSessionLocal() as db:
        user = (await db.execute(select(User).where(User.email == "pdf-download@example.com"))).scalar_one()
        project = Project(owner=user, name="PDF Project")
        scan = Scan(project=project, target_url="https://example.com", status=ScanStatus.COMPLETED, progress=100)
        html_path = tmp_path / "fallback.html"
        html_path.write_text("<html>fallback</html>", encoding="utf-8")
        pdf_fallback = Report(
            scan=scan,
            format=ReportFormat.PDF,
            report_type=ReportType.FULL,
            file_path=str(html_path),
            file_size=html_path.stat().st_size,
            report_status="fallback",
            error_message="PDF generation failed; HTML fallback generated.",
        )
        pdf_path = tmp_path / "real.pdf"
        pdf_path.write_bytes(b"%PDF-1.4\n")
        pdf_success = Report(
            scan=scan,
            format=ReportFormat.PDF,
            report_type=ReportType.KISA,
            file_path=str(pdf_path),
            file_size=pdf_path.stat().st_size,
            report_status="generated",
        )
        db.add_all([project, scan, pdf_fallback, pdf_success])
        await db.commit()
        fallback_id = pdf_fallback.id
        success_id = pdf_success.id
        scan_short = str(scan.id)[:8]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        fallback_response = await client.get(f"/api/v1/reports/{fallback_id}/download", headers={"Authorization": f"Bearer {token}"})
        success_response = await client.get(f"/api/v1/reports/{success_id}/download", headers={"Authorization": f"Bearer {token}"})

    assert fallback_response.status_code == 200
    assert fallback_response.headers["content-type"].startswith("text/html")
    assert f"sss_report_{scan_short}_full.html" in fallback_response.headers["content-disposition"]
    assert success_response.status_code == 200
    assert success_response.headers["content-type"].startswith("application/pdf")
    assert f"sss_report_{scan_short}_kisa.pdf" in success_response.headers["content-disposition"]


def test_report_outputs_share_summary_values_and_metadata(tmp_path):
    scan, findings = _report_fixture()
    metadata = {"client_name": "Consistency Client", "document_version": "3.0"}
    engine = ReportEngine(scan, findings, tmp_path, report_metadata=metadata)
    json_payload = json.loads(engine.generate(ReportFormat.JSON, ReportType.FULL).read_text(encoding="utf-8"))
    markdown = engine.generate(ReportFormat.MARKDOWN, ReportType.FULL).read_text(encoding="utf-8")
    full_html = engine.generate(ReportFormat.HTML, ReportType.FULL).read_text(encoding="utf-8")
    kisa_html = engine.generate(ReportFormat.HTML, ReportType.KISA).read_text(encoding="utf-8")

    assert json_payload["report_metadata"]["client_name"] == "Consistency Client"
    assert json_payload["kisa_report_metadata"]["redaction_applied"] is True
    assert json_payload["triage_summary"]["verified_findings_count"] == 1
    assert json_payload["triage_summary"]["candidate_findings_count"] == 1
    assert json_payload["triage_summary"]["false_positive_count"] == 1
    assert json_payload["severity_counts"]["high"] == 1
    assert json_payload["evidence_summary"]["total_artifacts_count"] == 3
    for text in (markdown, full_html, kisa_html):
        assert "Consistency Client" in text
        assert "Verified" in text or "Verified:" in text
        assert "Candidate" in text or "Candidate:" in text
        assert "False Positive" in text
        assert "Evidence Artifact" in text or "Evidence Artifacts" in text
