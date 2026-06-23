"""Regression tests for MVP stabilization behavior."""
import sys
import uuid
from types import SimpleNamespace

import pytest


@pytest.mark.asyncio
async def test_ai_round2_skips_without_api_key_and_keeps_round1_findings(monkeypatch, tmp_path):
    from sqlalchemy import select

    from app.core.database import AsyncSessionLocal
    from app.models.finding import Finding
    from app.models.project import Project
    from app.models.resource import Resource, ResourceType
    from app.models.scan import Scan, ScanStatus
    from app.models.user import User
    from app.services.analysis.agents import base_agent
    from app.services.analysis.agents.base_agent import AI_SKIP_MESSAGE
    from app.services.analysis.orchestrator import AnalysisOrchestrator

    monkeypatch.setattr(base_agent.settings, "anthropic_api_key", "")

    js_path = tmp_path / "app.js"
    js_path.write_text(
        "const source = location.hash;\n"
        "const output = document.getElementById('out');\n"
        "output.innerHTML = source;\n"
        "localStorage.setItem('access_token', source);\n",
        encoding="utf-8",
    )

    async with AsyncSessionLocal() as db:
        user = User(email=f"ai-skip-{uuid.uuid4()}@example.com", password_hash="x", full_name="AI Skip")
        db.add(user)
        await db.flush()
        project = Project(user_id=user.id, name="AI Skip Project")
        db.add(project)
        await db.flush()
        scan = Scan(project_id=project.id, target_url="https://example.com", status=ScanStatus.ANALYZING)
        db.add(scan)
        await db.flush()
        resource = Resource(
            scan_id=scan.id,
            url="https://example.com/app.js",
            resource_type=ResourceType.JS,
            file_path=str(js_path),
            size_bytes=js_path.stat().st_size,
            mime_type="application/javascript",
        )
        db.add(resource)
        await db.flush()

        orchestrator = AnalysisOrchestrator(
            scan_id=str(scan.id),
            target_url=scan.target_url,
            db=db,
        )
        findings = await orchestrator.run([resource], {"sitemap": {}, "endpoint_candidates": []})
        scan.status = ScanStatus.COMPLETED
        scan.findings_count = len(findings)
        await db.commit()

        result = await db.execute(select(Finding).where(Finding.scan_id == scan.id))
        saved = list(result.scalars().all())

    titles = {finding.title for finding in saved}
    assert "Potential DOM XSS data flow in JavaScript" in titles
    assert AI_SKIP_MESSAGE in titles
    assert scan.status == ScanStatus.COMPLETED


def test_pdf_generation_falls_back_to_html(monkeypatch, tmp_path):
    from app.models.report import ReportFormat, ReportType
    from app.services.report.report_engine import ReportEngine

    class BrokenWeasyPrint:
        class HTML:
            def __init__(self, filename: str):
                self.filename = filename

            def write_pdf(self, path: str) -> None:
                raise RuntimeError("weasyprint unavailable")

    monkeypatch.setitem(sys.modules, "weasyprint", BrokenWeasyPrint)

    scan = SimpleNamespace(
        id=uuid.uuid4(),
        target_url="https://example.com",
        resources=[],
        session=None,
    )
    engine = ReportEngine(scan=scan, findings=[], output_dir=tmp_path)

    path = engine.generate(ReportFormat.PDF, ReportType.FULL)

    assert path.suffix == ".html"
    assert path.exists()
    assert "Security Assessment Report" in path.read_text(encoding="utf-8")
