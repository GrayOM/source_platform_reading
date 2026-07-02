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


def test_ai_provider_prefers_nvidia_when_configured(monkeypatch):
    from app.services.analysis.agents import base_agent
    from app.services.analysis.agents.base_agent import get_configured_ai_provider

    monkeypatch.setattr(base_agent.settings, "ai_provider", "auto")
    monkeypatch.setattr(base_agent.settings, "nvidia_api_key", "nvapi-" + ("x" * 40))
    monkeypatch.setattr(base_agent.settings, "anthropic_api_key", "sk-ant-test")

    assert get_configured_ai_provider() == "nvidia"


def test_nvidia_adapter_keys_fall_back_to_shared_key(monkeypatch):
    from app.services.analysis.agents import base_agent

    monkeypatch.setattr(base_agent.settings, "nvidia_api_key", "nvapi-" + ("x" * 40))
    monkeypatch.setattr(base_agent.settings, "nvidia_pii_api_key", "")
    monkeypatch.setattr(base_agent.settings, "nvidia_rerank_api_key", "nvapi-" + ("r" * 40))

    assert base_agent.settings.nvidia_key_for("pii") == "nvapi-" + ("x" * 40)
    assert base_agent.settings.nvidia_key_for("rerank") == "nvapi-" + ("r" * 40)


def test_nvidia_nim_chat_completion_uses_openai_compatible_endpoint(monkeypatch):
    from app.services.analysis.agents import base_agent
    from app.services.analysis.agents.base_agent import BaseAgent
    from app.services.ai import nvidia

    class DummyAgent(BaseAgent):
        async def analyze(self, context):
            return []

    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"choices": [{"message": {"content": "[{\"title\":\"ok\"}]"}}]}

    class FakeClient:
        def __init__(self, timeout):
            captured["timeout"] = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def post(self, url, headers, json):
            captured["url"] = url
            captured["headers"] = headers
            captured["json"] = json
            return FakeResponse()

    monkeypatch.setattr(base_agent.settings, "ai_provider", "nvidia")
    monkeypatch.setattr(base_agent.settings, "nvidia_api_key", "nvapi-" + ("y" * 40))
    monkeypatch.setattr(base_agent.settings, "nvidia_base_url", "https://integrate.api.nvidia.com/v1")
    monkeypatch.setattr(base_agent.settings, "nvidia_nim_model", "deepseek-ai/deepseek-v4-pro")
    monkeypatch.setattr(base_agent.settings, "nvidia_thinking", False)
    monkeypatch.setattr(nvidia.httpx, "Client", FakeClient)

    result = DummyAgent()._call_ai("system", "user", max_tokens=123)

    assert result == "[{\"title\":\"ok\"}]"
    assert captured["url"] == "https://integrate.api.nvidia.com/v1/chat/completions"
    assert captured["headers"]["Authorization"].startswith("Bearer nvapi-")
    assert captured["json"]["model"] == "deepseek-ai/deepseek-v4-pro"
    assert captured["json"]["messages"][0] == {"role": "system", "content": "system"}
    assert captured["json"]["messages"][1] == {"role": "user", "content": "user"}
    assert captured["json"]["max_tokens"] == 123
    assert captured["json"]["chat_template_kwargs"] == {"thinking": False}


def test_nvidia_client_parses_pii_and_rerank_shapes(monkeypatch):
    from app.services.ai import nvidia
    from app.services.ai.nvidia import NvidiaNIMClient

    captured = []

    class FakeResponse:
        def __init__(self, payload):
            self.payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self.payload

    class FakeClient:
        def __init__(self, timeout):
            self.timeout = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def post(self, url, headers, json):
            captured.append((url, headers, json))
            if url.endswith("/chat/completions"):
                return FakeResponse({
                    "choices": [
                        {
                            "message": {
                                "content": (
                                    '{"total_entities":1,"entities":[{"text":"Alice",'
                                    '"label":"first_name","start":0,"end":5,"score":0.99}]}'
                                )
                            }
                        }
                    ]
                })
            return FakeResponse({"rankings": [{"index": 1, "logit": 2.5}]})

    monkeypatch.setattr(nvidia.httpx, "Client", FakeClient)
    client = NvidiaNIMClient()
    monkeypatch.setattr(client.settings, "nvidia_api_key", "nvapi-" + ("x" * 40))
    monkeypatch.setattr(client.settings, "nvidia_pii_api_key", "")
    monkeypatch.setattr(client.settings, "nvidia_rerank_api_key", "nvapi-" + ("r" * 40))
    monkeypatch.setattr(client.settings, "nvidia_rerank_url", "https://ai.api.nvidia.com/v1/retrieval/nvidia/reranking")
    monkeypatch.setattr(client.settings, "nvidia_rerank_model", "nv-rerank-qa-mistral-4b:1")

    entities = client.detect_pii("Alice")
    rankings = client.rerank("security", ["fruit", "OWASP security"])

    assert entities[0].label == "first_name"
    assert entities[0].text == "Alice"
    assert rankings == [{"index": 1, "logit": 2.5}]
    assert captured[1][0] == "https://ai.api.nvidia.com/v1/retrieval/nvidia/reranking"
    assert captured[1][2]["model"] == "nv-rerank-qa-mistral-4b:1"


@pytest.mark.asyncio
async def test_pii_detector_redacts_detected_values(monkeypatch, tmp_path):
    from app.core.config import get_settings
    from app.services.ai.nvidia import NvidiaNIMClient, PIIEntity
    from app.services.analysis.agents.base_agent import AgentContext
    from app.services.analysis.agents.pii_detector import PIIDetectorAgent

    settings = get_settings()
    monkeypatch.setattr(settings, "nvidia_api_key", "nvapi-" + ("x" * 40))
    pii_path = tmp_path / "profile.json"
    pii_path.write_text('{"name":"Alice Example","email":"alice@example.test"}', encoding="utf-8")

    def fake_detect_pii(self, text):
        return [
            PIIEntity(text="Alice", label="first_name", start=9, end=14, score=0.99),
            PIIEntity(text="alice@example.test", label="email", start=35, end=53, score=0.98),
        ]

    monkeypatch.setattr(NvidiaNIMClient, "detect_pii", fake_detect_pii)
    context = AgentContext(
        scan_id=str(uuid.uuid4()),
        target_url="https://example.com",
        resources=[
            {
                "url": "https://example.com/profile.json",
                "resource_type": "json",
                "file_path": str(pii_path),
                "mime_type": "application/json",
                "is_minified": False,
            }
        ],
        sitemap={},
        endpoint_candidates=[],
    )

    findings = await PIIDetectorAgent().analyze(context)

    assert len(findings) == 1
    assert findings[0].agent_name == "pii_detector"
    assert findings[0].evidence["entity_count"] == 2
    assert "email" in findings[0].evidence["labels"]
    redacted = {entity["redacted_value"] for entity in findings[0].evidence["entities"]}
    assert "alice@example.test" not in redacted
    assert any(value.startswith("a***@e***") for value in redacted)
