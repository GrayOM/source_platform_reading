import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.services.crawler.crawler import PlaywrightCrawler
from app.services.scan_policy import ScanPolicyResolver


def test_scan_policy_resolver_defaults_and_caps():
    careful = ScanPolicyResolver.resolve("https://example.com/app")
    assert careful["intensity"] == "careful"
    assert careful["max_pages"] == 15
    assert careful["max_resources"] == 50
    assert careful["max_concurrency"] == 1
    assert careful["request_delay_ms"] == 500
    assert careful["allowed_hosts"] == ["example.com"]

    normal = ScanPolicyResolver.resolve(
        "https://example.com/app",
        {"intensity": "normal", "max_pages": 9999, "max_resources": 9999, "max_concurrency": 99, "request_delay_ms": 0},
    )
    assert normal["intensity"] == "normal"
    assert normal["max_pages"] == 500
    assert normal["max_resources"] == 1000
    assert normal["max_concurrency"] == 6
    assert normal["request_delay_ms"] == 100

    low = ScanPolicyResolver.resolve("https://example.com/app", {"intensity": "low"})
    assert low["max_pages"] == 30
    assert low["max_resources"] == 100


def test_crawler_policy_blocks_scope_excluded_private_and_limits(tmp_path):
    policy = ScanPolicyResolver.resolve(
        "https://example.com/app",
        {
            "intensity": "careful",
            "max_pages": 1,
            "max_resources": 1,
            "excluded_paths": ["/logout"],
            "allowed_hosts": ["example.com"],
        },
    )
    crawler = PlaywrightCrawler("scan-id", "https://example.com/app", None, {"scan_policy": policy}, tmp_path)
    assert crawler._is_excluded("https://example.com/logout") is True
    assert crawler.policy_events[-1]["event_type"] == "excluded_path_skipped"

    assert crawler._can_download_resource("https://cdn.example.net/app.js") is False
    assert any(event["event_type"] == "outside_scope_blocked" for event in crawler.policy_events)

    crawler.discovered_resources["https://example.com/app.js"] = object()
    assert crawler._can_download_resource("https://example.com/next.js") is False
    assert any(event["event_type"] == "max_resources_reached" for event in crawler.policy_events)

    assert crawler._is_url_allowed_by_private_policy("http://127.0.0.1/") is False
    assert any(event["event_type"] == "private_target_blocked" for event in crawler.policy_events)


@pytest.mark.asyncio
async def test_crawler_records_max_pages_event_without_failing(tmp_path):
    policy = ScanPolicyResolver.resolve("https://example.com", {"max_pages": 1})
    crawler = PlaywrightCrawler("scan-id", "https://example.com", None, {"scan_policy": policy}, tmp_path)
    crawler.visited_pages.add("https://example.com")

    await crawler._crawl_page(None, "https://example.com/next", depth=0, parent=None)

    assert any(event["event_type"] == "max_pages_reached" for event in crawler.policy_events)
    assert any(item.get("policy_event") == "max_pages_reached" for item in crawler.failed_urls)


@pytest.mark.asyncio
async def test_scan_create_without_policy_stores_resolved_default(monkeypatch):
    from app.api.v1 import scans as scans_api
    from tests.test_api_smoke import _auth_headers

    class DummyTask:
        id = "policy-default-task"

    monkeypatch.setattr(scans_api.orchestrate_scan, "delay", lambda scan_id: DummyTask())

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        headers = await _auth_headers(client, "policy-default@example.com")
        project_response = await client.post("/api/v1/projects", json={"name": "Policy Default"}, headers=headers)
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
    policy = response.json()["config"]["scan_policy"]
    assert policy["intensity"] == "careful"
    assert policy["allowed_hosts"] == ["example.com"]
    assert response.json()["config"]["policy_events"][0]["event_type"] == "authorization_not_confirmed"


def test_report_outputs_include_scan_policy(tmp_path):
    from tests.test_kisa_report_template import _finding, _project
    from app.models.finding import TriageStatus
    from app.models.report import ReportFormat, ReportType
    from app.services.report.report_engine import ReportEngine

    project = _project()
    policy = ScanPolicyResolver.resolve("https://example.com", {"intensity": "low", "excluded_paths": ["/logout"]})
    scan = Scan(
        id=uuid.uuid4(),
        project_id=project.id,
        target_url="https://example.com",
        status=ScanStatus.COMPLETED,
        progress=100,
        config={
            "scan_policy": policy,
            "policy_events": [ScanPolicyResolver.policy_event("excluded_path_skipped", "https://example.com/logout", "Excluded path.", "excluded_paths")],
        },
    )
    scan.project = project
    finding = _finding(scan, "Policy report finding", TriageStatus.CANDIDATE)
    scan.findings = [finding]
    engine = ReportEngine(scan, [finding], tmp_path)

    payload = engine.generate(ReportFormat.JSON, ReportType.FULL).read_text(encoding="utf-8")
    markdown = engine.generate(ReportFormat.MARKDOWN, ReportType.FULL).read_text(encoding="utf-8")
    kisa_html = engine.generate(ReportFormat.HTML, ReportType.KISA).read_text(encoding="utf-8")

    assert '"scan_policy"' in payload
    assert '"policy_events"' in payload
    assert "Scan Policy Summary" in markdown
    assert "Scan Policy 및 안전 제한" in kisa_html
    assert "excluded_path_skipped" in kisa_html
