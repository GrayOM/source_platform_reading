import uuid
import asyncio
import json

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.services.crawler.crawler import PlaywrightCrawler
from app.services.scan_policy import ScanPolicyResolver


class _FakeResponse:
    status = 200
    headers = {"content-type": "text/html"}

    def __init__(self, url: str):
        self.url = url


class _FakePage:
    def __init__(self, links_by_url: dict[str, list[str]]):
        self.links_by_url = links_by_url
        self.url = ""

    def on(self, *_args, **_kwargs):
        return None

    async def route(self, *_args, **_kwargs):
        return None

    async def goto(self, url: str, **_kwargs):
        self.url = url
        return _FakeResponse(url)

    async def evaluate(self, script: str):
        if "querySelectorAll('a[href]')" in script:
            return self.links_by_url.get(self.url, [])
        return []

    async def close(self):
        return None


class _FakeContext:
    def __init__(self, links_by_url: dict[str, list[str]]):
        self.links_by_url = links_by_url

    async def new_page(self):
        return _FakePage(self.links_by_url)


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
async def test_crawler_max_concurrency_one_crawls_child_pages_without_deadlock(tmp_path):
    policy = ScanPolicyResolver.resolve(
        "https://example.com",
        {
            "max_pages": 2,
            "max_depth": 2,
            "max_concurrency": 1,
            "capture_screenshots": False,
            "capture_storage": False,
            "capture_api_flows": False,
        },
    )
    crawler = PlaywrightCrawler("scan-id", "https://example.com", None, {"scan_policy": policy}, tmp_path)
    crawler.semaphore = asyncio.Semaphore(1)
    links = {
        "https://example.com": ["https://example.com/child-1", "https://example.com/child-2"],
        "https://example.com/child-1": [],
        "https://example.com/child-2": [],
    }

    await asyncio.wait_for(crawler._crawl_page(_FakeContext(links), "https://example.com", depth=0, parent=None), timeout=2)

    assert "https://example.com" in crawler.visited_pages
    assert "https://example.com/child-1" in crawler.visited_pages
    assert any(event["event_type"] == "max_pages_reached" for event in crawler.policy_events)


@pytest.mark.asyncio
async def test_resource_download_timeout_records_policy_event(tmp_path):
    policy = ScanPolicyResolver.resolve("https://example.com", {"request_timeout_ms": 1000})
    crawler = PlaywrightCrawler("scan-id", "https://example.com", None, {"scan_policy": policy}, tmp_path)
    crawler.request_timeout_ms = 10

    async def slow_download(_url: str, _discovered_on: str) -> None:
        await asyncio.sleep(0.05)

    crawler._download_resource_inner = slow_download

    await crawler._download_resource("https://example.com/slow.js", "https://example.com")

    assert any(event["event_type"] == "request_timeout" for event in crawler.policy_events)
    assert any(item.get("policy_event") == "request_timeout" for item in crawler.failed_urls)


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
    outside_event = ScanPolicyResolver.policy_event(
        "outside_scope_blocked",
        "https://outside.example.invalid/blocked",
        "Discovered link is outside scan policy scope.",
        "allowed_hosts",
    )
    scan = Scan(
        id=uuid.uuid4(),
        project_id=project.id,
        target_url="https://example.com",
        status=ScanStatus.COMPLETED,
        progress=100,
        config={
            "scan_policy": policy,
            "policy_events": [
                ScanPolicyResolver.policy_event("excluded_path_skipped", "https://example.com/logout", "Excluded path.", "excluded_paths"),
                outside_event,
            ],
        },
    )
    scan.project = project
    finding = _finding(scan, "Policy report finding", TriageStatus.CANDIDATE)
    scan.findings = [finding]
    engine = ReportEngine(scan, [finding], tmp_path)

    payload = engine.generate(ReportFormat.JSON, ReportType.FULL).read_text(encoding="utf-8")
    markdown = engine.generate(ReportFormat.MARKDOWN, ReportType.FULL).read_text(encoding="utf-8")
    kisa_html = engine.generate(ReportFormat.HTML, ReportType.KISA).read_text(encoding="utf-8")

    data = json.loads(payload)
    assert data["scan_policy"]["intensity"] == "low"
    assert data["scan_policy"]["max_pages"] == 30
    assert data["scan_policy"]["same_origin_only"] is True
    assert data["scan_policy"]["excluded_paths"] == ["/logout"]
    assert len(data["policy_events"]) == 2
    assert any(event["event_type"] == "outside_scope_blocked" for event in data["policy_events"])
    assert "Scan Policy Summary" in markdown
    assert "outside_scope_blocked" in markdown
    assert "Scan Policy 및 안전 제한" in kisa_html
    assert "excluded_path_skipped" in kisa_html
    assert "outside_scope_blocked" in kisa_html
