"""Playwright-based authenticated recursive crawler.

Discovers pages, collects resource URLs (JS/CSS/XHR/Fetch/WS), and
downloads all unique resources while respecting scope and limits.
"""
import asyncio
import hashlib
import ipaddress
import json
import re
import socket
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import structlog
from playwright.async_api import Browser, BrowserContext, Page, Route, async_playwright

from app.core.config import get_settings
from app.core.security import validate_public_http_url
from app.models.scan import ScanSession
from app.models.resource import ResourceType
from app.services.auth.session_manager import apply_session_to_context
from app.services.crawler.sitemap_builder import SitemapBuilder
from app.services.collector.resource_classifier import classify_url, classify_mime
from app.services.evidence.redaction import redact_value, redacted_preview
from app.services.scan_policy import ScanPolicyResolver

settings = get_settings()
log = structlog.get_logger()


@dataclass
class CrawlResult:
    pages: list[str] = field(default_factory=list)
    resources: list["DiscoveredResource"] = field(default_factory=list)
    sitemap: dict = field(default_factory=dict)
    endpoint_candidates: list[str] = field(default_factory=list)
    websocket_urls: list[str] = field(default_factory=list)
    failed_urls: list[dict] = field(default_factory=list)
    policy_events: list[dict] = field(default_factory=list)
    artifact_candidates: list[dict] = field(default_factory=list)


@dataclass
class DiscoveredResource:
    url: str
    resource_type: ResourceType
    file_path: str | None = None
    content_hash: str | None = None
    size_bytes: int = 0
    mime_type: str | None = None
    http_status: int | None = None
    is_minified: bool = False
    source_map_url: str | None = None
    discovered_on_page: str | None = None
    metadata: dict = field(default_factory=dict)


class PlaywrightCrawler:
    def __init__(
        self,
        scan_id: str,
        target_url: str,
        session: ScanSession | None,
        config: dict,
        output_dir: Path,
        progress_callback=None,
    ):
        self.scan_id = scan_id
        self.target_url = target_url
        self.session = session
        self.config = config
        self.output_dir = output_dir
        self.progress_callback = progress_callback

        parsed = urllib.parse.urlparse(target_url)
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme

        self.policy = config.get("scan_policy") or ScanPolicyResolver.resolve(target_url, None, config)
        self.max_depth = self.policy.get("max_depth", config.get("max_depth", settings.max_crawl_depth))
        self.max_pages = self.policy.get("max_pages", config.get("max_pages", settings.max_crawl_pages))
        self.max_resources = self.policy.get("max_resources", settings.max_crawl_pages * 3)
        self.concurrency = self.policy.get("max_concurrency", config.get("concurrency", settings.crawl_concurrency))
        self.request_delay_ms = self.policy.get("request_delay_ms", 0)
        self.request_timeout_ms = self.policy.get("request_timeout_ms", settings.crawl_timeout_seconds * 1000)
        self.same_origin_only = self.policy.get("same_origin_only", True)
        self.allowed_hosts = set(self.policy.get("allowed_hosts") or [])
        self.excluded_hosts = set(self.policy.get("excluded_hosts") or [])
        self.allow_private_targets = bool(self.policy.get("allow_private_targets"))
        self.allow_redirect_outside_scope = bool(self.policy.get("allow_redirect_outside_scope"))
        self.follow_subdomains = config.get("follow_subdomains", False)
        self.allow_external_resources = config.get("allow_external_resources", settings.allow_external_resources)
        self.excluded_paths: list[str] = self.policy.get("excluded_paths") or config.get("excluded_paths", [])
        self.screenshot = bool(self.policy.get("capture_screenshots", config.get("screenshot_pages", True)))
        self.capture_storage = bool(self.policy.get("capture_storage", True))
        self.capture_api_flows = bool(self.policy.get("capture_api_flows", True))

        self.visited_pages: set[str] = set()
        self.queued_pages: set[str] = set()
        self.discovered_resources: dict[str, DiscoveredResource] = {}
        self.endpoint_candidates: set[str] = set()
        self.ws_urls: set[str] = set()
        self.failed_urls: list[dict] = []
        self.policy_events: list[dict] = []
        self.artifact_candidates: list[dict] = []
        self.sitemap_builder = SitemapBuilder()
        self.semaphore: asyncio.Semaphore | None = None
        self.authenticated_context = bool(
            session and getattr(getattr(session, "auth_method", None), "value", "none") != "none"
        )

    def _is_in_scope(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host or host in self.excluded_hosts:
            return False
        if self.allowed_hosts and host not in self.allowed_hosts:
            return False
        if self.same_origin_only and parsed.netloc != self.base_domain:
            return False
        if self.follow_subdomains:
            base = ".".join(self.base_domain.split(".")[-2:])
            return parsed.netloc.endswith(base)
        return parsed.netloc == self.base_domain

    def _can_download_resource(self, url: str) -> bool:
        if len(self.discovered_resources) >= self.max_resources:
            self._record_policy_event("max_resources_reached", url, "Resource collection limit reached.", "max_resources", "warning")
            return False
        if not self.allow_external_resources and not self._is_in_scope(url):
            self._record_policy_event("outside_scope_blocked", url, "Resource host is outside scan policy scope.", "allowed_hosts", "warning")
            return False
        if self._is_excluded(url):
            return False
        if not self._is_url_allowed_by_private_policy(url):
            return False
        return True

    def _is_excluded(self, url: str) -> bool:
        path = urllib.parse.urlparse(url).path
        matched = next((ex for ex in self.excluded_paths if path.startswith(ex)), None)
        if matched:
            self._record_policy_event("excluded_path_skipped", url, f"URL path matches excluded path {matched}.", "excluded_paths")
            return True
        return False

    def _normalize_url(self, url: str, base: str) -> str | None:
        try:
            joined = urllib.parse.urljoin(base, url)
            parsed = urllib.parse.urlparse(joined)
            clean = parsed._replace(fragment="").geturl()
            return clean
        except Exception:
            return None

    async def crawl(self) -> CrawlResult:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "resources").mkdir(exist_ok=True)
        (self.output_dir / "screenshots").mkdir(exist_ok=True)
        self.semaphore = asyncio.Semaphore(self.concurrency)

        async with async_playwright() as pw:
            browser: Browser = await pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            context: BrowserContext = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/131.0.0.0 Safari/537.36"
                ),
                ignore_https_errors=True,
            )

            if self.session:
                await apply_session_to_context(self.session, context)

            await self._crawl_page(context, self.target_url, depth=0, parent=None)
            await browser.close()

        return CrawlResult(
            pages=list(self.visited_pages),
            resources=list(self.discovered_resources.values()),
            sitemap=self.sitemap_builder.to_dict(),
            endpoint_candidates=list(self.endpoint_candidates),
            websocket_urls=list(self.ws_urls),
            failed_urls=self.failed_urls,
            policy_events=self.policy_events,
            artifact_candidates=self.artifact_candidates,
        )

    async def _crawl_page(self, context: BrowserContext, url: str, depth: int, parent: str | None) -> None:
        if depth > self.max_depth:
            self._record_policy_event("max_depth_reached", url, "Crawl depth limit reached.", "max_depth")
            return
        if len(self.visited_pages) >= self.max_pages:
            self._record_policy_event("max_pages_reached", url, "Page crawl limit reached.", "max_pages", "warning")
            return
        if url in self.visited_pages:
            return
        if self._is_excluded(url):
            return
        if not self._is_in_scope(url):
            self._record_policy_event("outside_scope_blocked", url, "Page URL is outside scan policy scope.", "allowed_hosts", "warning")
            return
        if not self._is_url_allowed_by_private_policy(url):
            return

        self.visited_pages.add(url)
        self.sitemap_builder.add_page(url, parent)
        child_pages: list[str] = []

        async with self.semaphore:
            try:
                page: Page = await context.new_page()
                discovered_on_this_page: list[str] = []

                page.on("response", lambda resp: self._record_api_response(resp))

                async def handle_request(route: Route):
                    req = route.request
                    req_url = req.url
                    resource_type = req.resource_type

                    if req_url.startswith(("http://", "https://")):
                        if self._is_excluded(req_url):
                            await route.abort()
                            return
                        if not self._is_in_scope(req_url):
                            if resource_type == "document":
                                self._record_policy_event(
                                    "redirect_outside_scope_blocked",
                                    req_url,
                                    "Navigation redirected outside scan policy scope.",
                                    "allow_redirect_outside_scope",
                                    "warning",
                                )
                            else:
                                self._record_policy_event(
                                    "outside_scope_blocked",
                                    req_url,
                                    "Browser request is outside scan policy scope.",
                                    "allowed_hosts",
                                    "warning",
                                )
                            await route.abort()
                            return
                        if not self._is_url_allowed_by_private_policy(req_url):
                            await route.abort()
                            return

                    if resource_type in ("xhr", "fetch"):
                        self.endpoint_candidates.add(req_url)
                        self._record_api_request(req)
                    elif resource_type == "websocket":
                        self.ws_urls.add(req_url)
                    elif resource_type in ("script", "stylesheet", "image", "font", "document"):
                        rtype = classify_url(req_url)
                        if rtype and self._can_download_resource(req_url) and req_url not in self.discovered_resources:
                            if len(self.discovered_resources) >= self.max_resources:
                                self._record_policy_event("max_resources_reached", req_url, "Resource collection limit reached.", "max_resources", "warning")
                                await route.abort()
                                return
                            discovered_on_this_page.append(req_url)
                            self.discovered_resources[req_url] = DiscoveredResource(
                                url=req_url,
                                resource_type=rtype,
                                discovered_on_page=url,
                                metadata=self._resource_metadata(),
                            )

                    await route.continue_()

                await page.route("**/*", handle_request)

                if self.request_delay_ms:
                    await asyncio.sleep(self.request_delay_ms / 1000)
                if not self._is_url_allowed_by_private_policy(url):
                    await page.close()
                    return
                response = await page.goto(url, wait_until="networkidle", timeout=self.request_timeout_ms)
                if response:
                    status = response.status
                    final_url = response.url
                    if not self._is_url_allowed_by_private_policy(final_url):
                        await page.close()
                        return
                    if not self._is_in_scope(final_url) and not self.allow_redirect_outside_scope:
                        self._record_policy_event(
                            "redirect_outside_scope_blocked",
                            final_url,
                            f"Navigation from {url} redirected outside scan policy scope.",
                            "allow_redirect_outside_scope",
                            "warning",
                        )
                        await page.close()
                        return
                    content_type = response.headers.get("content-type", "").split(";")[0].lower()
                    if content_type in ("", "text/html", "application/xhtml+xml"):
                        self.discovered_resources[final_url] = DiscoveredResource(
                            url=final_url,
                            resource_type=ResourceType.HTML,
                            http_status=status,
                            discovered_on_page=parent,
                            metadata=self._resource_metadata(page=True, requested_url=url),
                        )

                if self.screenshot:
                    screenshot_path = self.output_dir / "screenshots" / f"{_url_to_filename(url)}.png"
                    await page.screenshot(path=str(screenshot_path), full_page=True)
                    self.artifact_candidates.append(
                        {
                            "artifact_type": "screenshot",
                            "title": "Page screenshot",
                            "description": f"Screenshot captured during page visit: {url}",
                            "url": url,
                            "status_code": status if response else None,
                            "screenshot_path": str(screenshot_path),
                            "auth_context": self._auth_context(),
                        }
                    )

                self.artifact_candidates.append(
                    {
                        "artifact_type": "response",
                        "title": "Page visit",
                        "description": f"Visited page during crawl: {url}",
                        "url": final_url if response else url,
                        "status_code": status if response else None,
                        "content_type": content_type if response else None,
                        "auth_context": self._auth_context(),
                        "metadata": {"requested_url": url, "parent": parent},
                    }
                )
                if self.capture_storage:
                    await self._record_storage_snapshot(page, url)

                # Extract navigable page links only. Scripts/styles are captured
                # by the request route and must not be re-queued as pages.
                links = await page.evaluate("""
                    () => {
                        const links = new Set();
                        document.querySelectorAll('a[href]').forEach(a => links.add(a.href));
                        document.querySelectorAll('form[action]').forEach(f => links.add(f.action));
                        return Array.from(links).filter(l => l.startsWith('http'));
                    }
                """)

                # Extract JS-defined routes and API calls
                js_urls = await page.evaluate(r"""
                    () => {
                        const text = Array.from(document.querySelectorAll('script:not([src])'))
                            .map(s => s.textContent).join(' ');
                        const matches = text.match(/["'`](\/[a-zA-Z0-9_\-\/]+)["'`]/g) || [];
                        return matches.map(m => m.replace(/["'`]/g, ''));
                    }
                """)
                for path in js_urls:
                    if path.startswith("/api/") or "/api/" in path:
                        self.endpoint_candidates.add(urllib.parse.urljoin(url, path))

                await page.close()

                # Download resources discovered on this page
                await asyncio.gather(*[
                    self._download_resource(resource_url, url)
                    for resource_url in discovered_on_this_page
                ])

                # Queue discovered page links
                for link in (links or []):
                    norm = self._normalize_url(link, url)
                    if norm and self._is_in_scope(norm) and norm not in self.visited_pages:
                        child_pages.append(norm)
                        self.sitemap_builder.add_link(url, norm)
                    elif norm and norm not in self.visited_pages:
                        self._record_policy_event("outside_scope_blocked", norm, "Discovered link is outside scan policy scope.", "allowed_hosts")

                if self.progress_callback:
                    await asyncio.to_thread(
                        self.progress_callback,
                        len(self.visited_pages),
                        len(self.discovered_resources),
                    )

            except Exception as exc:
                log.warning("crawl.page_failed", url=url, error=str(exc))
                self.failed_urls.append({"url": url, "error": str(exc)})
                error_text = str(exc).lower()
                if "err_name_not_resolved" in error_text and self._is_in_scope(url) and not self.allow_redirect_outside_scope:
                    self._record_policy_event(
                        "redirect_outside_scope_blocked",
                        url,
                        "Navigation failed after a likely redirect to an unresolved outside-scope host.",
                        "allow_redirect_outside_scope",
                        "warning",
                    )
                if "timeout" in error_text:
                    self._record_policy_event("request_timeout", url, str(exc), "request_timeout_ms", "warning")
                self.discovered_resources[url] = DiscoveredResource(
                    url=url,
                    resource_type=ResourceType.OTHER,
                    discovered_on_page=parent,
                    metadata=self._resource_metadata(failed=True, error=str(exc)),
                )

        for child_url in child_pages:
            await self._crawl_page(context, child_url, depth + 1, url)

    async def _download_resource(self, url: str, discovered_on: str) -> None:
        try:
            await asyncio.wait_for(
                self._download_resource_inner(url, discovered_on),
                timeout=max(0.001, self.request_timeout_ms / 1000),
            )
        except asyncio.TimeoutError:
            log.warning("crawl.download_timeout", url=url)
            self._record_policy_event(
                "request_timeout",
                url,
                "Resource download exceeded request_timeout_ms.",
                "request_timeout_ms",
                "warning",
            )

    async def _download_resource_inner(self, url: str, discovered_on: str) -> None:
        if url in self.discovered_resources and self.discovered_resources[url].file_path:
            return  # already downloaded
        if not self._can_download_resource(url):
            return

        try:
            if self.request_delay_ms:
                await asyncio.sleep(self.request_delay_ms / 1000)
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=self.request_timeout_ms / 1000) as client:
                resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                if not self._can_download_resource(str(resp.url)):
                    if str(resp.url) != url:
                        self._record_policy_event(
                            "redirect_outside_scope_blocked",
                            str(resp.url),
                            f"Resource request from {url} redirected outside scan policy scope.",
                            "allow_redirect_outside_scope",
                            "warning",
                        )
                    return
                if resp.status_code >= 400:
                    return

                content = resp.content
                if len(content) > settings.max_resource_size_bytes:
                    return

                mime = resp.headers.get("content-type", "").split(";")[0].strip()
                rtype = classify_url(url) if url.endswith(".map") else None
                rtype = rtype or classify_mime(mime) or classify_url(url)
                if not rtype:
                    return

                content_hash = hashlib.sha256(content).hexdigest()
                filename = f"{content_hash[:16]}{_url_extension(url)}"
                file_path = self.output_dir / "resources" / filename

                if not file_path.exists():
                    file_path.write_bytes(content)

                # Detect source map reference
                source_map_url = None
                if rtype == ResourceType.JS:
                    match = re.search(rb"//# sourceMappingURL=(.+)$", content, re.MULTILINE)
                    if match:
                        source_map_url = match.group(1).decode("utf-8", errors="ignore").strip()
                        if source_map_url and not source_map_url.startswith("data:"):
                            source_map_url = urllib.parse.urljoin(url, source_map_url)

                is_minified = rtype == ResourceType.JS and _is_minified(content)

                self.discovered_resources[url] = DiscoveredResource(
                    url=url,
                    resource_type=rtype,
                    file_path=str(file_path),
                    content_hash=content_hash,
                    size_bytes=len(content),
                    mime_type=mime,
                    http_status=resp.status_code,
                    is_minified=is_minified,
                    source_map_url=source_map_url,
                    discovered_on_page=discovered_on,
                    metadata=self._resource_metadata(),
                )

                # Automatically queue source maps for download
                if source_map_url and source_map_url not in self.discovered_resources:
                    await self._download_resource(source_map_url, url)

        except Exception as exc:
            log.warning("crawl.download_failed", url=url, error=str(exc))
            if "timeout" in str(exc).lower():
                self._record_policy_event("request_timeout", url, str(exc), "request_timeout_ms", "warning")

    def _resource_metadata(self, **extra) -> dict:
        metadata = dict(extra)
        if self.authenticated_context:
            metadata["auth_context"] = "authenticated"
            metadata["discovered_after_login"] = True
        return metadata

    def _auth_context(self) -> str:
        return "authenticated" if self.authenticated_context else "anonymous"

    def _record_api_request(self, request) -> None:
        if not self.capture_api_flows:
            return
        try:
            preview = None
            post_data = request.post_data
            if post_data:
                preview = redacted_preview(post_data)
            self.artifact_candidates.append(
                {
                    "artifact_type": "api_flow",
                    "title": "API flow candidate",
                    "description": "XHR/fetch request observed during crawl. Manual authorization verification is required.",
                    "url": request.url,
                    "http_method": request.method,
                    "redacted_body_preview": preview,
                    "auth_context": self._auth_context(),
                    "verification_required": True,
                    "metadata": {"resource_type": request.resource_type},
                }
            )
        except Exception as exc:
            log.warning("crawl.api_request_artifact_failed", error=str(exc))

    def _record_api_response(self, response) -> None:
        if not self.capture_api_flows:
            return
        try:
            request = response.request
            if request.resource_type not in ("xhr", "fetch"):
                return
            self.artifact_candidates.append(
                {
                    "artifact_type": "response",
                    "title": "API response candidate",
                    "description": "Response metadata observed for an XHR/fetch API candidate.",
                    "url": response.url,
                    "http_method": request.method,
                    "status_code": response.status,
                    "content_type": response.headers.get("content-type", "").split(";")[0].lower() or None,
                    "auth_context": self._auth_context(),
                    "verification_required": True,
                }
            )
        except Exception as exc:
            log.warning("crawl.api_response_artifact_failed", error=str(exc))

    def _is_url_allowed_by_private_policy(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            self._record_policy_event("outside_scope_blocked", url, "Only http and https URLs with hostnames are allowed.", "allowed_hosts", "warning")
            return False
        if self.allow_private_targets:
            return True
        try:
            validate_public_http_url(url)
            return True
        except ValueError as exc:
            event_type = "private_target_blocked" if self._looks_private_host(parsed.hostname) else "outside_scope_blocked"
            self._record_policy_event(event_type, url, str(exc), "allow_private_targets", "error" if event_type == "private_target_blocked" else "warning")
            return False

    def _looks_private_host(self, hostname: str) -> bool:
        host = hostname.lower().rstrip(".")
        if host in ("localhost", "localhost."):
            return True
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(hostname))
            return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        except Exception:
            return False

    def _record_policy_event(self, event_type: str, url: str | None, reason: str, policy_field: str | None = None, severity: str = "info") -> None:
        event = ScanPolicyResolver.policy_event(event_type, url, reason, policy_field, severity)
        dedupe_key = (event_type, url, policy_field)
        existing = {(item.get("event_type"), item.get("url"), item.get("policy_field")) for item in self.policy_events}
        if dedupe_key not in existing:
            self.policy_events.append(event)
            if url:
                self.failed_urls.append({"url": url, "error": reason, "policy_event": event_type})

    async def _record_storage_snapshot(self, page: Page, url: str) -> None:
        try:
            snapshot = await page.evaluate(
                """() => ({
                    localStorage: Object.fromEntries(Object.entries(localStorage)),
                    sessionStorage: Object.fromEntries(Object.entries(sessionStorage))
                })"""
            )
        except Exception as exc:
            log.warning("crawl.storage_snapshot_failed", url=url, error=str(exc))
            return

        for storage_type, values in (snapshot or {}).items():
            if not isinstance(values, dict) or not values:
                continue
            redacted = {str(key): redact_value(str(key), value) for key, value in values.items()}
            self.artifact_candidates.append(
                {
                    "artifact_type": "storage_snapshot",
                    "title": f"{storage_type} snapshot",
                    "description": f"Browser storage keys observed on {url}. Sensitive-looking values are redacted.",
                    "url": url,
                    "storage_type": storage_type,
                    "redacted_body_preview": json.dumps(redacted, ensure_ascii=False, default=str)[:2000],
                    "auth_context": self._auth_context(),
                    "metadata": {"keys": list(redacted.keys())},
                }
            )


def _url_to_filename(url: str) -> str:
    return re.sub(r"[^\w\-]", "_", url)[:80]


def _url_extension(url: str) -> str:
    path = urllib.parse.urlparse(url).path
    ext = Path(path).suffix
    return ext[:10] if ext else ""


def _is_minified(content: bytes) -> bool:
    try:
        text = content.decode("utf-8", errors="ignore")
        lines = text.splitlines()
        if not lines:
            return False
        avg_len = sum(len(l) for l in lines) / len(lines)
        return avg_len > 500
    except Exception:
        return False
