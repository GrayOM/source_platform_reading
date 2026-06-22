"""Playwright-based authenticated recursive crawler.

Discovers pages, collects resource URLs (JS/CSS/XHR/Fetch/WS), and
downloads all unique resources while respecting scope and limits.
"""
import asyncio
import hashlib
import re
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

        self.max_depth = config.get("max_depth", settings.max_crawl_depth)
        self.max_pages = config.get("max_pages", settings.max_crawl_pages)
        self.concurrency = config.get("concurrency", settings.crawl_concurrency)
        self.follow_subdomains = config.get("follow_subdomains", False)
        self.allow_external_resources = config.get("allow_external_resources", settings.allow_external_resources)
        self.excluded_paths: list[str] = config.get("excluded_paths", [])
        self.screenshot = config.get("screenshot_pages", True)

        self.visited_pages: set[str] = set()
        self.queued_pages: set[str] = set()
        self.discovered_resources: dict[str, DiscoveredResource] = {}
        self.endpoint_candidates: set[str] = set()
        self.ws_urls: set[str] = set()
        self.failed_urls: list[dict] = []
        self.sitemap_builder = SitemapBuilder()
        self.semaphore: asyncio.Semaphore | None = None

    def _is_in_scope(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if self.follow_subdomains:
            base = ".".join(self.base_domain.split(".")[-2:])
            return parsed.netloc.endswith(base)
        return parsed.netloc == self.base_domain

    def _can_download_resource(self, url: str) -> bool:
        if not self.allow_external_resources and not self._is_in_scope(url):
            return False
        try:
            validate_public_http_url(url)
        except ValueError:
            return False
        return True

    def _is_excluded(self, url: str) -> bool:
        path = urllib.parse.urlparse(url).path
        return any(path.startswith(ex) for ex in self.excluded_paths)

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
        )

    async def _crawl_page(self, context: BrowserContext, url: str, depth: int, parent: str | None) -> None:
        if depth > self.max_depth:
            return
        if len(self.visited_pages) >= self.max_pages:
            return
        if url in self.visited_pages:
            return
        if not self._is_in_scope(url) or self._is_excluded(url):
            return

        self.visited_pages.add(url)
        self.sitemap_builder.add_page(url, parent)

        async with self.semaphore:
            try:
                page: Page = await context.new_page()
                discovered_on_this_page: list[str] = []

                async def handle_request(route: Route):
                    req = route.request
                    req_url = req.url
                    resource_type = req.resource_type

                    if resource_type in ("xhr", "fetch"):
                        self.endpoint_candidates.add(req_url)
                    elif resource_type == "websocket":
                        self.ws_urls.add(req_url)
                    elif resource_type in ("script", "stylesheet", "image", "font", "document"):
                        rtype = classify_url(req_url)
                        if rtype and self._can_download_resource(req_url) and req_url not in self.discovered_resources:
                            discovered_on_this_page.append(req_url)
                            self.discovered_resources[req_url] = DiscoveredResource(
                                url=req_url,
                                resource_type=rtype,
                                discovered_on_page=url,
                            )

                    await route.continue_()

                await page.route("**/*", handle_request)

                validate_public_http_url(url)
                response = await page.goto(url, wait_until="networkidle", timeout=settings.crawl_timeout_seconds * 1000)
                if response:
                    status = response.status
                    final_url = response.url
                    validate_public_http_url(final_url)
                    if not self._is_in_scope(final_url):
                        await page.close()
                        return
                    content_type = response.headers.get("content-type", "").split(";")[0].lower()
                    if content_type in ("", "text/html", "application/xhtml+xml"):
                        self.discovered_resources[final_url] = DiscoveredResource(
                            url=final_url,
                            resource_type=ResourceType.HTML,
                            http_status=status,
                            discovered_on_page=parent,
                            metadata={"page": True, "requested_url": url},
                        )

                if self.screenshot:
                    screenshot_path = self.output_dir / "screenshots" / f"{_url_to_filename(url)}.png"
                    await page.screenshot(path=str(screenshot_path), full_page=True)

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
                child_pages = []
                for link in (links or []):
                    norm = self._normalize_url(link, url)
                    if norm and self._is_in_scope(norm) and norm not in self.visited_pages:
                        child_pages.append(norm)
                        self.sitemap_builder.add_link(url, norm)

                if self.progress_callback:
                    await asyncio.to_thread(
                        self.progress_callback,
                        len(self.visited_pages),
                        len(self.discovered_resources),
                    )

                for child_url in child_pages:
                    await self._crawl_page(context, child_url, depth + 1, url)

            except Exception as exc:
                log.warning("crawl.page_failed", url=url, error=str(exc))
                self.failed_urls.append({"url": url, "error": str(exc)})
                self.discovered_resources[url] = DiscoveredResource(
                    url=url,
                    resource_type=ResourceType.OTHER,
                    discovered_on_page=parent,
                    metadata={"failed": True, "error": str(exc)},
                )

    async def _download_resource(self, url: str, discovered_on: str) -> None:
        if url in self.discovered_resources and self.discovered_resources[url].file_path:
            return  # already downloaded
        if not self._can_download_resource(url):
            return

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=30) as client:
                resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                if not self._can_download_resource(str(resp.url)):
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
                )

                # Automatically queue source maps for download
                if source_map_url and source_map_url not in self.discovered_resources:
                    await self._download_resource(source_map_url, url)

        except Exception as exc:
            log.warning("crawl.download_failed", url=url, error=str(exc))


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
