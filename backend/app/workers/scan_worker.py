"""Celery tasks for scan orchestration: auth, crawl, resource collection."""
import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import structlog
from celery import Task

from app.core.celery_app import celery_app
from app.core.config import get_settings

log = structlog.get_logger()
settings = get_settings()


def _publish_progress(scan_id: str, phase: str, progress: int, message: str = "", **extra):
    import redis as sync_redis
    r = sync_redis.from_url(settings.redis_url)
    data = json.dumps({"scan_id": scan_id, "phase": phase, "progress": progress, "message": message, **extra})
    r.publish(f"scan:{scan_id}:progress", data)
    r.close()


def _sync_db():
    """Get a sync-compatible async session wrapper for Celery tasks."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    sync_url = settings.database_url.replace("+asyncpg", "+psycopg2")
    engine = create_engine(sync_url, pool_pre_ping=True)
    Session = sessionmaker(bind=engine)
    return Session()


@celery_app.task(bind=True, max_retries=1, name="app.workers.scan_worker.orchestrate_scan")
def orchestrate_scan(self: Task, scan_id: str) -> dict:
    """Main scan orchestration: auth → crawl → analyze → report."""
    from app.models.scan import Scan, ScanPhase, ScanStatus

    db = _sync_db()
    try:
        scan = db.get(Scan, uuid.UUID(scan_id))
        if not scan:
            return {"error": "Scan not found"}

        scan.status = ScanStatus.CRAWLING
        scan.phase = ScanPhase.CRAWL
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        _publish_progress(scan_id, "crawl", 5, "Starting crawler...")

        # Run crawler
        output_dir = settings.scan_data_path / scan_id
        crawl_result = _run_crawl(scan, output_dir)

        # Persist discovered resources
        scan.pages_discovered = len(crawl_result.pages)
        scan.resources_collected = len(crawl_result.resources)
        scan.status = ScanStatus.ANALYZING
        scan.phase = ScanPhase.ANALYZE
        scan.progress = 40
        db.commit()

        _publish_progress(scan_id, "analyze", 40, f"Crawl complete. {len(crawl_result.resources)} resources found. Starting AI analysis...")

        _persist_resources(scan_id, crawl_result, db)
        db.commit()

        # Run analysis in async context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            finding_count = loop.run_until_complete(
                _run_analysis_async(scan_id, scan.target_url, crawl_result, output_dir)
            )
        finally:
            loop.close()

        scan.findings_count = finding_count
        scan.status = ScanStatus.COMPLETED
        scan.phase = None
        scan.progress = 100
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()

        _publish_progress(scan_id, "completed", 100, f"Scan complete. {finding_count} findings.", findings_count=finding_count)
        log.info("scan.completed", scan_id=scan_id, findings=finding_count)
        return {"status": "completed", "findings": finding_count}

    except Exception as exc:
        log.error("scan.failed", scan_id=scan_id, error=str(exc))
        try:
            from app.models.scan import ScanStatus
            scan = db.get(Scan, uuid.UUID(scan_id))
            if scan:
                scan.status = ScanStatus.FAILED
                scan.error_message = str(exc)[:1000]
                db.commit()
        except Exception:
            pass
        _publish_progress(scan_id, "failed", 0, f"Error: {str(exc)[:200]}")
        raise
    finally:
        db.close()


def _run_crawl(scan, output_dir: Path):
    from app.services.crawler.crawler import PlaywrightCrawler
    from app.models.scan import ScanSession

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def progress_cb(pages, resources):
        _publish_progress(
            str(scan.id), "crawl",
            min(35, 5 + int(pages / max(1, scan.config.get("max_pages", 500)) * 30)),
            f"Crawling... {pages} pages, {resources} resources",
        )

    try:
        crawler = PlaywrightCrawler(
            scan_id=str(scan.id),
            target_url=scan.target_url,
            session=scan.session,
            config=scan.config,
            output_dir=output_dir,
            progress_callback=progress_cb,
        )
        result = loop.run_until_complete(crawler.crawl())
        return result
    finally:
        loop.close()


def _persist_resources(scan_id: str, crawl_result, db) -> None:
    from app.models.resource import Resource
    for r in crawl_result.resources:
        resource = Resource(
            scan_id=uuid.UUID(scan_id),
            url=r.url,
            resource_type=r.resource_type,
            file_path=r.file_path,
            content_hash=r.content_hash,
            size_bytes=r.size_bytes,
            mime_type=r.mime_type,
            http_status=r.http_status,
            is_minified=r.is_minified,
            source_map_url=r.source_map_url,
            discovered_on_page=r.discovered_on_page,
        )
        db.add(resource)


async def _run_analysis_async(scan_id: str, target_url: str, crawl_result, output_dir: Path) -> int:
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
    from sqlalchemy import select
    from app.models.resource import Resource
    from app.services.analysis.orchestrator import AnalysisOrchestrator

    engine = create_async_engine(settings.database_url, echo=False)
    Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with Session() as db:
        result = await db.execute(
            select(Resource).where(Resource.scan_id == uuid.UUID(scan_id))
        )
        resources = list(result.scalars().all())

        def progress_cb(msg: str):
            _publish_progress(scan_id, "analyze", 60, msg)

        orchestrator = AnalysisOrchestrator(
            scan_id=scan_id,
            target_url=target_url,
            db=db,
            progress_callback=progress_cb,
        )
        findings = await orchestrator.run(
            resources=resources,
            crawl_data={
                "sitemap": crawl_result.sitemap,
                "endpoint_candidates": crawl_result.endpoint_candidates,
            },
        )
        await db.commit()

    await engine.dispose()
    return len(findings)


@celery_app.task(bind=True, name="app.workers.scan_worker.run_browser_auth")
def run_browser_auth(self: Task, scan_id: str) -> dict:
    """Run browser-assisted authentication and store the captured session."""
    import json as _json
    from app.models.scan import Scan, ScanStatus
    from app.core.security import encrypt_session_data
    from app.models.scan import ScanSession, AuthMethod

    db = _sync_db()
    try:
        scan = db.get(Scan, uuid.UUID(scan_id))
        if not scan:
            return {"error": "Scan not found"}

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            from app.services.auth.browser_auth import run_browser_auth_session
            captured = loop.run_until_complete(run_browser_auth_session(scan.target_url))
        finally:
            loop.close()

        session = scan.session or ScanSession(scan_id=scan.id, auth_method=AuthMethod.BROWSER)
        session.auth_method = AuthMethod.BROWSER
        session.cookies_encrypted = encrypt_session_data(
            _json.dumps(captured.cookies).encode("utf-8")
        )
        storage_data = {
            "local_storage": captured.local_storage,
            "session_storage": captured.session_storage,
        }
        session.storage_encrypted = encrypt_session_data(
            _json.dumps(storage_data).encode("utf-8")
        )
        if captured.extra_headers:
            session.headers_encrypted = encrypt_session_data(
                _json.dumps(captured.extra_headers).encode("utf-8")
            )

        if not scan.session:
            db.add(session)
        scan.status = ScanStatus.PENDING
        db.commit()

        _publish_progress(scan_id, "auth", 100, "Authentication captured. Ready to start crawl.")
        return {"status": "auth_captured", "cookies": len(captured.cookies)}

    finally:
        db.close()
