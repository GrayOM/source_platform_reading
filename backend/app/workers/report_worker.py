"""Celery task for report generation."""
import uuid
from pathlib import Path

import structlog

from app.core.celery_app import celery_app
from app.core.config import get_settings

log = structlog.get_logger()
settings = get_settings()


@celery_app.task(bind=True, name="app.workers.report_worker.generate_report")
def generate_report(self, report_id: str, compare_scan_id: str | None = None) -> dict:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker, selectinload
    from app.models.report import Report
    from app.models.scan import Scan
    from app.models.finding import Finding
    from app.services.report.report_engine import ReportEngine
    from app.services.scan_diff import build_cross_scan_diff
    from sqlalchemy import select

    sync_url = settings.database_url.replace("+asyncpg", "+psycopg2")
    engine = create_engine(sync_url, pool_pre_ping=True)
    Session = sessionmaker(bind=engine)
    db = Session()

    try:
        report = db.get(Report, uuid.UUID(report_id))
        if not report:
            return {"error": "Report not found"}

        scan = db.execute(
            select(Scan)
            .where(Scan.id == report.scan_id)
            .options(
                selectinload(Scan.session),
                selectinload(Scan.project),
                selectinload(Scan.resources),
                selectinload(Scan.findings).selectinload(Finding.evidence_artifacts),
                selectinload(Scan.evidence_artifacts),
            )
        ).scalar_one()
        findings = db.execute(
            select(Finding)
            .where(Finding.scan_id == report.scan_id)
            .options(selectinload(Finding.evidence_artifacts))
        ).scalars().all()
        cross_scan_diff = None
        if compare_scan_id:
            compare_scan = db.execute(
                select(Scan)
                .where(Scan.id == uuid.UUID(compare_scan_id))
                .options(selectinload(Scan.session), selectinload(Scan.resources), selectinload(Scan.findings))
            ).scalar_one()
            cross_scan_diff = build_cross_scan_diff(scan, compare_scan)

        output_dir = settings.scan_data_path / str(scan.id) / "reports"
        engine_svc = ReportEngine(
            scan=scan,
            findings=list(findings),
            output_dir=output_dir,
            cross_scan_diff=cross_scan_diff,
        )
        file_path = engine_svc.generate(report.format, report.report_type)

        report.file_path = str(file_path)
        report.file_size = file_path.stat().st_size
        db.commit()

        log.info("report.generated", report_id=report_id, path=str(file_path))
        return {"status": "generated", "file_path": str(file_path)}

    except Exception as exc:
        log.error("report.failed", report_id=report_id, error=str(exc))
        raise
    finally:
        db.close()
        engine.dispose()
