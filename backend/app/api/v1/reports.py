import uuid
import json
import zipfile
from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.api.deps import DB, CurrentUser
from app.core.config import get_settings
from app.models.finding import Finding
from app.models.project import Project
from app.models.report import Report, ReportFormat, ReportType
from app.models.scan import Scan, ScanStatus
from app.schemas.report import ReportOut, ReportRequest
from app.services.report.report_engine import ReportEngine
from app.services.scan_diff import normalized_origin
from app.workers.report_worker import generate_report

router = APIRouter(prefix="/reports", tags=["reports"])
settings = get_settings()


@router.post("/scans/{scan_id}/generate", response_model=ReportOut, status_code=status.HTTP_202_ACCEPTED)
async def request_report(scan_id: uuid.UUID, payload: ReportRequest, current_user: CurrentUser, db: DB) -> Report:
    result = await db.execute(
        select(Scan)
        .join(Project)
        .where(Scan.id == scan_id, Project.user_id == current_user.id)
        .options(selectinload(Scan.session))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan not yet completed")

    if payload.compare_scan_id:
        compare_result = await db.execute(
            select(Scan)
            .join(Project)
            .where(Scan.id == payload.compare_scan_id, Project.user_id == current_user.id)
            .options(selectinload(Scan.session))
        )
        compare_scan = compare_result.scalar_one_or_none()
        if not compare_scan:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="compare_scan_id was not found or is not accessible",
            )
        if compare_scan.id == scan.id:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="compare_scan_id must reference a different scan",
            )
        if compare_scan.project_id != scan.project_id:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="compare_scan_id must belong to the same project",
            )
        if normalized_origin(compare_scan.target_url) != normalized_origin(scan.target_url):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="compare_scan_id must have the same normalized target origin",
            )
        if compare_scan.status != ScanStatus.COMPLETED:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Compare scan not yet completed",
            )

    report = Report(
        scan_id=scan_id,
        format=payload.format,
        report_type=payload.report_type,
    )
    db.add(report)
    await db.flush()
    await db.commit()

    generate_report.delay(str(report.id), str(payload.compare_scan_id) if payload.compare_scan_id else None)
    await db.refresh(report)
    return report


@router.get("/scans/{scan_id}", response_model=list[ReportOut])
async def list_reports(scan_id: uuid.UUID, current_user: CurrentUser, db: DB) -> list[Report]:
    result = await db.execute(
        select(Report)
        .join(Scan)
        .join(Project)
        .where(Scan.id == scan_id, Project.user_id == current_user.id)
        .order_by(Report.created_at.desc())
    )
    return list(result.scalars().all())


@router.post("/scans/{scan_id}/evidence-bundle")
async def export_evidence_bundle(scan_id: uuid.UUID, current_user: CurrentUser, db: DB) -> FileResponse:
    result = await db.execute(
        select(Scan)
        .join(Project)
        .where(Scan.id == scan_id, Project.user_id == current_user.id)
        .options(
            selectinload(Scan.session),
            selectinload(Scan.project),
            selectinload(Scan.resources),
            selectinload(Scan.evidence_artifacts),
            selectinload(Scan.findings).selectinload(Finding.evidence_artifacts),
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan not yet completed")

    output_dir = settings.scan_data_path / str(scan.id) / "reports"
    engine = ReportEngine(scan=scan, findings=list(scan.findings), output_dir=output_dir)
    json_report = engine.generate(ReportFormat.JSON, ReportType.FULL)
    markdown_report = engine.generate(ReportFormat.MARKDOWN, ReportType.FULL)
    html_report = engine.generate(ReportFormat.HTML, ReportType.FULL)
    kisa_html_report = engine.generate(ReportFormat.HTML, ReportType.KISA)
    kisa_markdown_report = engine.generate(ReportFormat.MARKDOWN, ReportType.KISA)
    ctx = engine._build_context(ReportType.FULL)
    artifact_index_path = output_dir / "artifact_index.json"
    artifact_index_path.write_text(json.dumps(ctx["artifact_index"], indent=2, default=str), encoding="utf-8")

    bundle_path = output_dir / f"evidence_bundle_{str(scan.id)[:8]}.zip"
    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in (json_report, markdown_report, html_report, artifact_index_path):
            zf.write(path, arcname=path.name)
        zf.write(kisa_html_report, arcname="kisa_report.html")
        zf.write(kisa_markdown_report, arcname="kisa_summary.md")
        for artifact in scan.evidence_artifacts:
            screenshot_path = Path(artifact.screenshot_path) if artifact.screenshot_path else None
            if screenshot_path and screenshot_path.exists() and screenshot_path.is_file():
                zf.write(screenshot_path, arcname=f"screenshots/{screenshot_path.name}")

    return FileResponse(
        path=str(bundle_path),
        media_type="application/zip",
        filename=bundle_path.name,
    )


@router.get("/{report_id}/download")
async def download_report(report_id: uuid.UUID, current_user: CurrentUser, db: DB) -> FileResponse:
    result = await db.execute(
        select(Report)
        .join(Scan)
        .join(Project)
        .where(Report.id == report_id, Project.user_id == current_user.id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    if not report.file_path or not Path(report.file_path).exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file not ready")

    file_path = Path(report.file_path)
    suffix = file_path.suffix.lower().lstrip(".")
    media_format = "markdown" if suffix == "md" else suffix or report.format.value
    media_types = {"pdf": "application/pdf", "html": "text/html", "json": "application/json", "markdown": "text/markdown"}
    return FileResponse(
        path=report.file_path,
        media_type=media_types.get(media_format, "application/octet-stream"),
        filename=file_path.name,
    )
