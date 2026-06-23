import uuid
from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select

from app.api.deps import DB, CurrentUser
from app.models.project import Project
from app.models.report import Report
from app.models.scan import Scan, ScanStatus
from app.schemas.report import ReportOut, ReportRequest
from app.workers.report_worker import generate_report

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/scans/{scan_id}/generate", response_model=ReportOut, status_code=status.HTTP_202_ACCEPTED)
async def request_report(scan_id: uuid.UUID, payload: ReportRequest, current_user: CurrentUser, db: DB) -> Report:
    result = await db.execute(
        select(Scan).join(Project).where(Scan.id == scan_id, Project.user_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan not yet completed")

    report = Report(
        scan_id=scan_id,
        format=payload.format,
        report_type=payload.report_type,
    )
    db.add(report)
    await db.flush()

    generate_report.delay(str(report.id))
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
