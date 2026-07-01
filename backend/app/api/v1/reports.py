import uuid
import hashlib
import json
import zipfile
from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from starlette.concurrency import run_in_threadpool

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
        report_metadata=payload.report_metadata.model_dump(mode="json", exclude_none=True) if payload.report_metadata else {},
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

    metadata_result = await db.execute(
        select(Report)
        .where(Report.scan_id == scan.id)
        .order_by(Report.created_at.desc())
    )
    metadata_report = next((report for report in metadata_result.scalars().all() if report.report_metadata), None)
    report_metadata = metadata_report.report_metadata if metadata_report else {}
    bundle_path = await run_in_threadpool(_create_evidence_bundle, scan, report_metadata)

    return FileResponse(
        path=str(bundle_path),
        media_type="application/zip",
        filename=bundle_path.name,
    )


def _create_evidence_bundle(scan: Scan, report_metadata: dict) -> Path:
    output_dir = settings.scan_data_path / str(scan.id) / "reports"
    engine = ReportEngine(scan=scan, findings=list(scan.findings), output_dir=output_dir, report_metadata=report_metadata)
    json_report = engine.generate(ReportFormat.JSON, ReportType.FULL)
    markdown_report = engine.generate(ReportFormat.MARKDOWN, ReportType.FULL)
    html_report = engine.generate(ReportFormat.HTML, ReportType.FULL)
    kisa_html_report = engine.generate(ReportFormat.HTML, ReportType.KISA)
    kisa_markdown_report = engine.generate(ReportFormat.MARKDOWN, ReportType.KISA)
    ctx = engine._build_context(ReportType.FULL)
    artifact_index_path = output_dir / "artifact_index.json"
    artifact_index_path.write_text(json.dumps(ctx["artifact_index"], indent=2, default=str), encoding="utf-8")
    report_metadata_path = output_dir / "report_metadata.json"
    report_metadata_path.write_text(json.dumps(ctx["report_metadata"], indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    scan_policy_path = output_dir / "scan_policy.json"
    scan_policy_path.write_text(json.dumps(ctx["scan_policy"], indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    policy_events_path = output_dir / "policy_events.json"
    policy_events_path.write_text(json.dumps(ctx["policy_events"], indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    manifest_path = output_dir / "manifest.json"
    readme_path = output_dir / "README.txt"

    short_id = str(scan.id)[:8]
    bundle_path = output_dir / f"sss_evidence_bundle_{short_id}.zip"
    files: list[tuple[Path, str]] = [
        (html_report, "reports/full_report.html"),
        (kisa_html_report, "reports/kisa_report.html"),
        (markdown_report, "reports/summary.md"),
        (json_report, "reports/report.json"),
        (report_metadata_path, "reports/report_metadata.json"),
        (scan_policy_path, "reports/scan_policy.json"),
        (policy_events_path, "reports/policy_events.json"),
        (artifact_index_path, "evidence/artifact_index.json"),
        (kisa_html_report, "kisa_report.html"),
        (kisa_markdown_report, "kisa_summary.md"),
        (artifact_index_path, "artifact_index.json"),
        (report_metadata_path, "report_metadata.json"),
        (scan_policy_path, "scan_policy.json"),
        (policy_events_path, "policy_events.json"),
    ]
    checksums = {arcname: _sha256_file(path) for path, arcname in files}
    screenshot_root = (settings.scan_data_path / str(scan.id) / "screenshots").resolve()
    screenshot_entries: list[tuple[Path, str]] = []
    for artifact in scan.evidence_artifacts:
        screenshot_path = Path(artifact.screenshot_path).resolve() if artifact.screenshot_path else None
        if (
            screenshot_path
            and screenshot_path.is_relative_to(screenshot_root)
            and screenshot_path.exists()
            and screenshot_path.is_file()
        ):
            arcname = f"evidence/screenshots/{screenshot_path.name}"
            screenshot_entries.append((screenshot_path, arcname))
            checksums[arcname] = _sha256_file(screenshot_path)
            legacy_arcname = f"screenshots/{screenshot_path.name}"
            screenshot_entries.append((screenshot_path, legacy_arcname))
            checksums[legacy_arcname] = checksums[arcname]
    preview_entries = _preview_entries(ctx["artifact_index"])
    for arcname, content in preview_entries:
        checksums[arcname] = _sha256_bytes(content)

    readme_path.write_text(_bundle_readme(ctx), encoding="utf-8")
    checksums["README.txt"] = _sha256_file(readme_path)
    manifest = {
        "generated_at": ctx["generated_at"],
        "scan_id": str(scan.id),
        "target_url": scan.target_url,
        "report_type": "kisa",
        "formats_included": ["html", "markdown", "json"],
        "redaction_applied": True,
        "artifact_count": len(ctx["artifact_index"]),
        "policy_event_count": len(ctx["policy_events"]),
        "screenshot_count": len({arc for _path, arc in screenshot_entries if arc.startswith("evidence/screenshots/")}),
        "checksums": checksums,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, arcname in files:
            zf.write(path, arcname=arcname)
        zf.write(manifest_path, arcname="manifest.json")
        zf.write(readme_path, arcname="README.txt")
        for path, arcname in screenshot_entries:
            zf.write(path, arcname=arcname)
        for arcname, content in preview_entries:
            zf.writestr(arcname, content)

    return bundle_path


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
        filename=_download_filename(report, file_path),
    )


def _download_filename(report: Report, file_path: Path) -> str:
    suffix = file_path.suffix.lower().lstrip(".") or report.format.value
    if suffix == "md":
        suffix = "md"
    return f"sss_report_{str(report.scan_id)[:8]}_{report.report_type.value}.{suffix}"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_bytes(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _preview_entries(artifact_index: list[dict]) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for artifact in artifact_index:
        preview = artifact.get("redacted_body_preview") or artifact.get("redacted_value")
        if preview:
            artifact_id = artifact.get("id") or f"artifact-{len(entries) + 1}"
            entries.append((f"evidence/previews/{artifact_id}.txt", str(preview)[:4000]))
    return entries


def _bundle_readme(ctx: dict) -> str:
    limitations = ctx["report_metadata"].get("limitations") or []
    limitation_lines = "\n".join(f"- {item}" for item in limitations) or "- N/A"
    policy = ctx.get("scan_policy") or {}
    return "\n".join(
        [
            "SSS Evidence Bundle",
            "",
            f"Generated at: {ctx['generated_at']}",
            f"Target URL: {ctx['target_url']}",
            f"Scan ID: {ctx['scan_id']}",
            f"Report type: kisa",
            "",
            "Redaction notice:",
            "Sensitive raw values are not intentionally included. Reports and previews use redacted values, hashes, and paths.",
            "",
            "Artifact layout:",
            "- reports/: rendered reports, report metadata, scan policy, and policy events",
            "- evidence/artifact_index.json: structured artifact index",
            "- evidence/screenshots/: screenshot artifacts when available",
            "- evidence/previews/: redacted text previews when available",
            "",
            "Scan policy:",
            f"- Intensity: {policy.get('intensity') or 'N/A'}",
            f"- Limits: pages {policy.get('max_pages') or 'N/A'}, resources {policy.get('max_resources') or 'N/A'}, depth {policy.get('max_depth') or 'N/A'}, concurrency {policy.get('max_concurrency') or 'N/A'}",
            f"- Allowed hosts: {', '.join(policy.get('allowed_hosts') or []) or 'N/A'}",
            f"- Excluded paths: {', '.join(policy.get('excluded_paths') or []) or 'N/A'}",
            f"- Policy events: {len(ctx.get('policy_events') or [])}",
            "",
            "Limitations:",
            limitation_lines,
            "",
        ]
    )
