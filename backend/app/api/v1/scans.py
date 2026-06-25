import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.api.deps import DB, CurrentUser
from app.core.security import validate_target_url
from app.models.project import Project
from app.models.scan import AuthMethod, Scan, ScanSession, ScanStatus
from app.schemas.scan import AuthConfig, ScanCreate, ScanOut
from app.services.scan_diff import build_cross_scan_diff, normalized_origin, scan_auth_method
from app.workers.scan_worker import orchestrate_scan

router = APIRouter(prefix="/scans", tags=["scans"])


async def _get_scan_or_404(scan_id: uuid.UUID, user: "User", db: DB) -> Scan:
    result = await db.execute(
        select(Scan)
        .join(Project)
        .where(Scan.id == scan_id, Project.user_id == user.id)
        .options(selectinload(Scan.session))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def create_scan(payload: ScanCreate, current_user: CurrentUser, db: DB) -> Scan:
    try:
        validate_target_url(payload.target_url)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    proj_result = await db.execute(
        select(Project).where(Project.id == payload.project_id, Project.user_id == current_user.id)
    )
    if not proj_result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    scan = Scan(
        project_id=payload.project_id,
        target_url=payload.target_url,
        status=ScanStatus.PENDING,
        config=payload.config.model_dump(),
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    await db.flush()

    await _store_session(scan.id, payload.auth, db)
    await db.flush()

    if payload.auth.method == AuthMethod.BROWSER:
        scan.status = ScanStatus.PENDING
        scan.celery_task_id = None
        await db.commit()
        await db.refresh(scan)
    else:
        await db.commit()
        task = orchestrate_scan.delay(str(scan.id))
        scan.celery_task_id = task.id
        await db.commit()
        await db.refresh(scan)
    return scan


async def _store_session(scan_id: uuid.UUID, auth: AuthConfig, db: DB) -> None:
    import json
    from app.core.security import encrypt_session_data
    from app.services.auth.browser_auth import normalize_cookies

    session = ScanSession(scan_id=scan_id, auth_method=auth.method)

    if auth.method == AuthMethod.COOKIES and auth.cookies_json:
        cookies = normalize_cookies(auth.cookies_json)
        session.cookies_encrypted = encrypt_session_data(json.dumps(cookies).encode("utf-8"))

    if auth.method == AuthMethod.BEARER and auth.bearer_token:
        headers = {"Authorization": f"Bearer {auth.bearer_token}"}
        session.headers_encrypted = encrypt_session_data(json.dumps(headers).encode("utf-8"))

    if auth.custom_headers:
        existing = {}
        if session.headers_encrypted:
            from app.core.security import decrypt_session_data
            existing = json.loads(decrypt_session_data(session.headers_encrypted))
        existing.update(auth.custom_headers)
        session.headers_encrypted = encrypt_session_data(json.dumps(existing).encode("utf-8"))

    db.add(session)


@router.get("", response_model=list[ScanOut])
async def list_scans(
    current_user: CurrentUser,
    db: DB,
    project_id: Annotated[uuid.UUID | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Scan]:
    q = select(Scan).join(Project).where(Project.user_id == current_user.id)
    if project_id:
        q = q.where(Scan.project_id == project_id)
    q = q.order_by(Scan.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(q)
    return list(result.scalars().all())


@router.post("/compare")
async def compare_scans(payload: dict, current_user: CurrentUser, db: DB) -> dict:
    try:
        base_scan_id = uuid.UUID(str(payload.get("base_scan_id") or payload.get("scan_id")))
        compare_scan_id = uuid.UUID(str(payload.get("compare_scan_id")))
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="base_scan_id and compare_scan_id are required UUIDs",
        )

    result = await db.execute(
        select(Scan)
        .join(Project)
        .where(Scan.id.in_([base_scan_id, compare_scan_id]), Project.user_id == current_user.id)
        .options(selectinload(Scan.session), selectinload(Scan.resources), selectinload(Scan.findings))
    )
    scans = {scan.id: scan for scan in result.scalars().all()}
    base_scan = scans.get(base_scan_id)
    compare_scan = scans.get(compare_scan_id)
    if not base_scan or not compare_scan:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Both scans must exist and belong to the current user",
        )
    if base_scan.project_id != compare_scan.project_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Scans must belong to the same project",
        )
    if normalized_origin(base_scan.target_url) != normalized_origin(compare_scan.target_url):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Scans must have the same normalized target origin",
        )
    if base_scan.status != ScanStatus.COMPLETED or compare_scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Both scans must be completed")

    return build_cross_scan_diff(base_scan, compare_scan)


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: uuid.UUID, current_user: CurrentUser, db: DB) -> Scan:
    return await _get_scan_or_404(scan_id, current_user, db)


@router.get("/{scan_id}/diff-candidates")
async def diff_candidates(scan_id: uuid.UUID, current_user: CurrentUser, db: DB) -> list[dict]:
    scan = await _get_scan_or_404(scan_id, current_user, db)
    result = await db.execute(
        select(Scan)
        .join(Project)
        .where(
            Project.user_id == current_user.id,
            Scan.project_id == scan.project_id,
            Scan.id != scan.id,
            Scan.status == ScanStatus.COMPLETED,
        )
        .options(selectinload(Scan.session))
        .order_by(Scan.created_at.desc())
    )
    origin = normalized_origin(scan.target_url)
    candidates = [
        candidate for candidate in result.scalars().all()
        if normalized_origin(candidate.target_url) == origin
    ]
    return [
        {
            "id": str(candidate.id),
            "target_url": candidate.target_url,
            "status": candidate.status.value,
            "auth_method": scan_auth_method(candidate),
            "created_at": candidate.created_at,
            "completed_at": candidate.completed_at,
        }
        for candidate in candidates
    ]


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: uuid.UUID, current_user: CurrentUser, db: DB) -> dict:
    scan = await _get_scan_or_404(scan_id, current_user, db)
    if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan already finished")

    if scan.celery_task_id:
        from app.core.celery_app import celery_app
        celery_app.control.revoke(scan.celery_task_id, terminate=True)

    scan.status = ScanStatus.CANCELLED
    return {"detail": "Scan cancelled"}


@router.post("/{scan_id}/browser-auth/start")
async def start_browser_auth(scan_id: uuid.UUID, current_user: CurrentUser, db: DB) -> dict:
    """Trigger headful browser for user-assisted login."""
    scan = await _get_scan_or_404(scan_id, current_user, db)
    if scan.status != ScanStatus.PENDING:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan not in pending state")

    from app.workers.scan_worker import run_browser_auth
    scan.status = ScanStatus.AUTHENTICATING
    await db.commit()
    task = run_browser_auth.delay(str(scan_id))
    scan.celery_task_id = task.id
    await db.commit()
    return {"task_id": task.id, "detail": "Browser auth session started"}
