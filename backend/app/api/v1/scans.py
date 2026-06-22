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
    else:
        task = orchestrate_scan.delay(str(scan.id))
        scan.celery_task_id = task.id
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


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: uuid.UUID, current_user: CurrentUser, db: DB) -> Scan:
    return await _get_scan_or_404(scan_id, current_user, db)


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
    task = run_browser_auth.delay(str(scan_id))
    scan.celery_task_id = task.id
    scan.status = ScanStatus.AUTHENTICATING
    return {"task_id": task.id, "detail": "Browser auth session started"}
