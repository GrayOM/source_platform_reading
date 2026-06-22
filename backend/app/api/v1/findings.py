import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import case, select

from app.api.deps import DB, CurrentUser
from app.models.finding import Finding, Severity
from app.models.project import Project
from app.models.scan import Scan
from app.schemas.finding import FindingOut, FindingUpdate

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=list[FindingOut])
async def list_findings(
    current_user: CurrentUser,
    db: DB,
    scan_id: Annotated[uuid.UUID | None, Query()] = None,
    severity: Annotated[Severity | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Finding]:
    q = (
        select(Finding)
        .join(Scan)
        .join(Project)
        .where(Project.user_id == current_user.id)
    )
    if scan_id:
        q = q.where(Finding.scan_id == scan_id)
    if severity:
        q = q.where(Finding.severity == severity)
    severity_rank = case(
        (Finding.severity == Severity.CRITICAL, 0),
        (Finding.severity == Severity.HIGH, 1),
        (Finding.severity == Severity.MEDIUM, 2),
        (Finding.severity == Severity.LOW, 3),
        (Finding.severity == Severity.INFO, 4),
        else_=5,
    )
    q = q.order_by(severity_rank, Finding.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(q)
    return list(result.scalars().all())


@router.get("/{finding_id}", response_model=FindingOut)
async def get_finding(finding_id: uuid.UUID, current_user: CurrentUser, db: DB) -> Finding:
    result = await db.execute(
        select(Finding)
        .join(Scan)
        .join(Project)
        .where(Finding.id == finding_id, Project.user_id == current_user.id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding


@router.patch("/{finding_id}", response_model=FindingOut)
async def update_finding(finding_id: uuid.UUID, payload: FindingUpdate, current_user: CurrentUser, db: DB) -> Finding:
    finding = await get_finding(finding_id, current_user, db)
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(finding, field, value)
    return finding
