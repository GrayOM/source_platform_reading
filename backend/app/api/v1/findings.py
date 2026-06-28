import uuid
from typing import Annotated
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import case, or_, select
from sqlalchemy.orm import selectinload

from app.api.deps import DB, CurrentUser
from app.models.finding import Finding, FindingEvidenceArtifact, Severity, TriageStatus
from app.models.project import Project
from app.models.scan import Scan
from app.schemas.evidence import EvidenceArtifactOut
from app.schemas.finding import FindingOut, FindingTriageUpdate, FindingUpdate

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=list[FindingOut])
async def list_findings(
    current_user: CurrentUser,
    db: DB,
    scan_id: Annotated[uuid.UUID | None, Query()] = None,
    severity: Annotated[Severity | None, Query()] = None,
    triage_status: Annotated[TriageStatus | None, Query()] = None,
    only_new: Annotated[bool, Query()] = False,
    recurring: Annotated[bool, Query()] = False,
    previously_verified: Annotated[bool, Query()] = False,
    previously_false_positive: Annotated[bool, Query()] = False,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Finding]:
    q = (
        select(Finding)
        .join(Scan)
        .join(Project)
        .where(Project.user_id == current_user.id)
        .options(selectinload(Finding.evidence_artifacts))
    )
    if scan_id:
        q = q.where(Finding.scan_id == scan_id)
    if severity:
        q = q.where(Finding.severity == severity)
    if triage_status:
        q = q.where(Finding.triage_status == triage_status)
    if only_new:
        q = q.where(Finding.duplicate_of_finding_id.is_(None), Finding.recurrence_count <= 1)
    if recurring:
        q = q.where(or_(Finding.duplicate_of_finding_id.is_not(None), Finding.recurrence_count > 1))
    if previously_verified:
        q = q.where(Finding.evidence["previously_verified"].as_boolean().is_(True))
    if previously_false_positive:
        q = q.where(Finding.evidence["previously_marked_false_positive"].as_boolean().is_(True))
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
        .options(selectinload(Finding.evidence_artifacts))
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding


@router.get("/{finding_id}/artifacts", response_model=list[EvidenceArtifactOut])
async def list_finding_artifacts(
    finding_id: uuid.UUID,
    current_user: CurrentUser,
    db: DB,
) -> list[FindingEvidenceArtifact]:
    finding = await get_finding(finding_id, current_user, db)
    result = await db.execute(
        select(FindingEvidenceArtifact)
        .where(FindingEvidenceArtifact.finding_id == finding.id)
        .order_by(FindingEvidenceArtifact.created_at.desc())
    )
    return list(result.scalars().all())


@router.patch("/{finding_id}", response_model=FindingOut)
async def update_finding(finding_id: uuid.UUID, payload: FindingUpdate, current_user: CurrentUser, db: DB) -> Finding:
    finding = await get_finding(finding_id, current_user, db)
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(finding, field, value)
    return finding


@router.patch("/{finding_id}/triage", response_model=FindingOut)
async def update_finding_triage(
    finding_id: uuid.UUID,
    payload: FindingTriageUpdate,
    current_user: CurrentUser,
    db: DB,
) -> Finding:
    finding = await get_finding(finding_id, current_user, db)
    finding.triage_status = payload.triage_status
    finding.analyst_note = payload.analyst_note
    finding.verification_note = payload.verification_note
    finding.remediation_status = payload.remediation_status
    finding.reviewed_at = datetime.now(timezone.utc)
    finding.reviewed_by = current_user.id
    if payload.triage_status == TriageStatus.FIXED:
        finding.fixed_at = finding.fixed_at or finding.reviewed_at
    elif payload.triage_status != TriageStatus.FIXED:
        finding.fixed_at = None
    return finding
