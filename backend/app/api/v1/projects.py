import uuid

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, select

from app.api.deps import DB, CurrentUser
from app.models.project import Project
from app.models.scan import Scan
from app.schemas.project import ProjectCreate, ProjectOut, ProjectUpdate

router = APIRouter(prefix="/projects", tags=["projects"])


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
async def create_project(payload: ProjectCreate, current_user: CurrentUser, db: DB) -> ProjectOut:
    project = Project(user_id=current_user.id, name=payload.name, description=payload.description)
    db.add(project)
    await db.flush()
    return ProjectOut(id=project.id, name=project.name, description=project.description, created_at=project.created_at)


@router.get("", response_model=list[ProjectOut])
async def list_projects(current_user: CurrentUser, db: DB) -> list[ProjectOut]:
    result = await db.execute(
        select(Project, func.count(Scan.id).label("scan_count"))
        .outerjoin(Scan)
        .where(Project.user_id == current_user.id)
        .group_by(Project.id)
        .order_by(Project.created_at.desc())
    )
    rows = result.all()
    return [
        ProjectOut(
            id=p.id, name=p.name, description=p.description, created_at=p.created_at, scan_count=count
        )
        for p, count in rows
    ]


@router.get("/{project_id}", response_model=ProjectOut)
async def get_project(project_id: uuid.UUID, current_user: CurrentUser, db: DB) -> ProjectOut:
    result = await db.execute(
        select(Project, func.count(Scan.id).label("scan_count"))
        .outerjoin(Scan)
        .where(Project.id == project_id, Project.user_id == current_user.id)
        .group_by(Project.id)
    )
    row = result.one_or_none()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    p, count = row
    return ProjectOut(id=p.id, name=p.name, description=p.description, created_at=p.created_at, scan_count=count)


@router.patch("/{project_id}", response_model=ProjectOut)
async def update_project(project_id: uuid.UUID, payload: ProjectUpdate, current_user: CurrentUser, db: DB) -> ProjectOut:
    result = await db.execute(
        select(Project).where(Project.id == project_id, Project.user_id == current_user.id)
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(project, field, value)
    return ProjectOut(id=project.id, name=project.name, description=project.description, created_at=project.created_at)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(project_id: uuid.UUID, current_user: CurrentUser, db: DB) -> None:
    result = await db.execute(
        select(Project).where(Project.id == project_id, Project.user_id == current_user.id)
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    await db.delete(project)
