from fastapi import APIRouter

from app.api.v1 import auth, findings, projects, reports, scans

router = APIRouter()

router.include_router(auth.router)
router.include_router(projects.router)
router.include_router(scans.router)
router.include_router(findings.router)
router.include_router(reports.router)
