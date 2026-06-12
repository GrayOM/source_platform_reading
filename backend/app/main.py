from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.api.v1.router import router as api_v1_router
from app.api.v1.websocket import router as ws_router
from app.core.config import get_settings
from app.core.database import engine, Base

settings = get_settings()
log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("sss_platform.startup", environment=settings.environment)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    settings.scan_data_path.mkdir(parents=True, exist_ok=True)
    yield
    log.info("sss_platform.shutdown")
    await engine.dispose()


app = FastAPI(
    title="SSS Platform API",
    version="1.0.0",
    description="Smart Security Scanner — AI-powered web application security assessment platform",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1024)

app.include_router(api_v1_router, prefix=settings.api_prefix)
app.include_router(ws_router)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "version": "1.0.0"}
