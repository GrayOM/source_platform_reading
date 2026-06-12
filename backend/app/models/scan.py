import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    AUTHENTICATING = "authenticating"
    CRAWLING = "crawling"
    ANALYZING = "analyzing"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanPhase(str, enum.Enum):
    AUTH = "auth"
    CRAWL = "crawl"
    COLLECT = "collect"
    ANALYZE = "analyze"
    REPORT = "report"


class AuthMethod(str, enum.Enum):
    NONE = "none"
    BROWSER = "browser"
    COOKIES = "cookies"
    BEARER = "bearer"
    BASIC = "basic"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True
    )
    phase: Mapped[ScanPhase | None] = mapped_column(Enum(ScanPhase), nullable=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    celery_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    pages_discovered: Mapped[int] = mapped_column(Integer, default=0)
    resources_collected: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    project: Mapped["Project"] = relationship("Project", back_populates="scans")
    session: Mapped["ScanSession | None"] = relationship(
        "ScanSession", back_populates="scan", uselist=False, cascade="all, delete-orphan"
    )
    resources: Mapped[list["Resource"]] = relationship("Resource", back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship("Report", back_populates="scan", cascade="all, delete-orphan")


class ScanSession(Base):
    __tablename__ = "scan_sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id"), unique=True, nullable=False
    )
    auth_method: Mapped[AuthMethod] = mapped_column(Enum(AuthMethod), default=AuthMethod.NONE)
    cookies_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    headers_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    storage_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="session")
