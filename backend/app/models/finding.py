import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, enum.Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    OUT_OF_SCOPE = "out_of_scope"
    ACCEPTED = "accepted"


class VulnType(str, enum.Enum):
    XSS = "xss"
    SQLI = "sql_injection"
    SECRET_LEAK = "secret_leak"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    MISSING_AUTH = "missing_auth"
    SENSITIVE_DATA = "sensitive_data"
    INSECURE_STORAGE = "insecure_storage"
    API_KEY_EXPOSURE = "api_key_exposure"
    JWT_WEAKNESS = "jwt_weakness"
    CSRF = "csrf"
    OPEN_REDIRECT = "open_redirect"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    BUSINESS_LOGIC = "business_logic"
    OTHER = "other"


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False, index=True)
    resource_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("resources.id"), nullable=True
    )
    agent_name: Mapped[str] = mapped_column(String(100), nullable=False)
    vulnerability_type: Mapped[VulnType] = mapped_column(Enum(VulnType), nullable=False, index=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    affected_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    affected_parameter: Mapped[str | None] = mapped_column(String(500), nullable=True)
    evidence: Mapped[dict] = mapped_column(JSONB, default=dict)
    cwe_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(200), nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus), default=FindingStatus.NEW, nullable=False, index=True
    )
    analyst_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
    resource: Mapped["Resource | None"] = relationship("Resource", back_populates="findings")
