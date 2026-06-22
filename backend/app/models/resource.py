import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class ResourceType(str, enum.Enum):
    HTML = "html"
    JS = "js"
    CSS = "css"
    JSON = "json"
    SOURCE_MAP = "source_map"
    IMAGE = "image"
    FONT = "font"
    DOCUMENT = "document"
    OTHER = "other"


class Resource(Base):
    __tablename__ = "resources"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False, index=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    resource_type: Mapped[ResourceType] = mapped_column(Enum(ResourceType), nullable=False, index=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    mime_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_minified: Mapped[bool] = mapped_column(Boolean, default=False)
    source_map_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    discovered_on_page: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    extra_metadata: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="resources")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="resource")
