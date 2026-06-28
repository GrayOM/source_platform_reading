import uuid
from datetime import datetime

from pydantic import BaseModel

from app.models.finding import EvidenceArtifactType


class EvidenceArtifactOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    finding_id: uuid.UUID | None
    artifact_type: EvidenceArtifactType
    title: str
    description: str | None
    file_path: str | None
    url: str | None
    http_method: str | None
    status_code: int | None
    content_type: str | None
    content_hash: str | None
    redacted_body_preview: str | None
    line_start: int | None
    line_end: int | None
    storage_type: str | None
    storage_key: str | None
    redacted_value: str | None
    screenshot_path: str | None
    auth_context: str | None
    verification_required: bool
    extra_metadata: dict
    created_at: datetime

    model_config = {"from_attributes": True, "use_enum_values": True}


class ArtifactSummaryOut(BaseModel):
    total_artifacts: int
    screenshots_count: int
    source_files_count: int
    api_flow_artifacts_count: int
    authenticated_artifacts_count: int
