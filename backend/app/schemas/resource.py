import uuid
from datetime import datetime

from pydantic import BaseModel

from app.models.resource import ResourceType


class ResourceOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    url: str
    resource_type: ResourceType
    content_hash: str | None
    size_bytes: int
    mime_type: str | None
    is_minified: bool
    source_map_url: str | None
    http_status: int | None
    metadata: dict
    collected_at: datetime

    model_config = {"from_attributes": True}
