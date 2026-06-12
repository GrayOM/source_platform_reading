import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models.finding import FindingStatus, Severity, VulnType


class FindingCreate(BaseModel):
    resource_id: uuid.UUID | None = None
    agent_name: str
    vulnerability_type: VulnType
    severity: Severity
    title: str = Field(max_length=500)
    description: str
    affected_url: str | None = None
    affected_parameter: str | None = None
    evidence: dict = Field(default_factory=dict)
    cwe_id: int | None = None
    cvss_score: float | None = Field(None, ge=0.0, le=10.0)
    cvss_vector: str | None = None
    owasp_category: str | None = None
    recommendation: str = ""


class FindingUpdate(BaseModel):
    status: FindingStatus | None = None
    analyst_note: str | None = None
    severity: Severity | None = None


class FindingOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    resource_id: uuid.UUID | None
    agent_name: str
    vulnerability_type: VulnType
    severity: Severity
    title: str
    description: str
    affected_url: str | None
    affected_parameter: str | None
    evidence: dict
    cwe_id: int | None
    cvss_score: float | None
    cvss_vector: str | None
    owasp_category: str | None
    recommendation: str
    status: FindingStatus
    analyst_note: str | None
    created_at: datetime

    model_config = {"from_attributes": True}
