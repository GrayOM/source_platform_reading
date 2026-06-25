import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models.finding import FindingStatus, Severity, TriageStatus, VulnType


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
    code_snippet: str | None = None
    poc: dict = Field(default_factory=dict)
    reproduction_steps: list[str] = Field(default_factory=list)
    cwe_id: int | None = None
    cvss_score: float | None = Field(None, ge=0.0, le=10.0)
    cvss_vector: str | None = None
    owasp_category: str | None = None
    recommendation: str = ""


class FindingUpdate(BaseModel):
    status: FindingStatus | None = None
    analyst_note: str | None = None
    severity: Severity | None = None


class FindingTriageUpdate(BaseModel):
    triage_status: TriageStatus
    analyst_note: str | None = None
    verification_note: str | None = None
    remediation_status: str | None = Field(None, max_length=100)


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
    code_snippet: str | None
    poc: dict
    reproduction_steps: list[str]
    cwe_id: int | None
    cvss_score: float | None
    cvss_vector: str | None
    owasp_category: str | None
    recommendation: str
    status: FindingStatus
    triage_status: TriageStatus
    analyst_note: str | None
    verification_note: str | None
    reviewed_at: datetime | None
    reviewed_by: uuid.UUID | None
    fixed_at: datetime | None
    remediation_status: str | None
    fingerprint: str | None
    duplicate_of_finding_id: uuid.UUID | None
    recurrence_count: int
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    previous_triage_status: str | None
    previous_finding_id: str | None
    previously_verified: bool
    previously_marked_false_positive: bool
    created_at: datetime

    model_config = {"from_attributes": True}
