import uuid
from datetime import date, datetime
from typing import Annotated

from pydantic import BaseModel, Field, field_validator

from app.models.report import ReportFormat, ReportType

ShortText = Annotated[str, Field(max_length=255)]
LongText = Annotated[str, Field(max_length=4000)]
TextList = Annotated[list[Annotated[str, Field(max_length=1000)]], Field(max_length=20)]


class ReportMetadata(BaseModel):
    report_title: ShortText | None = None
    client_name: ShortText | None = None
    service_name: ShortText | None = None
    organization_name: ShortText | None = None
    author: ShortText | None = None
    reviewer: ShortText | None = None
    document_version: Annotated[str, Field(max_length=50)] | None = None
    report_id: Annotated[str, Field(max_length=100)] | None = None
    classification: Annotated[str, Field(max_length=50)] | None = None
    assessment_start_date: date | None = None
    assessment_end_date: date | None = None
    assessment_scope: LongText | None = None
    out_of_scope: TextList = Field(default_factory=list)
    methodology: TextList = Field(default_factory=list)
    limitations: TextList = Field(default_factory=list)
    contact: ShortText | None = None
    prepared_date: date | None = None
    executive_summary_note: LongText | None = None
    remediation_due_date: date | None = None
    custom_notes: LongText | None = None

    @field_validator("classification")
    @classmethod
    def validate_classification(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        allowed = {"Public", "Internal", "Confidential", "Restricted"}
        if value not in allowed:
            raise ValueError("classification must be one of Public, Internal, Confidential, Restricted")
        return value

    @field_validator("out_of_scope", "methodology", "limitations", mode="before")
    @classmethod
    def normalize_text_list(cls, value):
        if value is None or value == "":
            return []
        if isinstance(value, str):
            return [line.strip() for line in value.splitlines() if line.strip()]
        return value


class ReportRequest(BaseModel):
    format: ReportFormat = ReportFormat.PDF
    report_type: ReportType = ReportType.FULL
    compare_scan_id: uuid.UUID | None = None
    report_metadata: ReportMetadata | None = None


class ReportOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    format: ReportFormat
    report_type: ReportType
    report_metadata: dict
    file_path: str | None
    file_size: int
    created_at: datetime

    model_config = {"from_attributes": True}
