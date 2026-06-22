import uuid
from datetime import datetime

from pydantic import BaseModel

from app.models.report import ReportFormat, ReportType


class ReportRequest(BaseModel):
    format: ReportFormat = ReportFormat.PDF
    report_type: ReportType = ReportType.FULL


class ReportOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    format: ReportFormat
    report_type: ReportType
    file_path: str | None
    file_size: int
    created_at: datetime

    model_config = {"from_attributes": True}
