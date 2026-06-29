import uuid
from datetime import datetime

from typing import Literal

from pydantic import BaseModel, Field

from app.models.scan import AuthMethod, ScanPhase, ScanStatus


class ScanConfig(BaseModel):
    max_depth: int = Field(default=5, ge=1, le=20)
    max_pages: int = Field(default=500, ge=1, le=5000)
    concurrency: int = Field(default=5, ge=1, le=20)
    excluded_paths: list[str] = Field(default_factory=list)
    included_paths: list[str] = Field(default_factory=list)
    follow_subdomains: bool = False
    wait_for_network_idle: bool = True
    screenshot_pages: bool = True
    analyze_source_maps: bool = True
    allow_external_resources: bool = False


class ScanPolicy(BaseModel):
    policy_name: str | None = Field(default=None, max_length=120)
    intensity: Literal["low", "normal", "careful"] = "careful"
    max_pages: int | None = Field(default=None, ge=1, le=5000)
    max_resources: int | None = Field(default=None, ge=1, le=5000)
    max_depth: int | None = Field(default=None, ge=1, le=20)
    request_delay_ms: int | None = Field(default=None, ge=0, le=10000)
    max_concurrency: int | None = Field(default=None, ge=1, le=50)
    request_timeout_ms: int | None = Field(default=None, ge=1000, le=120000)
    same_origin_only: bool | None = None
    allowed_hosts: list[str] = Field(default_factory=list, max_length=50)
    excluded_hosts: list[str] = Field(default_factory=list, max_length=50)
    excluded_paths: list[str] = Field(default_factory=list, max_length=100)
    respect_robots_txt: bool | None = None
    allow_private_targets: bool | None = None
    allow_redirect_outside_scope: bool | None = None
    capture_screenshots: bool | None = None
    capture_storage: bool | None = None
    capture_api_flows: bool | None = None
    authorization_confirmed: bool | None = None
    notes: str | None = Field(default=None, max_length=1000)


class AuthConfig(BaseModel):
    method: AuthMethod = AuthMethod.NONE
    cookies_json: str | None = None  # JSON array of cookie objects
    bearer_token: str | None = None
    custom_headers: dict[str, str] | None = None


class ScanCreate(BaseModel):
    project_id: uuid.UUID
    target_url: str = Field(description="Full URL including scheme")
    config: ScanConfig = Field(default_factory=ScanConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    scan_policy: ScanPolicy | None = None


class ScanProgress(BaseModel):
    scan_id: uuid.UUID
    status: ScanStatus
    phase: ScanPhase | None
    progress: int
    pages_discovered: int
    resources_collected: int
    findings_count: int
    message: str | None = None


class ScanOut(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    target_url: str
    status: ScanStatus
    phase: ScanPhase | None
    progress: int
    config: dict
    error_message: str | None
    pages_discovered: int
    resources_collected: int
    findings_count: int
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}
