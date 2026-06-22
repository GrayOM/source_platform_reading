"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-06-22
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("is_superuser", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)

    op.create_table(
        "projects",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    auth_method = sa.Enum("NONE", "BROWSER", "COOKIES", "BEARER", "BASIC", name="authmethod")
    scan_phase = sa.Enum("AUTH", "CRAWL", "COLLECT", "ANALYZE", "REPORT", name="scanphase")
    scan_status = sa.Enum("PENDING", "AUTHENTICATING", "CRAWLING", "ANALYZING", "REPORTING", "COMPLETED", "FAILED", "CANCELLED", name="scanstatus")
    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_url", sa.Text(), nullable=False),
        sa.Column("status", scan_status, nullable=False),
        sa.Column("phase", scan_phase, nullable=True),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("config", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("celery_task_id", sa.String(length=255), nullable=True),
        sa.Column("pages_discovered", sa.Integer(), nullable=False),
        sa.Column("resources_collected", sa.Integer(), nullable=False),
        sa.Column("findings_count", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scans_status"), "scans", ["status"], unique=False)

    op.create_table(
        "scan_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("auth_method", auth_method, nullable=False),
        sa.Column("cookies_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("headers_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("storage_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id"),
    )

    resource_type = sa.Enum("HTML", "JS", "CSS", "JSON", "SOURCE_MAP", "IMAGE", "FONT", "DOCUMENT", "OTHER", name="resourcetype")
    op.create_table(
        "resources",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("resource_type", resource_type, nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=True),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("mime_type", sa.String(length=255), nullable=True),
        sa.Column("is_minified", sa.Boolean(), nullable=False),
        sa.Column("source_map_url", sa.Text(), nullable=True),
        sa.Column("discovered_on_page", sa.Text(), nullable=True),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_resources_resource_type"), "resources", ["resource_type"], unique=False)
    op.create_index(op.f("ix_resources_scan_id"), "resources", ["scan_id"], unique=False)

    severity = sa.Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", name="severity")
    finding_status = sa.Enum("NEW", "CONFIRMED", "FALSE_POSITIVE", "OUT_OF_SCOPE", "ACCEPTED", name="findingstatus")
    vuln_type = sa.Enum("XSS", "SQLI", "SECRET_LEAK", "IDOR", "AUTH_BYPASS", "MISSING_AUTH", "SENSITIVE_DATA", "INSECURE_STORAGE", "API_KEY_EXPOSURE", "JWT_WEAKNESS", "CSRF", "OPEN_REDIRECT", "PATH_TRAVERSAL", "SSRF", "BUSINESS_LOGIC", "OTHER", name="vulntype")
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("agent_name", sa.String(length=100), nullable=False),
        sa.Column("vulnerability_type", vuln_type, nullable=False),
        sa.Column("severity", severity, nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("affected_url", sa.Text(), nullable=True),
        sa.Column("affected_parameter", sa.String(length=500), nullable=True),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("code_snippet", sa.Text(), nullable=True),
        sa.Column("poc", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("reproduction_steps", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("cwe_id", sa.Integer(), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(length=200), nullable=True),
        sa.Column("owasp_category", sa.String(length=100), nullable=True),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column("status", finding_status, nullable=False),
        sa.Column("analyst_note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["resource_id"], ["resources.id"]),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_findings_scan_id"), "findings", ["scan_id"], unique=False)
    op.create_index(op.f("ix_findings_severity"), "findings", ["severity"], unique=False)
    op.create_index(op.f("ix_findings_status"), "findings", ["status"], unique=False)
    op.create_index(op.f("ix_findings_vulnerability_type"), "findings", ["vulnerability_type"], unique=False)

    report_format = sa.Enum("PDF", "HTML", "JSON", "MARKDOWN", name="reportformat")
    report_type = sa.Enum("KISA", "OWASP", "EXECUTIVE", "TECHNICAL", "FULL", name="reporttype")
    op.create_table(
        "reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("format", report_format, nullable=False),
        sa.Column("report_type", report_type, nullable=False),
        sa.Column("file_path", sa.String(length=500), nullable=True),
        sa.Column("file_size", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_reports_scan_id"), "reports", ["scan_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_reports_scan_id"), table_name="reports")
    op.drop_table("reports")
    op.drop_index(op.f("ix_findings_vulnerability_type"), table_name="findings")
    op.drop_index(op.f("ix_findings_status"), table_name="findings")
    op.drop_index(op.f("ix_findings_severity"), table_name="findings")
    op.drop_index(op.f("ix_findings_scan_id"), table_name="findings")
    op.drop_table("findings")
    op.drop_index(op.f("ix_resources_scan_id"), table_name="resources")
    op.drop_index(op.f("ix_resources_resource_type"), table_name="resources")
    op.drop_table("resources")
    op.drop_table("scan_sessions")
    op.drop_index(op.f("ix_scans_status"), table_name="scans")
    op.drop_table("scans")
    op.drop_table("projects")
    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.drop_table("users")
    for enum_name in ("reporttype", "reportformat", "vulntype", "findingstatus", "severity", "resourcetype", "scanstatus", "scanphase", "authmethod"):
        op.execute(f"DROP TYPE IF EXISTS {enum_name}")
