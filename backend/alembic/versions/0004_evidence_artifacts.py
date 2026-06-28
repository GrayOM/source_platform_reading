"""add finding evidence artifacts

Revision ID: 0004_evidence_artifacts
Revises: 0003_finding_fingerprint
Create Date: 2026-06-25
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0004_evidence_artifacts"
down_revision: Union[str, None] = "0003_finding_fingerprint"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

artifact_type = postgresql.ENUM(
    "SOURCE_FILE",
    "CODE_SNIPPET",
    "REQUEST",
    "RESPONSE",
    "SCREENSHOT",
    "STORAGE_SNAPSHOT",
    "SOURCE_MAP",
    "API_FLOW",
    "REPRODUCTION",
    "REPORT_ATTACHMENT",
    name="evidenceartifacttype",
    create_type=False,
)


def upgrade() -> None:
    artifact_type.create(op.get_bind(), checkfirst=True)
    op.create_table(
        "finding_evidence_artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("artifact_type", artifact_type, nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("http_method", sa.String(length=20), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("content_type", sa.String(length=255), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=True),
        sa.Column("redacted_body_preview", sa.Text(), nullable=True),
        sa.Column("line_start", sa.Integer(), nullable=True),
        sa.Column("line_end", sa.Integer(), nullable=True),
        sa.Column("storage_type", sa.String(length=50), nullable=True),
        sa.Column("storage_key", sa.String(length=500), nullable=True),
        sa.Column("redacted_value", sa.Text(), nullable=True),
        sa.Column("screenshot_path", sa.Text(), nullable=True),
        sa.Column("auth_context", sa.String(length=50), nullable=True),
        sa.Column("verification_required", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_finding_evidence_artifacts_artifact_type"), "finding_evidence_artifacts", ["artifact_type"])
    op.create_index(op.f("ix_finding_evidence_artifacts_auth_context"), "finding_evidence_artifacts", ["auth_context"])
    op.create_index(op.f("ix_finding_evidence_artifacts_finding_id"), "finding_evidence_artifacts", ["finding_id"])
    op.create_index(op.f("ix_finding_evidence_artifacts_scan_id"), "finding_evidence_artifacts", ["scan_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_finding_evidence_artifacts_scan_id"), table_name="finding_evidence_artifacts")
    op.drop_index(op.f("ix_finding_evidence_artifacts_finding_id"), table_name="finding_evidence_artifacts")
    op.drop_index(op.f("ix_finding_evidence_artifacts_auth_context"), table_name="finding_evidence_artifacts")
    op.drop_index(op.f("ix_finding_evidence_artifacts_artifact_type"), table_name="finding_evidence_artifacts")
    op.drop_table("finding_evidence_artifacts")
    artifact_type.drop(op.get_bind(), checkfirst=True)
