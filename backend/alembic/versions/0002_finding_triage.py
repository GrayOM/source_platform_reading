"""add finding triage metadata

Revision ID: 0002_finding_triage
Revises: 0001_initial
Create Date: 2026-06-24
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0002_finding_triage"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


triage_status = sa.Enum(
    "CANDIDATE",
    "VERIFIED",
    "FALSE_POSITIVE",
    "ACCEPTED_RISK",
    "FIXED",
    "NEEDS_REVIEW",
    name="triagestatus",
)


def upgrade() -> None:
    triage_status.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "findings",
        sa.Column("triage_status", triage_status, nullable=False, server_default="CANDIDATE"),
    )
    op.add_column("findings", sa.Column("verification_note", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("reviewed_by", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("findings", sa.Column("fixed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("remediation_status", sa.String(length=100), nullable=True))
    op.create_foreign_key("fk_findings_reviewed_by_users", "findings", "users", ["reviewed_by"], ["id"])
    op.create_index(op.f("ix_findings_triage_status"), "findings", ["triage_status"], unique=False)
    op.alter_column("findings", "triage_status", server_default=None)


def downgrade() -> None:
    op.drop_index(op.f("ix_findings_triage_status"), table_name="findings")
    op.drop_constraint("fk_findings_reviewed_by_users", "findings", type_="foreignkey")
    op.drop_column("findings", "remediation_status")
    op.drop_column("findings", "fixed_at")
    op.drop_column("findings", "reviewed_by")
    op.drop_column("findings", "reviewed_at")
    op.drop_column("findings", "verification_note")
    op.drop_column("findings", "triage_status")
    triage_status.drop(op.get_bind(), checkfirst=True)
