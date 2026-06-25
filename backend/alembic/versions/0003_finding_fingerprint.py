"""add finding fingerprint recurrence fields

Revision ID: 0003_finding_fingerprint
Revises: 0002_finding_triage
Create Date: 2026-06-25
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0003_finding_fingerprint"
down_revision: Union[str, None] = "0002_finding_triage"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("fingerprint", sa.String(length=64), nullable=True))
    op.add_column("findings", sa.Column("duplicate_of_finding_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("findings", sa.Column("recurrence_count", sa.Integer(), nullable=False, server_default="1"))
    op.add_column("findings", sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.create_foreign_key(
        "fk_findings_duplicate_of_finding_id",
        "findings",
        "findings",
        ["duplicate_of_finding_id"],
        ["id"],
    )
    op.create_index(op.f("ix_findings_fingerprint"), "findings", ["fingerprint"], unique=False)
    op.alter_column("findings", "recurrence_count", server_default=None)


def downgrade() -> None:
    op.drop_index(op.f("ix_findings_fingerprint"), table_name="findings")
    op.drop_constraint("fk_findings_duplicate_of_finding_id", "findings", type_="foreignkey")
    op.drop_column("findings", "last_seen_at")
    op.drop_column("findings", "first_seen_at")
    op.drop_column("findings", "recurrence_count")
    op.drop_column("findings", "duplicate_of_finding_id")
    op.drop_column("findings", "fingerprint")
