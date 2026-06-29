"""add report metadata

Revision ID: 0005_report_metadata
Revises: 0004_evidence_artifacts
Create Date: 2026-06-29
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0005_report_metadata"
down_revision: Union[str, None] = "0004_evidence_artifacts"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "reports",
        sa.Column(
            "report_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.alter_column("reports", "report_metadata", server_default=None)


def downgrade() -> None:
    op.drop_column("reports", "report_metadata")
