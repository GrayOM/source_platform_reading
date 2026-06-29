"""add report export status

Revision ID: 0006_report_export_status
Revises: 0005_report_metadata
Create Date: 2026-06-29
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006_report_export_status"
down_revision: Union[str, None] = "0005_report_metadata"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("reports", sa.Column("report_status", sa.String(length=50), nullable=False, server_default="queued"))
    op.add_column("reports", sa.Column("error_message", sa.String(length=1000), nullable=True))
    op.alter_column("reports", "report_status", server_default=None)


def downgrade() -> None:
    op.drop_column("reports", "error_message")
    op.drop_column("reports", "report_status")
