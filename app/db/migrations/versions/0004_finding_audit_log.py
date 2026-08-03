"""Add finding triage audit log

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-03

``status`` and ``status_note`` on asset_vulnerabilities are overwritten on every
triage decision, so there was no way to establish who accepted a risk, when, or
what the finding looked like beforehand. This append-only log makes the
justification the API already requires actually auditable.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "finding_audit_log",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "finding_id",
            sa.Integer(),
            sa.ForeignKey("asset_vulnerabilities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # The user id and name are stored side by side so the trail survives
        # the deletion of the account that produced it.
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(length=64), nullable=True),
        sa.Column("old_status", sa.String(length=32), nullable=True),
        sa.Column("new_status", sa.String(length=32), nullable=False),
        sa.Column("status_note", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_finding_audit_log_finding_id", "finding_audit_log", ["finding_id"]
    )
    op.create_index(
        "ix_finding_audit_log_created_at", "finding_audit_log", ["created_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_finding_audit_log_created_at", table_name="finding_audit_log")
    op.drop_index("ix_finding_audit_log_finding_id", table_name="finding_audit_log")
    op.drop_table("finding_audit_log")
