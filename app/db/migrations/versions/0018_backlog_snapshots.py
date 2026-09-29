"""Daily snapshots of the backlog, per team

Revision ID: 0018
Revises: 0017
Create Date: 2026-09-29

Trends need history. The daily pass records each day as it ended, and rebuilds
the last 90 days (marked estimated) from detection and fix dates on its first
run, or when an administrator asks for it.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: Union[str, None] = "0017"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "backlog_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("owner_team", sa.String(length=128), server_default="", nullable=False),
        sa.Column("estimated", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("open_findings", sa.Integer(), nullable=False),
        sa.Column("open_high", sa.Integer(), nullable=False),
        sa.Column("open_kev", sa.Integer(), nullable=False),
        sa.Column("overdue", sa.Integer(), nullable=False),
        sa.Column("open_risk", sa.Float(), nullable=False),
        sa.Column("new_findings", sa.Integer(), nullable=False),
        sa.Column("fixed", sa.Integer(), nullable=False),
        sa.Column("fixed_on_time", sa.Integer(), nullable=False),
        sa.Column("fixed_days_total", sa.Float(), nullable=False),
        sa.Column("fixed_risk", sa.Float(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("day", "owner_team", name="uq_backlog_snapshot_day_team"),
    )
    op.create_index("ix_backlog_snapshots_day", "backlog_snapshots", ["day"])


def downgrade() -> None:
    op.drop_index("ix_backlog_snapshots_day", table_name="backlog_snapshots")
    op.drop_table("backlog_snapshots")
