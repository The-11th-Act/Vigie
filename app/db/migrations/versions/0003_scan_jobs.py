"""Add scan job history

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-03

An upload used to leave no trace: the only tracking was Celery's result
backend, which is not queryable and expires. This table records who uploaded
what, when, and what the ingestion produced — and is what lets a scan's status
be scoped to its author instead of readable by any authenticated user.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

scan_status_enum = sa.Enum(
    "Pending", "Running", "Success", "Failed", name="scan_status_enum"
)


def upgrade() -> None:
    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("task_id", sa.String(length=155), nullable=True),
        sa.Column("scan_type", sa.String(length=32), nullable=False),
        sa.Column("filename", sa.String(length=512), nullable=False),
        sa.Column(
            "uploaded_by",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "status", scan_status_enum, server_default="Pending", nullable=False
        ),
        sa.Column(
            "processed_records", sa.Integer(), server_default="0", nullable=False
        ),
        sa.Column("new_assets", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "new_vulnerabilities", sa.Integer(), server_default="0", nullable=False
        ),
        sa.Column(
            "new_associations", sa.Integer(), server_default="0", nullable=False
        ),
        sa.Column("reopened", sa.Integer(), server_default="0", nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_scan_jobs_task_id", "scan_jobs", ["task_id"], unique=True)
    op.create_index("ix_scan_jobs_uploaded_by", "scan_jobs", ["uploaded_by"])
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])
    op.create_index("ix_scan_jobs_created_at", "scan_jobs", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_scan_jobs_created_at", table_name="scan_jobs")
    op.drop_index("ix_scan_jobs_status", table_name="scan_jobs")
    op.drop_index("ix_scan_jobs_uploaded_by", table_name="scan_jobs")
    op.drop_index("ix_scan_jobs_task_id", table_name="scan_jobs")
    op.drop_table("scan_jobs")

    scan_status_enum.drop(op.get_bind(), checkfirst=True)
