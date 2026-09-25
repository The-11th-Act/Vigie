"""Record how many findings a scan closed automatically

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-25

The worker already counted the findings an ingestion closed, but the scan
history had nowhere to keep that number: it was returned by the task, then
lost with Celery's expiring result. It is the one counter an operator needs to
check that a scan did not wrongly empty the backlog.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scan_jobs",
        sa.Column("auto_remediated", sa.Integer(), server_default="0", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("scan_jobs", "auto_remediated")
