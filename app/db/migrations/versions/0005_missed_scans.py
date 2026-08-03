"""Track consecutive scan misses on findings

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-03

A finding that stops being reported by its source used to stay open forever:
patching a host cleaned the machine but never the backlog, so the queue drifted
away from reality. Counting misses lets a finding be closed automatically once
several consecutive scans no longer see it — several, not one, so a partial or
failed scan does not wrongly close everything it missed.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("missed_scans", sa.Integer(), server_default="0", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("asset_vulnerabilities", "missed_scans")
