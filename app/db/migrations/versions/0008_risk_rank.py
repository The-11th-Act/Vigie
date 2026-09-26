"""Unclamped risk rank, to order findings tied at the 10.0 ceiling

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-26

Once KEV, EPSS and exposure multiply the score, several findings reach 10.0 and
the ranking among them was arbitrary: on real data an internal Log4Shell came
before an Internet-facing PAN-OS. risk_rank keeps the score before the clamp.

Existing rows start from their stored score, which is exact below the ceiling;
the daily rescoring (or any rescoring of a finding) sets the true rank.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("risk_rank", sa.Float(), server_default="0", nullable=False),
    )
    op.execute("UPDATE asset_vulnerabilities SET risk_rank = risk_score")


def downgrade() -> None:
    op.drop_column("asset_vulnerabilities", "risk_rank")
