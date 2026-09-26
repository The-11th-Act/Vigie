"""Keep the last KEV and EPSS snapshots whole

Revision ID: 0010
Revises: 0009
Create Date: 2026-09-26

The feeds were applied to the CVEs already in the database and nothing else, so
a CVE detected for the first time had no KEV flag or EPSS score until the next
daily refresh. Storing both snapshots lets ingestion enrich it at once.

The tables fill on the next refresh or import; until then new CVEs simply wait,
as they did before.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: Union[str, None] = "0009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "kev_catalog",
        sa.Column("cve_id", sa.String(length=32), primary_key=True),
        sa.Column("date_added", sa.Date(), nullable=True),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("ransomware", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.create_table(
        "epss_scores",
        sa.Column("cve_id", sa.String(length=32), primary_key=True),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("percentile", sa.Float(), nullable=True),
        sa.Column("score_date", sa.Date(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("epss_scores")
    op.drop_table("kev_catalog")
