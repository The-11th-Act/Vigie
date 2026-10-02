"""Asset tags for categorization and dynamic policy rules

Revision ID: 0024
Revises: 0023
Create Date: 2026-10-02

Assets can carry free-form tags (pci-dss, dmz, web...) used to evaluate
dynamic rules (criticality, team, environment, Internet exposure) alongside
hostname regexes and subnet CIDRs.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0024"
down_revision: Union[str, None] = "0023"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("assets") as batch:
        batch.add_column(
            sa.Column("tags", sa.JSON(), server_default="[]", nullable=False)
        )


def downgrade() -> None:
    with op.batch_alter_table("assets") as batch:
        batch.drop_column("tags")
