"""Team in charge of each asset

Revision ID: 0014
Revises: 0013
Create Date: 2026-09-29

Remediation tickets go to the team that fixes a host. Nothing is backfilled
here: OWNER_TEAM_RULES reaches existing hosts at their next scan, and a team can
be set by hand at any time.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("owner_team", sa.String(length=128), nullable=True))
    op.create_index("ix_assets_owner_team", "assets", ["owner_team"])


def downgrade() -> None:
    op.drop_index("ix_assets_owner_team", table_name="assets")
    op.drop_column("assets", "owner_team")
