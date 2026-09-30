"""Scopes: the teams whose hosts a user may see

Revision ID: 0019
Revises: 0018
Create Date: 2026-09-30

A user with rows here only sees the hosts of those teams, everywhere; a user
without any sees the whole estate, as every account did before. Existing
accounts are therefore unchanged by this migration.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0019"
down_revision: Union[str, None] = "0018"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "user_teams",
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("owner_team", sa.String(length=128), primary_key=True),
    )


def downgrade() -> None:
    op.drop_table("user_teams")
