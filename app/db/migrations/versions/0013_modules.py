"""Modules: instance switches, role profiles, user preferences

Revision ID: 0013
Revises: 0012
Create Date: 2026-09-29

The sidebar was the same five links for everybody. Modules are now switched on
or off for the instance, granted per role, and arranged by each user. All three
tables start empty: no row means the defaults of app/core/modules.py.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _updated_at() -> sa.Column:
    return sa.Column(
        "updated_at",
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
    )


def upgrade() -> None:
    op.create_table(
        "module_settings",
        sa.Column("module", sa.String(length=32), primary_key=True),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        _updated_at(),
    )
    op.create_table(
        "role_profiles",
        sa.Column("role", sa.String(length=16), primary_key=True),
        sa.Column("modules", sa.JSON(), nullable=False),
        _updated_at(),
    )
    op.create_table(
        "user_preferences",
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("module_order", sa.JSON(), nullable=True),
        sa.Column("hidden_modules", sa.JSON(), nullable=True),
        _updated_at(),
    )


def downgrade() -> None:
    op.drop_table("user_preferences")
    op.drop_table("role_profiles")
    op.drop_table("module_settings")
