"""Personal API tokens and saved extracts

Revision ID: 0016
Revises: 0015
Create Date: 2026-09-29

Scripts and reporting tools needed a password to reach the API. They now use
personal tokens (read-only, expiring, stored hashed), and saved extracts give
them a stable URL to pull.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: Union[str, None] = "0015"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _user_id() -> sa.Column:
    return sa.Column(
        "user_id",
        sa.Integer(),
        sa.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )


def _created_at() -> sa.Column:
    return sa.Column(
        "created_at",
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
    )


def upgrade() -> None:
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        _user_id(),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("prefix", sa.String(length=16), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        _created_at(),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_api_tokens_user_id", "api_tokens", ["user_id"])
    op.create_index("ix_api_tokens_token_hash", "api_tokens", ["token_hash"], unique=True)

    op.create_table(
        "saved_extracts",
        sa.Column("id", sa.Integer(), primary_key=True),
        _user_id(),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("dataset", sa.String(length=32), nullable=False),
        sa.Column("columns", sa.JSON(), nullable=False),
        sa.Column("filters", sa.JSON(), nullable=False),
        sa.Column("format", sa.String(length=8), nullable=False),
        _created_at(),
    )
    op.create_index("ix_saved_extracts_user_id", "saved_extracts", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_saved_extracts_user_id", table_name="saved_extracts")
    op.drop_table("saved_extracts")
    op.drop_index("ix_api_tokens_token_hash", table_name="api_tokens")
    op.drop_index("ix_api_tokens_user_id", table_name="api_tokens")
    op.drop_table("api_tokens")
