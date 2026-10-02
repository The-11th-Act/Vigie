"""Account lifecycle: disabled accounts and sessions ended by a password change

Revision ID: 0023
Revises: 0022
Create Date: 2026-10-02

Accounts are created by an administrator (self-registration is closed), and
can be disabled. Changing a password, or disabling the account, ends every
session opened before.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0023"
down_revision: Union[str, None] = "0022"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(
            sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False)
        )
        batch.add_column(
            sa.Column("sessions_valid_after", sa.DateTime(timezone=True), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_column("sessions_valid_after")
        batch.drop_column("is_active")
