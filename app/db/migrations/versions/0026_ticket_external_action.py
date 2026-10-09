"""The fix a connector's external ticket describes

Revision ID: 0026
Revises: 0025
Create Date: 2026-10-09

A ticket follows its findings to a later KB; the external ticket keeps the
old one until the connector tells the tool. Links made before this column
describe the ticket's current fix.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0026"
down_revision: Union[str, None] = "0025"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

FOREIGN_KEY = "fk_remediation_tickets_external_action_id"


def upgrade() -> None:
    with op.batch_alter_table("remediation_tickets") as batch:
        batch.add_column(sa.Column("external_action_id", sa.Integer(), nullable=True))
        batch.create_foreign_key(
            FOREIGN_KEY,
            "remediation_actions",
            ["external_action_id"],
            ["id"],
            ondelete="SET NULL",
        )
    op.execute(
        "UPDATE remediation_tickets SET external_action_id = action_id "
        "WHERE external_seal IS NOT NULL"
    )


def downgrade() -> None:
    with op.batch_alter_table("remediation_tickets") as batch:
        batch.drop_constraint(FOREIGN_KEY, type_="foreignkey")
        batch.drop_column("external_action_id")
