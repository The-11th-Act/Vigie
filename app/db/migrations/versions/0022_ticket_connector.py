"""Ticketing connector: sealed external links and the connector's last run

Revision ID: 0022
Revises: 0021
Create Date: 2026-10-02

Remediation tickets can be mirrored in an external ticketing tool (GLPI
first). A link written by the connector is sealed to the instance and to the
tool's server, and remembers the external ticket's state to tell its changes
from Vigie's.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0022"
down_revision: Union[str, None] = "0021"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _new_ticket_columns() -> tuple[sa.Column, ...]:
    return (
        sa.Column("external_seal", sa.String(length=128), nullable=True),
        sa.Column("external_state", sa.String(length=16), nullable=True),
        sa.Column("external_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("external_error", sa.String(length=512), nullable=True),
    )


def upgrade() -> None:
    with op.batch_alter_table("remediation_tickets") as batch:
        for column in _new_ticket_columns():
            batch.add_column(column)

    op.create_table(
        "ticket_connector_status",
        sa.Column("name", sa.String(length=32), primary_key=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=512), nullable=True),
        sa.Column("last_result", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("ticket_connector_status")
    with op.batch_alter_table("remediation_tickets") as batch:
        for column in reversed(_new_ticket_columns()):
            batch.drop_column(column.name)
