"""Outgoing webhooks and their delivery outbox

Revision ID: 0021
Revises: 0020
Create Date: 2026-10-01

Other tools (chat, SOAR, a ticketing bridge) learn about scans, tickets and
KEV listings from signed HTTP calls. Deliveries are written in the transaction
of the change they report and sent by the worker, with retries.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: Union[str, None] = "0020"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _created_at() -> sa.Column:
    return sa.Column(
        "created_at",
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
    )


def upgrade() -> None:
    op.create_table(
        "webhooks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("url", sa.String(length=1024), nullable=False),
        sa.Column("events", sa.JSON(), nullable=False),
        sa.Column("secret", sa.String(length=128), nullable=False),
        sa.Column("seal", sa.String(length=128), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column(
            "created_by",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        _created_at(),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_failure_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=512), nullable=True),
    )

    op.create_table(
        "webhook_deliveries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "webhook_id",
            sa.Integer(),
            sa.ForeignKey("webhooks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_id", sa.String(length=32), nullable=False),
        sa.Column("event", sa.String(length=64), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column(
            "status", sa.String(length=16), server_default="pending", nullable=False
        ),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("response_status", sa.Integer(), nullable=True),
        sa.Column("last_error", sa.String(length=512), nullable=True),
        _created_at(),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
    )
    for column in ("webhook_id", "event_id", "status", "next_attempt_at"):
        op.create_index(
            f"ix_webhook_deliveries_{column}", "webhook_deliveries", [column]
        )


def downgrade() -> None:
    for column in ("next_attempt_at", "status", "event_id", "webhook_id"):
        op.drop_index(f"ix_webhook_deliveries_{column}", table_name="webhook_deliveries")
    op.drop_table("webhook_deliveries")
    op.drop_table("webhooks")
