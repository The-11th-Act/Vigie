"""Remediation tickets, their findings and their history

Revision ID: 0015
Revises: 0014
Create Date: 2026-09-29

A ticket is one fix for one team. Its status follows the scans: resolved once
every finding it holds is closed, reopened if one comes back.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: Union[str, None] = "0014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _now(name: str, nullable: bool = False) -> sa.Column:
    return sa.Column(
        name, sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=nullable
    )


def upgrade() -> None:
    op.create_table(
        "remediation_tickets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "action_id",
            sa.Integer(),
            sa.ForeignKey("remediation_actions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("owner_team", sa.String(length=128), nullable=True),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="open", nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("external_system", sa.String(length=32), nullable=True),
        sa.Column("external_ref", sa.String(length=128), nullable=True),
        sa.Column("external_url", sa.String(length=1024), nullable=True),
        sa.Column(
            "created_by",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        _now("created_at"),
        _now("updated_at"),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )
    for column in ("action_id", "owner_team", "status"):
        op.create_index(
            f"ix_remediation_tickets_{column}", "remediation_tickets", [column]
        )

    op.create_table(
        "ticket_findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "ticket_id",
            sa.Integer(),
            sa.ForeignKey("remediation_tickets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "finding_id",
            sa.Integer(),
            sa.ForeignKey("asset_vulnerabilities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        _now("added_at"),
        sa.UniqueConstraint("ticket_id", "finding_id", name="uq_ticket_finding"),
    )
    op.create_index("ix_ticket_findings_ticket_id", "ticket_findings", ["ticket_id"])
    op.create_index("ix_ticket_findings_finding_id", "ticket_findings", ["finding_id"])

    op.create_table(
        "ticket_audit_log",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "ticket_id",
            sa.Integer(),
            sa.ForeignKey("remediation_tickets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(length=64), nullable=True),
        sa.Column("old_status", sa.String(length=16), nullable=True),
        sa.Column("new_status", sa.String(length=16), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        _now("created_at"),
    )
    op.create_index("ix_ticket_audit_log_ticket_id", "ticket_audit_log", ["ticket_id"])
    op.create_index("ix_ticket_audit_log_created_at", "ticket_audit_log", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_ticket_audit_log_created_at", table_name="ticket_audit_log")
    op.drop_index("ix_ticket_audit_log_ticket_id", table_name="ticket_audit_log")
    op.drop_table("ticket_audit_log")
    op.drop_index("ix_ticket_findings_finding_id", table_name="ticket_findings")
    op.drop_index("ix_ticket_findings_ticket_id", table_name="ticket_findings")
    op.drop_table("ticket_findings")
    for column in ("status", "owner_team", "action_id"):
        op.drop_index(f"ix_remediation_tickets_{column}", table_name="remediation_tickets")
    op.drop_table("remediation_tickets")
