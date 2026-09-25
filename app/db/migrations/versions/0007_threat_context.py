"""Threat context: CISA KEV, FIRST EPSS and asset exposure

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-25

The risk score only knew how bad a vulnerability is in theory (CVSS) and how
much the host matters (criticality). Whether it is actually being exploited
(KEV), how likely it is to be (EPSS), and whether the host is reachable from the
Internet are what separate the few findings to fix this week from the rest.

Booleans get a ``false()`` server default so existing rows are valid on both
PostgreSQL (``DEFAULT false``) and SQLite (``DEFAULT 0``), which refuses to add a
NOT NULL column without one.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "vulnerabilities",
        sa.Column("in_kev", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column("vulnerabilities", sa.Column("kev_date_added", sa.Date(), nullable=True))
    op.add_column("vulnerabilities", sa.Column("kev_due_date", sa.Date(), nullable=True))
    op.add_column(
        "vulnerabilities",
        sa.Column(
            "kev_ransomware", sa.Boolean(), server_default=sa.false(), nullable=False
        ),
    )
    op.add_column("vulnerabilities", sa.Column("epss_score", sa.Float(), nullable=True))
    op.add_column(
        "vulnerabilities", sa.Column("epss_percentile", sa.Float(), nullable=True)
    )
    op.add_column("vulnerabilities", sa.Column("epss_date", sa.Date(), nullable=True))
    op.add_column(
        "vulnerabilities",
        sa.Column("threat_intel_updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_vulnerabilities_in_kev",
        "vulnerabilities",
        ["id"],
        postgresql_where=sa.text("in_kev IS true"),
        sqlite_where=sa.text("in_kev IS 1"),
    )

    op.add_column(
        "assets",
        sa.Column(
            "internet_facing", sa.Boolean(), server_default=sa.false(), nullable=False
        ),
    )

    op.create_table(
        "threat_feed_status",
        sa.Column("feed", sa.String(length=16), primary_key=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("source", sa.String(length=16), nullable=True),
        sa.Column("source_version", sa.String(length=64), nullable=True),
        sa.Column("source_date", sa.Date(), nullable=True),
        sa.Column("records", sa.Integer(), server_default="0", nullable=False),
        sa.Column("changed", sa.Integer(), server_default="0", nullable=False),
    )


def downgrade() -> None:
    op.drop_table("threat_feed_status")
    op.drop_column("assets", "internet_facing")
    op.drop_index("ix_vulnerabilities_in_kev", table_name="vulnerabilities")
    for column in (
        "threat_intel_updated_at",
        "epss_date",
        "epss_percentile",
        "epss_score",
        "kev_ransomware",
        "kev_due_date",
        "kev_date_added",
        "in_kev",
    ):
        op.drop_column("vulnerabilities", column)
