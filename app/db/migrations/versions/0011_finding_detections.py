"""Detections per source

Revision ID: 0011
Revises: 0010
Create Date: 2026-09-26

A finding remembered only the last scanner to report it, and automatic closure
listened to that one alone. Each source now keeps its own sightings and misses;
a finding closes once every source that saw it has stopped seeing it.

Existing findings get one detection from what they knew: their last source,
first detection date, last sighting and miss count.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: Union[str, None] = "0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "finding_detections",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "finding_id",
            sa.Integer(),
            sa.ForeignKey("asset_vulnerabilities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("missed_scans", sa.Integer(), server_default="0", nullable=False),
        sa.UniqueConstraint("finding_id", "source", name="uq_finding_detection_source"),
    )
    op.create_index(
        "ix_finding_detections_finding_id", "finding_detections", ["finding_id"]
    )

    op.execute(
        "INSERT INTO finding_detections "
        "(finding_id, source, first_seen_at, last_seen_at, missed_scans) "
        "SELECT id, scan_source, "
        "COALESCE(detected_at, CURRENT_TIMESTAMP), "
        "COALESCE(last_seen_at, CURRENT_TIMESTAMP), "
        "missed_scans "
        "FROM asset_vulnerabilities WHERE scan_source IS NOT NULL"
    )


def downgrade() -> None:
    op.drop_index("ix_finding_detections_finding_id", table_name="finding_detections")
    op.drop_table("finding_detections")
