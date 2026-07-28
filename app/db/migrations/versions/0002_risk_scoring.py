"""Add risk scoring and finding lifecycle columns

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-28

Adds the columns that make risk-based prioritisation possible:
  - ``risk_score``   : CVSS contextualised by asset criticality and SLA age
  - ``status_note``  : audit justification for risk-accepted / false-positive
  - ``last_seen_at`` : most recent scan that still reported the finding
  - ``updated_at``   : last modification, for triage tracking
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "asset_vulnerabilities",
        sa.Column(
            "risk_score", sa.Float(), server_default="0", nullable=False
        ),
    )
    op.add_column(
        "asset_vulnerabilities", sa.Column("status_note", sa.Text(), nullable=True)
    )
    op.add_column(
        "asset_vulnerabilities",
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.add_column(
        "asset_vulnerabilities",
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    op.create_index(
        "ix_asset_vulnerabilities_risk_score", "asset_vulnerabilities", ["risk_score"]
    )
    op.create_index(
        "ix_asset_vulns_status_risk",
        "asset_vulnerabilities",
        ["status", sa.text("risk_score DESC")],
    )

    # Backfill: existing findings have no score, so they would all sort last.
    # Mirrors calculate_risk_score() without the overdue penalty, which cannot
    # be expressed portably in SQL.
    op.execute(
        """
        UPDATE asset_vulnerabilities
        SET risk_score = ROUND(
            LEAST(10.0, GREATEST(0.0, sub.cvss_score * sub.multiplier))::numeric, 2
        )
        FROM (
            SELECT av.id AS av_id,
                   v.cvss_score AS cvss_score,
                   CASE a.business_criticality::text
                       WHEN 'Critical' THEN 1.5
                       WHEN 'High'     THEN 1.2
                       WHEN 'Medium'   THEN 1.0
                       WHEN 'Low'      THEN 0.7
                       ELSE 1.0
                   END AS multiplier
            FROM asset_vulnerabilities av
            JOIN vulnerabilities v ON v.id = av.vulnerability_id
            JOIN assets a ON a.id = av.asset_id
        ) AS sub
        WHERE asset_vulnerabilities.id = sub.av_id
        """
        if op.get_bind().dialect.name == "postgresql"
        else """
        UPDATE asset_vulnerabilities
        SET risk_score = (
            SELECT ROUND(MIN(10.0, MAX(0.0, v.cvss_score * CASE a.business_criticality
                WHEN 'Critical' THEN 1.5
                WHEN 'High'     THEN 1.2
                WHEN 'Medium'   THEN 1.0
                WHEN 'Low'      THEN 0.7
                ELSE 1.0
            END)), 2)
            FROM vulnerabilities v, assets a
            WHERE v.id = asset_vulnerabilities.vulnerability_id
              AND a.id = asset_vulnerabilities.asset_id
        )
        """
    )


def downgrade() -> None:
    op.drop_index("ix_asset_vulns_status_risk", table_name="asset_vulnerabilities")
    op.drop_index(
        "ix_asset_vulnerabilities_risk_score", table_name="asset_vulnerabilities"
    )
    op.drop_column("asset_vulnerabilities", "updated_at")
    op.drop_column("asset_vulnerabilities", "last_seen_at")
    op.drop_column("asset_vulnerabilities", "status_note")
    op.drop_column("asset_vulnerabilities", "risk_score")
