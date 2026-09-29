"""Categories of findings, types and environments of assets

Revision ID: 0017
Revises: 0016
Create Date: 2026-09-29

The categorization matrix crosses the kind of software a finding hits with the
kind of host it sits on. Existing rows are filled here, with the same pure
functions the ingestion uses: findings from their CVE title and their fixes'
scanner families, asset types from the operating system. Environments come
from ENVIRONMENT_RULES at the next scan, or by hand.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

from app.services.categorization import asset_type_for, classify_finding

revision: str = "0017"
down_revision: Union[str, None] = "0016"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("asset_type", sa.String(length=16), nullable=True))
    op.add_column("assets", sa.Column("environment", sa.String(length=32), nullable=True))
    op.create_index("ix_assets_asset_type", "assets", ["asset_type"])
    op.create_index("ix_assets_environment", "assets", ["environment"])
    op.add_column(
        "asset_vulnerabilities", sa.Column("category", sa.String(length=32), nullable=True)
    )
    op.create_index(
        "ix_asset_vulnerabilities_category", "asset_vulnerabilities", ["category"]
    )

    bind = op.get_bind()

    families: dict[int, list[str]] = {}
    for finding_id, family in bind.execute(
        sa.text(
            "SELECT fr.finding_id, ra.family FROM finding_remediations fr "
            "JOIN remediation_actions ra ON ra.id = fr.action_id "
            "WHERE ra.family IS NOT NULL"
        )
    ):
        families.setdefault(finding_id, []).append(family)

    updates = [
        {"id": finding_id, "category": classify_finding(title, families.get(finding_id, ()))}
        for finding_id, title in bind.execute(
            sa.text(
                "SELECT av.id, v.title FROM asset_vulnerabilities av "
                "JOIN vulnerabilities v ON v.id = av.vulnerability_id"
            )
        )
    ]
    if updates:
        bind.execute(
            sa.text("UPDATE asset_vulnerabilities SET category = :category WHERE id = :id"),
            updates,
        )

    types = [
        {"id": asset_id, "asset_type": asset_type_for(os_name)}
        for asset_id, os_name in bind.execute(
            sa.text("SELECT id, operating_system FROM assets WHERE operating_system IS NOT NULL")
        )
    ]
    types = [row for row in types if row["asset_type"]]
    if types:
        bind.execute(
            sa.text("UPDATE assets SET asset_type = :asset_type WHERE id = :id"), types
        )


def downgrade() -> None:
    op.drop_index("ix_asset_vulnerabilities_category", table_name="asset_vulnerabilities")
    op.drop_column("asset_vulnerabilities", "category")
    op.drop_index("ix_assets_environment", table_name="assets")
    op.drop_index("ix_assets_asset_type", table_name="assets")
    op.drop_column("assets", "environment")
    op.drop_column("assets", "asset_type")
