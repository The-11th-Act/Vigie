"""Remediation actions (KB, vendor fix) per finding

Revision ID: 0012
Revises: 0011
Create Date: 2026-09-29

Parsers used to drop everything a scanner says about how to fix a finding: the
KB to deploy, the version to upgrade to, the vendor's solution. Remediation
teams work from exactly that, so it is now kept, once per action and linked to
each finding (asset × CVE) it fixes.

Nothing is backfilled: scan files are deleted after ingestion, so existing
findings gain their remediation on their next scan.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "remediation_actions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("reference", sa.String(length=128), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=True),
        sa.Column("solution", sa.Text(), nullable=True),
        sa.Column("url", sa.String(length=1024), nullable=True),
        sa.Column("family", sa.String(length=128), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_remediation_actions_reference",
        "remediation_actions",
        ["reference"],
        unique=True,
    )
    op.create_index("ix_remediation_actions_kind", "remediation_actions", ["kind"])

    op.create_table(
        "finding_remediations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "finding_id",
            sa.Integer(),
            sa.ForeignKey("asset_vulnerabilities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "action_id",
            sa.Integer(),
            sa.ForeignKey("remediation_actions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("installed_version", sa.String(length=256), nullable=True),
        sa.Column("fixed_version", sa.String(length=256), nullable=True),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "finding_id", "action_id", "source", name="uq_finding_remediation"
        ),
    )
    op.create_index(
        "ix_finding_remediations_finding_id", "finding_remediations", ["finding_id"]
    )
    op.create_index(
        "ix_finding_remediations_action_id", "finding_remediations", ["action_id"]
    )


def downgrade() -> None:
    op.drop_index(
        "ix_finding_remediations_action_id", table_name="finding_remediations"
    )
    op.drop_index(
        "ix_finding_remediations_finding_id", table_name="finding_remediations"
    )
    op.drop_table("finding_remediations")
    op.drop_index("ix_remediation_actions_kind", table_name="remediation_actions")
    op.drop_index("ix_remediation_actions_reference", table_name="remediation_actions")
    op.drop_table("remediation_actions")
