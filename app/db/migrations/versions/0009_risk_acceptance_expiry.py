"""Risk acceptances expire

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-26

Accepting a risk closed a finding for good. It now carries an end date, after
which the daily job reopens it, and the audit log records the date granted.

Acceptances made before this migration get 90 days from now (the default of
RISK_ACCEPTANCE_DEFAULT_DAYS) rather than expiring all at once on deployment.
"""
from datetime import UTC, datetime, timedelta
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

EXISTING_ACCEPTANCE_DAYS = 90


def upgrade() -> None:
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("accepted_until", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_asset_vulnerabilities_accepted_until",
        "asset_vulnerabilities",
        ["accepted_until"],
    )
    op.add_column(
        "finding_audit_log",
        sa.Column("accepted_until", sa.DateTime(timezone=True), nullable=True),
    )

    op.get_bind().execute(
        sa.text(
            "UPDATE asset_vulnerabilities SET accepted_until = :until "
            "WHERE status = 'Risk Accepted'"
        ),
        {"until": datetime.now(UTC) + timedelta(days=EXISTING_ACCEPTANCE_DAYS)},
    )


def downgrade() -> None:
    op.drop_column("finding_audit_log", "accepted_until")
    op.drop_index(
        "ix_asset_vulnerabilities_accepted_until", table_name="asset_vulnerabilities"
    )
    op.drop_column("asset_vulnerabilities", "accepted_until")
