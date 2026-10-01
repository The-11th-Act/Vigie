"""KEV: the day ransomware use became known

Revision ID: 0020
Revises: 0019
Create Date: 2026-10-01

CISA flags an entry's ransomware use without a date, sometimes long after the
listing. Anchoring the shorter ransomware window on the listing or the
detection made a finding overdue the day the flag appeared. Existing flags
are dated from their listing, as they were treated until now.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0020"
down_revision: Union[str, None] = "0019"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "vulnerabilities", sa.Column("kev_ransomware_since", sa.Date(), nullable=True)
    )
    op.execute(
        "UPDATE vulnerabilities SET kev_ransomware_since = kev_date_added "
        "WHERE kev_ransomware"
    )


def downgrade() -> None:
    op.drop_column("vulnerabilities", "kev_ransomware_since")
