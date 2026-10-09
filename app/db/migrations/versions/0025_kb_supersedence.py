"""KB supersedence from the MSRC documents

Revision ID: 0025
Revises: 0024
Create Date: 2026-10-09

Which KB replaces which, per monthly MSRC document, and on each remediation
link the KB the scanner asked for when a later one replaced it.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0025"
down_revision: Union[str, None] = "0024"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "msrc_documents",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column("initial_release", sa.DateTime(timezone=True), nullable=True),
        sa.Column("current_release", sa.DateTime(timezone=True), nullable=True),
        sa.Column("supersedences", sa.Integer(), server_default="0", nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "kb_supersedences",
        sa.Column(
            "document_id",
            sa.String(length=32),
            sa.ForeignKey("msrc_documents.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("kb", sa.String(length=16), primary_key=True),
        sa.Column("superseded_kb", sa.String(length=16), primary_key=True),
    )
    op.create_index(
        "ix_kb_supersedences_superseded_kb", "kb_supersedences", ["superseded_kb"]
    )
    with op.batch_alter_table("finding_remediations") as batch:
        batch.add_column(
            sa.Column("reported_reference", sa.String(length=128), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("finding_remediations") as batch:
        batch.drop_column("reported_reference")
    op.drop_index("ix_kb_supersedences_superseded_kb", table_name="kb_supersedences")
    op.drop_table("kb_supersedences")
    op.drop_table("msrc_documents")
