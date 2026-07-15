"""Initial migration - create all tables

Revision ID: 0001
Revises:
Create Date: 2026-07-15
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("hashed_password", sa.String(), nullable=False),
        sa.Column("role", sa.String(), server_default="analyst", nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.UniqueConstraint("email", name="uq_users_email"),
        sa.UniqueConstraint("username", name="uq_users_username"),
    )
    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_users_username", "users", ["username"])

    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("hostname", sa.String(), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=False),
        sa.Column("operating_system", sa.String(), nullable=True),
        sa.Column("business_criticality", sa.String(), server_default="Medium"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index("ix_assets_hostname", "assets", ["hostname"])
    op.create_index("ix_assets_ip_address", "assets", ["ip_address"])
    op.create_index("ix_assets_ip_hostname", "assets", ["ip_address", "hostname"])

    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("cve_id", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.UniqueConstraint("cve_id", name="uq_vulnerabilities_cve_id"),
    )
    op.create_index("ix_vulnerabilities_cve_id", "vulnerabilities", ["cve_id"])

    op.create_table(
        "asset_vulnerabilities",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("asset_id", sa.Integer(),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("vulnerability_id", sa.Integer(),
                   sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(), server_default="Open"),
        sa.Column("scan_source", sa.String(), nullable=True),
        sa.Column("detected_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("remediation_deadline", sa.DateTime(), nullable=True),
        sa.Column("fixed_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_asset_vulnerabilities_status", "asset_vulnerabilities", ["status"])
    op.create_index("ix_asset_vulns_asset_status", "asset_vulnerabilities", ["asset_id", "status"])


def downgrade() -> None:
    op.drop_index("ix_asset_vulns_asset_status", table_name="asset_vulnerabilities")
    op.drop_index("ix_asset_vulnerabilities_status", table_name="asset_vulnerabilities")
    op.drop_table("asset_vulnerabilities")
    op.drop_index("ix_vulnerabilities_cve_id", table_name="vulnerabilities")
    op.drop_table("vulnerabilities")
    op.drop_index("ix_assets_ip_hostname", table_name="assets")
    op.drop_index("ix_assets_ip_address", table_name="assets")
    op.drop_index("ix_assets_hostname", table_name="assets")
    op.drop_table("assets")
    op.drop_index("ix_users_username", table_name="users")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")