"""Initial migration - create all tables

Revision ID: 0001
Revises:
Create Date: 2026-07-15

Note: the enum and timestamp types here mirror ``app.models`` exactly. The
first version of this migration declared plain ``String``/naive ``DateTime``
columns, which diverged from the ORM definitions and produced a schema that
only happened to work because the test suite runs on SQLite.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

criticality_enum = sa.Enum(
    "Low", "Medium", "High", "Critical", name="criticality_enum"
)
severity_enum = sa.Enum("Low", "Medium", "High", "Critical", name="severity_enum")
status_enum = sa.Enum(
    "Open", "False Positive", "Risk Accepted", "Remediated", name="status_enum"
)


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("hashed_password", sa.String(), nullable=False),
        sa.Column("role", sa.String(), server_default="analyst", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    # Unique indexes rather than a constraint plus a separate index: the ORM
    # declares unique=True, index=True, which produces exactly one unique index.
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_username", "users", ["username"], unique=True)

    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("hostname", sa.String(), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=False),
        sa.Column("operating_system", sa.String(), nullable=True),
        sa.Column(
            "business_criticality",
            criticality_enum,
            server_default="Medium",
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_assets_hostname", "assets", ["hostname"])
    op.create_index("ix_assets_ip_address", "assets", ["ip_address"])
    op.create_index("ix_assets_ip_hostname", "assets", ["ip_address", "hostname"])
    op.create_index(
        "ix_assets_business_criticality", "assets", ["business_criticality"]
    )

    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=False),
        sa.Column("severity", severity_enum, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_vulnerabilities_cve_id", "vulnerabilities", ["cve_id"], unique=True
    )
    op.create_index("ix_vulnerabilities_severity", "vulnerabilities", ["severity"])

    op.create_table(
        "asset_vulnerabilities",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "asset_id",
            sa.Integer(),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "vulnerability_id",
            sa.Integer(),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", status_enum, server_default="Open", nullable=False),
        sa.Column("scan_source", sa.String(length=64), nullable=True),
        sa.Column(
            "detected_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("remediation_deadline", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fixed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("asset_id", "vulnerability_id", name="uq_asset_vuln"),
    )
    op.create_index("ix_asset_vulnerabilities_status", "asset_vulnerabilities", ["status"])
    op.create_index(
        "ix_asset_vulnerabilities_asset_id", "asset_vulnerabilities", ["asset_id"]
    )
    op.create_index(
        "ix_asset_vulnerabilities_vulnerability_id",
        "asset_vulnerabilities",
        ["vulnerability_id"],
    )
    op.create_index(
        "ix_asset_vulnerabilities_remediation_deadline",
        "asset_vulnerabilities",
        ["remediation_deadline"],
    )
    op.create_index(
        "ix_asset_vulns_asset_status", "asset_vulnerabilities", ["asset_id", "status"]
    )


def downgrade() -> None:
    op.drop_index("ix_asset_vulns_asset_status", table_name="asset_vulnerabilities")
    op.drop_index(
        "ix_asset_vulnerabilities_remediation_deadline",
        table_name="asset_vulnerabilities",
    )
    op.drop_index(
        "ix_asset_vulnerabilities_vulnerability_id", table_name="asset_vulnerabilities"
    )
    op.drop_index("ix_asset_vulnerabilities_asset_id", table_name="asset_vulnerabilities")
    op.drop_index("ix_asset_vulnerabilities_status", table_name="asset_vulnerabilities")
    op.drop_table("asset_vulnerabilities")

    op.drop_index("ix_vulnerabilities_severity", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_cve_id", table_name="vulnerabilities")
    op.drop_table("vulnerabilities")

    op.drop_index("ix_assets_business_criticality", table_name="assets")
    op.drop_index("ix_assets_ip_hostname", table_name="assets")
    op.drop_index("ix_assets_ip_address", table_name="assets")
    op.drop_index("ix_assets_hostname", table_name="assets")
    op.drop_table("assets")

    op.drop_index("ix_users_username", table_name="users")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")

    bind = op.get_bind()
    status_enum.drop(bind, checkfirst=True)
    severity_enum.drop(bind, checkfirst=True)
    criticality_enum.drop(bind, checkfirst=True)
