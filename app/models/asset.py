from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, DateTime, Index, String
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import false, func

from app.db.database import Base


class Criticality(str, Enum):
    low = "Low"
    medium = "Medium"
    high = "High"
    critical = "Critical"


class Asset(Base):
    __tablename__ = "assets"

    # A primary key is already indexed; index=True would create a duplicate.
    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    ip_address: Mapped[str] = mapped_column(String, index=True, nullable=False)
    operating_system: Mapped[str | None] = mapped_column(String, nullable=True)
    business_criticality: Mapped[Criticality] = mapped_column(
        SAEnum(
            Criticality,
            name="criticality_enum",
            values_callable=lambda enum_cls: [m.value for m in enum_cls],
        ),
        default=Criticality.medium,
        server_default=Criticality.medium.value,
        nullable=False,
        index=True,
    )
    # Reachable from the Internet. Multiplies risk: the same CVE is far more
    # likely to be exploited on an exposed host than on an internal one.
    internet_facing: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=false(), nullable=False
    )
    # What the host is (server, workstation, network...), inferred from its
    # OS until set by hand; and where it runs (production, staging...).
    asset_type: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    environment: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    # Team in charge of fixing this host: remediation tickets are split by it.
    owner_team: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    vulnerabilities = relationship(
        "AssetVulnerability", back_populates="asset", cascade="all, delete-orphan"
    )


Index("ix_assets_ip_hostname", Asset.ip_address, Asset.hostname)
