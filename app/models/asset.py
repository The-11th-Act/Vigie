from sqlalchemy import String, DateTime, Index, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func
from app.db.database import Base
from enum import Enum


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
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    vulnerabilities = relationship("AssetVulnerability", back_populates="asset", cascade="all, delete-orphan")


Index("ix_assets_ip_hostname", Asset.ip_address, Asset.hostname)