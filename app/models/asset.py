from sqlalchemy import Column, Integer, String, DateTime, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, index=True, nullable=True)
    ip_address = Column(String, index=True, nullable=False)
    operating_system = Column(String, nullable=True)
    business_criticality = Column(String, default="Medium")  # Low, Medium, High, Critical
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    vulnerabilities = relationship("AssetVulnerability", back_populates="asset", cascade="all, delete-orphan")


Index("ix_assets_ip_hostname", Asset.ip_address, Asset.hostname)