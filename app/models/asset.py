from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy.orm import relationship
from app.db.database import Base
import datetime

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, index=True, nullable=True)
    ip_address = Column(String, index=True, nullable=False)
    operating_system = Column(String, nullable=True)
    business_criticality = Column(String, default="Medium")  # Low, Medium, High, Critical
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    vulnerabilities = relationship("AssetVulnerability", back_populates="asset", cascade="all, delete-orphan")
