from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class AssetBase(BaseModel):
    hostname: Optional[str] = None
    ip_address: str
    operating_system: Optional[str] = None
    business_criticality: str = "Medium"

class AssetCreate(AssetBase):
    pass

class AssetUpdate(BaseModel):
    hostname: Optional[str] = None
    operating_system: Optional[str] = None
    business_criticality: Optional[str] = None

class AssetResponse(AssetBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class PaginatedAssetResponse(BaseModel):
    total: int
    items: List[AssetResponse]
