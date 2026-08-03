from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel

from app.models.asset import Criticality


class AssetBase(BaseModel):
    hostname: Optional[str] = None
    ip_address: str
    operating_system: Optional[str] = None
    business_criticality: Criticality = Criticality.medium


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    hostname: Optional[str] = None
    operating_system: Optional[str] = None
    business_criticality: Optional[Criticality] = None


class AssetResponse(AssetBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class PaginatedAssetResponse(BaseModel):
    total: int
    items: List[AssetResponse]
