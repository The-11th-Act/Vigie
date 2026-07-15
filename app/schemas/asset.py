from pydantic import BaseModel, field_validator
from typing import Optional, List
from datetime import datetime

VALID_CRITICALITY = {"Low", "Medium", "High", "Critical"}


class AssetBase(BaseModel):
    hostname: Optional[str] = None
    ip_address: str
    operating_system: Optional[str] = None
    business_criticality: str = "Medium"

    @field_validator("business_criticality")
    @classmethod
    def validate_criticality(cls, v: str) -> str:
        v = v.capitalize()
        if v not in VALID_CRITICALITY:
            raise ValueError(f"business_criticality must be one of {VALID_CRITICALITY}")
        return v


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    hostname: Optional[str] = None
    operating_system: Optional[str] = None
    business_criticality: Optional[str] = None

    @field_validator("business_criticality")
    @classmethod
    def validate_criticality(cls, v: str) -> str:
        if v is None:
            return v
        v = v.capitalize()
        if v not in VALID_CRITICALITY:
            raise ValueError(f"business_criticality must be one of {VALID_CRITICALITY}")
        return v


class AssetResponse(AssetBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class PaginatedAssetResponse(BaseModel):
    total: int
    items: List[AssetResponse]