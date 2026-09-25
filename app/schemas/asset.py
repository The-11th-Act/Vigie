from datetime import datetime

from pydantic import BaseModel, field_validator

from app.models.asset import Criticality


class AssetBase(BaseModel):
    hostname: str | None = None
    ip_address: str
    operating_system: str | None = None
    business_criticality: Criticality = Criticality.medium
    internet_facing: bool = False


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    hostname: str | None = None
    operating_system: str | None = None
    business_criticality: Criticality | None = None
    internet_facing: bool | None = None

    # Both may be left out of a partial update, but not sent as null: the
    # columns are NOT NULL, and an explicit null used to surface as a 500.
    @field_validator("business_criticality", "internet_facing")
    @classmethod
    def reject_explicit_null(cls, v):
        if v is None:
            raise ValueError("may be omitted, but not set to null")
        return v


class AssetResponse(AssetBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class PaginatedAssetResponse(BaseModel):
    total: int
    items: list[AssetResponse]
