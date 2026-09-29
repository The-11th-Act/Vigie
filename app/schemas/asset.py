from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.models.asset import Criticality
from app.services.categorization import ASSET_TYPES


def _asset_type(v: str | None) -> str | None:
    v = (v or "").strip() or None
    if v is not None and v not in ASSET_TYPES:
        raise ValueError(f"must be one of {', '.join(ASSET_TYPES)}")
    return v


class AssetBase(BaseModel):
    hostname: str | None = None
    ip_address: str
    operating_system: str | None = None
    business_criticality: Criticality = Criticality.medium
    internet_facing: bool = False
    owner_team: str | None = Field(None, max_length=128)
    asset_type: str | None = None
    environment: str | None = Field(None, max_length=32)

    @field_validator("owner_team", "environment")
    @classmethod
    def blank_team_is_none(cls, v: str | None) -> str | None:
        return (v or "").strip() or None

    @field_validator("asset_type")
    @classmethod
    def known_type(cls, v: str | None) -> str | None:
        return _asset_type(v)


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    hostname: str | None = None
    operating_system: str | None = None
    business_criticality: Criticality | None = None
    internet_facing: bool | None = None
    # Null clears it: the host then waits for a team.
    owner_team: str | None = Field(None, max_length=128)
    asset_type: str | None = None
    environment: str | None = Field(None, max_length=32)

    @field_validator("owner_team", "environment")
    @classmethod
    def blank_team_is_none(cls, v: str | None) -> str | None:
        return (v or "").strip() or None

    @field_validator("asset_type")
    @classmethod
    def known_type(cls, v: str | None) -> str | None:
        return _asset_type(v)

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
