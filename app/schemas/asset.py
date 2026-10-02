from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.models.asset import Criticality
from app.services.categorization import ASSET_TYPES


def _asset_type(v: str | None) -> str | None:
    v = (v or "").strip() or None
    if v is not None and v not in ASSET_TYPES:
        raise ValueError(f"must be one of {', '.join(ASSET_TYPES)}")
    return v


MAX_TAGS = 50
MAX_TAG_LENGTH = 64


def _clean_tags(v: Any) -> list[str]:
    """Tags trimmed, cut to MAX_TAG_LENGTH, and kept once whatever their case:
    the rules match "PCI" and "pci" alike, so both would be the same tag."""
    if v is None:
        return []
    if isinstance(v, str):
        v = [t.strip() for t in v.split(",") if t.strip()]
    if not isinstance(v, list):
        raise ValueError("tags must be a list of strings")
    cleaned: list[str] = []
    seen: set[str] = set()
    for t in v:
        tag_str = str(t).strip()[:MAX_TAG_LENGTH]
        if tag_str and tag_str.lower() not in seen:
            seen.add(tag_str.lower())
            cleaned.append(tag_str)
    if len(cleaned) > MAX_TAGS:
        raise ValueError(f"at most {MAX_TAGS} tags")
    return cleaned


class AssetBase(BaseModel):
    hostname: str | None = None
    ip_address: str
    operating_system: str | None = None
    business_criticality: Criticality = Criticality.medium
    internet_facing: bool = False
    owner_team: str | None = Field(None, max_length=128)
    asset_type: str | None = None
    environment: str | None = Field(None, max_length=32)
    tags: list[str] = Field(default_factory=list)

    @field_validator("owner_team", "environment")
    @classmethod
    def blank_team_is_none(cls, v: str | None) -> str | None:
        return (v or "").strip() or None

    @field_validator("asset_type")
    @classmethod
    def known_type(cls, v: str | None) -> str | None:
        return _asset_type(v)

    @field_validator("tags", mode="before")
    @classmethod
    def normalize_tags(cls, v: Any) -> list[str]:
        return _clean_tags(v)


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
    tags: list[str] | None = None

    @field_validator("owner_team", "environment")
    @classmethod
    def blank_team_is_none(cls, v: str | None) -> str | None:
        return (v or "").strip() or None

    @field_validator("asset_type")
    @classmethod
    def known_type(cls, v: str | None) -> str | None:
        return _asset_type(v)

    @field_validator("tags", mode="before")
    @classmethod
    def normalize_update_tags(cls, v: Any) -> list[str] | None:
        if v is None:
            return None
        return _clean_tags(v)

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
