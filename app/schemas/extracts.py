from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, computed_field, field_validator

from app.services.extracts import FORMATS


class ApiTokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    # Mandatory lifetime: a forgotten token must not stay valid for ever.
    expires_in_days: int = Field(90, ge=1, le=365)

    @field_validator("name")
    @classmethod
    def strip_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("a name is required")
        return v


class ApiTokenResponse(BaseModel):
    id: int
    name: str
    prefix: str
    scope: str
    created_at: datetime | None = None
    expires_at: datetime
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None

    model_config = {"from_attributes": True}

    @computed_field  # type: ignore[prop-decorator]
    @property
    def active(self) -> bool:
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        return self.revoked_at is None and expires > datetime.now(UTC)


class ApiTokenCreated(ApiTokenResponse):
    # Shown once: only its hash is kept.
    token: str


class SavedExtractCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    dataset: str = Field(max_length=32)
    columns: list[str] | None = Field(None, max_length=100)
    filters: dict[str, Any] = Field(default_factory=dict)
    format: str = "csv"

    @field_validator("format")
    @classmethod
    def known_format(cls, v: str) -> str:
        if v not in FORMATS:
            raise ValueError(f"format must be one of {', '.join(FORMATS)}")
        return v


class SavedExtractResponse(BaseModel):
    id: int
    name: str
    dataset: str
    columns: list[str]
    filters: dict[str, Any]
    format: str
    created_at: datetime | None = None

    model_config = {"from_attributes": True}

    @computed_field  # type: ignore[prop-decorator]
    @property
    def run_path(self) -> str:
        """Stable URL a reporting tool pulls, with a personal token."""
        return f"/api/v1/extracts/saved/{self.id}/run"
