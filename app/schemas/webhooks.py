from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, Field

from app.services.webhooks import EVENTS, TargetRefused, check_url


def _events(value: list[str]) -> list[str]:
    unknown = sorted(set(value) - set(EVENTS))
    if unknown:
        raise ValueError(f"unknown event(s): {', '.join(unknown)}")
    # Stored in the order of EVENTS, without duplicates.
    return [event for event in EVENTS if event in value]


def _url(value: str) -> str:
    value = value.strip()
    try:
        return check_url(value)
    except TargetRefused as exc:
        raise ValueError(str(exc)) from None


def _name(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("a name is required")
    return value


Name = Annotated[str, Field(min_length=1, max_length=64), AfterValidator(_name)]
Url = Annotated[str, Field(min_length=1, max_length=1024), AfterValidator(_url)]
Events = Annotated[list[str], Field(min_length=1), AfterValidator(_events)]


class WebhookCreate(BaseModel):
    name: Name
    url: Url
    events: Events


class WebhookUpdate(BaseModel):
    name: Name | None = None
    url: Url | None = None
    events: Events | None = None
    enabled: bool | None = None


class WebhookResponse(BaseModel):
    id: int
    name: str
    url: str
    events: list[str]
    enabled: bool
    # False for a webhook another instance registered (a staging restored
    # from production): it sends nothing here until its secret is rotated.
    usable: bool
    created_at: datetime | None = None
    created_by_username: str | None = None
    last_success_at: datetime | None = None
    last_failure_at: datetime | None = None
    last_error: str | None = None
    pending: int = 0
    failed: int = 0


class WebhookWithSecret(WebhookResponse):
    # Shown once, at creation and at rotation.
    secret: str


class WebhookEvent(BaseModel):
    name: str
    description: str


class WebhookDeliveryResponse(BaseModel):
    id: int
    event_id: str
    event: str
    status: str
    attempts: int
    next_attempt_at: datetime | None = None
    response_status: int | None = None
    last_error: str | None = None
    created_at: datetime | None = None
    delivered_at: datetime | None = None

    model_config = {"from_attributes": True}
