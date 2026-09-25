from datetime import date, datetime

from pydantic import BaseModel


class FeedStatusResponse(BaseModel):
    feed: str
    last_attempt_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None
    source: str | None = None
    source_version: str | None = None
    source_date: date | None = None
    records: int = 0
    stale: bool = True


class ThreatIntelStatusResponse(BaseModel):
    # Whether the daily network refresh runs; imported values count either way.
    enabled: bool
    stale_after_hours: int
    feeds: list[FeedStatusResponse]


class FeedResultResponse(BaseModel):
    feed: str
    status: str
    records: int = 0
    changed: int = 0
    rescored: int = 0
    error: str | None = None
