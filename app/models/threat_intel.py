from sqlalchemy import Date, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base

FEED_KEV = "kev"
FEED_EPSS = "epss"
FEEDS = (FEED_KEV, FEED_EPSS)


class ThreatFeedStatus(Base):
    """Freshness and provenance of one threat-intelligence feed.

    One row per feed. It is what the metrics read (the worker that refreshes the
    feeds exposes no ``/metrics`` of its own), and what the refresh compares a new
    snapshot against: an older snapshot, or a KEV catalogue that shrank sharply,
    is refused rather than allowed to erase good data.
    """

    __tablename__ = "threat_feed_status"

    # A plain string rather than an ENUM: there is no database type to create,
    # alter or drop when a feed is added.
    feed: Mapped[str] = mapped_column(String(16), primary_key=True)

    last_attempt_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_success_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Where the last applied snapshot came from: "network" or "import".
    source: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # KEV catalogVersion, or EPSS model_version.
    source_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # KEV dateReleased, or EPSS score_date.
    source_date: Mapped[Date | None] = mapped_column(Date, nullable=True)

    # Entries in the last applied snapshot, and how many rows it changed.
    records: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    changed: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
