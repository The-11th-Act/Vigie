from datetime import datetime
from enum import Enum

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func, true

from app.db.database import Base


class DeliveryStatus(str, Enum):
    pending = "pending"  # waiting for its first attempt or for a retry
    delivered = "delivered"  # the receiver answered 2xx
    failed = "failed"  # every attempt failed, or the webhook can no longer send


class Webhook(Base):
    """An HTTP endpoint told about events, signed with a secret of its own.

    ``seal`` binds the row to the instance that registered it: an HMAC, under
    the instance's signing key, of the URL and the secret. A staging restored
    from production has another key (docs/PREPRODUCTION.md), so production's
    webhooks cannot send from it; and a URL changed in the database, rather
    than through the API, breaks the seal too. See app/services/webhooks.py.
    """

    __tablename__ = "webhooks"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    url: Mapped[str] = mapped_column(String(1024), nullable=False)
    # Event names (app/services/webhooks.py, EVENTS).
    events: Mapped[list] = mapped_column(JSON, nullable=False)
    # Kept readable: every delivery is signed with it. Shown once, at creation
    # and at rotation.
    secret: Mapped[str] = mapped_column(String(128), nullable=False)
    seal: Mapped[str] = mapped_column(String(128), nullable=False)
    enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, server_default=true(), nullable=False
    )
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_success_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_failure_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[str | None] = mapped_column(String(512), nullable=True)

    creator = relationship("User")


class WebhookDelivery(Base):
    """One event for one webhook: an outbox row, written in the transaction of
    the change it reports, then sent by the worker.

    The body is serialised once, when the event happens, so every retry sends
    the same bytes and the receiver can deduplicate on ``event_id``.
    """

    __tablename__ = "webhook_deliveries"

    id: Mapped[int] = mapped_column(primary_key=True)
    webhook_id: Mapped[int] = mapped_column(
        ForeignKey("webhooks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    event: Mapped[str] = mapped_column(String(64), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16),
        default=DeliveryStatus.pending.value,
        server_default=DeliveryStatus.pending.value,
        nullable=False,
        index=True,
    )
    attempts: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    delivered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    webhook = relationship("Webhook")
