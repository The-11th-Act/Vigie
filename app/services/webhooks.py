"""Outgoing webhooks: events written to an outbox, sent signed by the worker.

An event is queued with ``emit`` inside the transaction of the change it
reports: a change rolled back sends nothing, and a change committed is sent
even if the receiver, the network or the worker is down at that moment. The
worker (``deliver_due``) posts each delivery, retries with a growing delay, and
gives up after ``RETRY_DELAYS``.

Each request carries:

- ``X-Vigie-Event``: the event name;
- ``X-Vigie-Delivery``: the event id, the same across retries, to deduplicate;
- ``X-Vigie-Timestamp``: Unix seconds at sending, to refuse replays;
- ``X-Vigie-Signature``: ``sha256=`` + HMAC-SHA256 of ``"<timestamp>.<body>"``
  under the webhook's secret.

A webhook is sealed to the instance that registered it (``seal_state``): a
staging restored from production does not call production's receivers.
"""

import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import socket
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from urllib.parse import urlsplit
from uuid import uuid4

import requests
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.webhook import DeliveryStatus, Webhook, WebhookDelivery

logger = logging.getLogger(__name__)

# What a webhook can subscribe to. Names are part of the receivers' contract:
# add, never rename.
EVENTS: dict[str, str] = {
    "scan.completed": "A scan file or a CrowdStrike sync was ingested",
    "scan.failed": "A scan file or a CrowdStrike sync failed for good",
    "ticket.created": "A remediation ticket was opened",
    "ticket.status_changed": "A ticket changed status, by a person or by the scans",
    "threat.kev_listed": (
        "CVEs with open findings entered CISA KEV, or became known for ransomware use"
    ),
}
# Sent on demand from the administration screen, whatever the subscription.
PING_EVENT = "ping"

# Delay before each retry. Seven attempts over about 21 hours: a receiver down
# for a night still gets the event, one gone for good stops being called.
RETRY_DELAYS = (
    timedelta(minutes=1),
    timedelta(minutes=5),
    timedelta(minutes=30),
    timedelta(hours=2),
    timedelta(hours=6),
    timedelta(hours=12),
)
DELIVERIES_PER_RUN = 100
MAX_ERROR_LENGTH = 512
CONNECT_TIMEOUT_SECONDS = 5
USER_AGENT = "Vigie-Webhooks/1"
SECRET_PREFIX = "whsec_"  # noqa: S105 — a label, not a secret

SealState = Literal["current", "previous", "foreign"]


class TargetRefused(ValueError):
    """The URL points somewhere a webhook must not reach."""


# --- Registration -----------------------------------------------------------


def new_secret() -> str:
    return SECRET_PREFIX + secrets.token_urlsafe(32)


def check_url(url: str) -> str:
    """Refuse, at registration, a URL that could never be delivered to.

    The address is checked again at each delivery: DNS can change in between.
    """
    parts = urlsplit(url)
    allowed = ("https", "http") if settings.WEBHOOK_ALLOW_HTTP else ("https",)
    if parts.scheme not in allowed:
        raise TargetRefused(
            "The URL must use https"
            + ("" if settings.WEBHOOK_ALLOW_HTTP else " (WEBHOOK_ALLOW_HTTP is off)")
        )
    if not parts.hostname:
        raise TargetRefused("The URL has no host")
    # Credentials in the URL would be shown to every admin in the list.
    if parts.username or parts.password:
        raise TargetRefused("Put no credentials in the URL; check the signature instead")
    try:
        literal = ipaddress.ip_address(parts.hostname)
    except ValueError:
        return url
    _check_address(literal)
    return url


def _check_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    # Never: the instance itself, cloud metadata (169.254.169.254), broadcast.
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        raise TargetRefused(f"Address {address} is not a valid webhook target")
    if not address.is_global and not settings.WEBHOOK_ALLOW_PRIVATE_TARGETS:
        raise TargetRefused(
            f"Address {address} is private (WEBHOOK_ALLOW_PRIVATE_TARGETS is off)"
        )


def _check_resolved(url: str) -> None:
    """Every address the host resolves to must be an allowed target."""
    parts = urlsplit(check_url(url))
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ConnectionError(f"Cannot resolve {host}: {exc.strerror}") from None
    for info in infos:
        # IPv6 socket addresses may carry a zone ("fe80::1%eth0").
        _check_address(ipaddress.ip_address(str(info[4][0]).split("%")[0]))


# --- Seal -------------------------------------------------------------------


def _seal_with(key: str, webhook: Webhook) -> str:
    message = f"vigie-webhook\x00{webhook.url}\x00{webhook.secret}".encode()
    return hmac.new(key.encode(), message, hashlib.sha256).hexdigest()


def seal(webhook: Webhook) -> None:
    """Bind the webhook to this instance; after any change of URL or secret."""
    webhook.seal = _seal_with(settings.SECRET_KEY, webhook)


def seal_state(webhook: Webhook) -> SealState:
    """Who sealed this webhook: this instance, this instance before a key
    rotation, or another instance (or someone writing to the database)."""
    if hmac.compare_digest(webhook.seal, _seal_with(settings.SECRET_KEY, webhook)):
        return "current"
    for key in settings.PREVIOUS_SECRET_KEYS.values():
        if hmac.compare_digest(webhook.seal, _seal_with(key, webhook)):
            return "previous"
    return "foreign"


def reseal_webhooks(db: Session) -> int:
    """Move every webhook sealed with a retired key to the current one.

    Run by the daily pass, so a key dropped from PREVIOUS_SECRET_KEYS after
    the rotation period no longer strands its webhooks. The caller commits.
    """
    resealed = 0
    for webhook in db.query(Webhook):
        if seal_state(webhook) == "previous":
            seal(webhook)
            resealed += 1
    return resealed


# --- Events -----------------------------------------------------------------


def _body(event_id: str, event: str, data: dict, now: datetime) -> str:
    return json.dumps(
        {"id": event_id, "event": event, "created_at": now.isoformat(), "data": data},
        default=str,
        separators=(",", ":"),
    )


def emit(db: Session, event: str, data: dict, now: datetime | None = None) -> int:
    """Queue ``event`` for every enabled webhook subscribed to it, in the
    caller's transaction. Returns the number of deliveries queued."""
    if event not in EVENTS:
        raise ValueError(f"Unknown webhook event: {event}")
    targets = [
        webhook
        for webhook in db.query(Webhook).filter(Webhook.enabled.is_(True))
        # Another instance's webhooks would only pile up failed deliveries.
        if event in (webhook.events or []) and seal_state(webhook) != "foreign"
    ]
    if not targets:
        return 0
    now = now or datetime.now(UTC)
    event_id = uuid4().hex
    body = _body(event_id, event, data, now)
    db.add_all(
        WebhookDelivery(
            webhook_id=webhook.id,
            event_id=event_id,
            event=event,
            body=body,
            status=DeliveryStatus.pending.value,
            next_attempt_at=now,
        )
        for webhook in targets
    )
    return len(targets)


def queue_ping(db: Session, webhook: Webhook, now: datetime | None = None) -> None:
    """A test delivery to one webhook, sent like any other."""
    now = now or datetime.now(UTC)
    event_id = uuid4().hex
    db.add(
        WebhookDelivery(
            webhook_id=webhook.id,
            event_id=event_id,
            event=PING_EVENT,
            body=_body(event_id, PING_EVENT, {"webhook": webhook.name}, now),
            status=DeliveryStatus.pending.value,
            next_attempt_at=now,
        )
    )


def ticket_data(
    ticket, status: str, previous_status: str | None, actor: str, note: str | None
) -> dict:
    """``status`` given apart: the history is written before the ticket moves."""
    action = ticket.action
    return {
        "ticket": {
            "id": ticket.id,
            "title": ticket.title,
            "status": status,
            "previous_status": previous_status,
            "owner_team": ticket.owner_team,
            "external_ref": ticket.external_ref,
            "external_url": ticket.external_url,
            "action": (
                {
                    "reference": action.reference,
                    "kind": action.kind,
                    "title": action.title,
                }
                if action is not None
                else None
            ),
        },
        "actor": actor,
        "note": note,
    }


def scan_data(job) -> dict:
    status = getattr(job.status, "value", job.status)
    return {
        "scan": {
            "id": job.id,
            "scan_type": job.scan_type,
            "filename": job.filename,
            "status": status,
            "processed_records": job.processed_records,
            "new_assets": job.new_assets,
            "new_vulnerabilities": job.new_vulnerabilities,
            "new_associations": job.new_associations,
            "reopened": job.reopened,
            "auto_remediated": job.auto_remediated,
            "message": job.message,
            "finished_at": job.finished_at,
        }
    }


# --- Delivery ---------------------------------------------------------------


@dataclass
class DeliveryRun:
    delivered: int = 0
    retrying: int = 0
    failed: int = 0

    def as_dict(self) -> dict:
        return asdict(self)


def sign(secret: str, timestamp: str, body: str) -> str:
    digest = hmac.new(
        secret.encode(), f"{timestamp}.{body}".encode(), hashlib.sha256
    ).hexdigest()
    return f"sha256={digest}"


def deliver_due(db: Session, limit: int = DELIVERIES_PER_RUN) -> DeliveryRun:
    """Send the deliveries whose time has come, one transaction each.

    ``SKIP LOCKED`` lets two runs overlap (a slow receiver, a second worker)
    without sending a delivery twice; the row stays locked only for its own
    request. SQLite ignores it, and the test suite runs one worker.
    """
    run = DeliveryRun()
    for _ in range(limit):
        now = datetime.now(UTC)
        delivery = (
            db.query(WebhookDelivery)
            .filter(
                WebhookDelivery.status == DeliveryStatus.pending.value,
                WebhookDelivery.next_attempt_at <= now,
            )
            .order_by(WebhookDelivery.next_attempt_at, WebhookDelivery.id)
            .with_for_update(skip_locked=True)
            .first()
        )
        if delivery is None:
            break
        outcome = _attempt(delivery, now)
        setattr(run, outcome, getattr(run, outcome) + 1)
        db.commit()
    return run


def _attempt(delivery: WebhookDelivery, now: datetime) -> str:
    webhook = delivery.webhook
    if not webhook.enabled:
        return _give_up(delivery, now, "Webhook disabled")
    state = seal_state(webhook)
    if state == "foreign":
        return _give_up(delivery, now, "Webhook registered by another instance")
    if state == "previous":
        seal(webhook)

    delivery.attempts += 1
    timestamp = str(int(now.timestamp()))
    try:
        _check_resolved(webhook.url)
        response = requests.post(
            webhook.url,
            data=delivery.body.encode(),
            headers={
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
                "X-Vigie-Event": delivery.event,
                "X-Vigie-Delivery": delivery.event_id,
                "X-Vigie-Timestamp": timestamp,
                "X-Vigie-Signature": sign(webhook.secret, timestamp, delivery.body),
            },
            timeout=(CONNECT_TIMEOUT_SECONDS, settings.WEBHOOK_TIMEOUT_SECONDS),
            # A redirect could lead anywhere, past the address check.
            allow_redirects=False,
        )
    except TargetRefused as exc:
        return _give_up(delivery, now, str(exc))
    except (requests.RequestException, ConnectionError) as exc:
        return _retry(delivery, now, f"{type(exc).__name__}: {exc}")

    delivery.response_status = response.status_code
    response.close()
    if 200 <= response.status_code < 300:
        delivery.status = DeliveryStatus.delivered.value
        delivery.delivered_at = now
        delivery.last_error = None
        webhook.last_success_at = now
        return "delivered"
    return _retry(delivery, now, f"HTTP {response.status_code}")


def _retry(delivery: WebhookDelivery, now: datetime, error: str) -> str:
    if delivery.attempts > len(RETRY_DELAYS):
        return _give_up(delivery, now, error)
    delivery.last_error = error[:MAX_ERROR_LENGTH]
    delivery.next_attempt_at = now + RETRY_DELAYS[delivery.attempts - 1]
    _record_failure(delivery.webhook, now, error)
    return "retrying"


def _give_up(delivery: WebhookDelivery, now: datetime, error: str) -> str:
    delivery.status = DeliveryStatus.failed.value
    delivery.last_error = error[:MAX_ERROR_LENGTH]
    _record_failure(delivery.webhook, now, error)
    logger.warning(
        "Webhook delivery %s (%s) to webhook %s abandoned: %s",
        delivery.event_id,
        delivery.event,
        delivery.webhook_id,
        error,
    )
    return "failed"


def _record_failure(webhook: Webhook, now: datetime, error: str) -> None:
    webhook.last_failure_at = now
    webhook.last_error = error[:MAX_ERROR_LENGTH]


def retry_delivery(delivery: WebhookDelivery, now: datetime | None = None) -> None:
    """Send an abandoned delivery again, from a fresh set of attempts."""
    delivery.status = DeliveryStatus.pending.value
    delivery.attempts = 0
    delivery.next_attempt_at = now or datetime.now(UTC)


def purge_deliveries(db: Session, now: datetime | None = None) -> int:
    """Drop sent and abandoned deliveries past WEBHOOK_RETENTION_DAYS.

    Run by the daily pass. Pending ones stay, however old: they are still
    owed. The caller commits.
    """
    cutoff = (now or datetime.now(UTC)) - timedelta(days=settings.WEBHOOK_RETENTION_DAYS)
    return (
        db.query(WebhookDelivery)
        .filter(
            WebhookDelivery.status != DeliveryStatus.pending.value,
            WebhookDelivery.created_at < cutoff,
        )
        .delete(synchronize_session=False)
    )


def delivery_counts(db: Session) -> dict[int, dict[str, int]]:
    """Deliveries per webhook and status, for the administration screen."""
    counts: dict[int, dict[str, int]] = {}
    rows = db.query(
        WebhookDelivery.webhook_id, WebhookDelivery.status, func.count(WebhookDelivery.id)
    ).group_by(WebhookDelivery.webhook_id, WebhookDelivery.status)
    for webhook_id, status, count in rows:
        counts.setdefault(webhook_id, {})[status] = count
    return counts
