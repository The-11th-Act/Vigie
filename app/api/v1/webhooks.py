"""Administration of outgoing webhooks (app/services/webhooks.py).

Admins only, and never scoped: a webhook carries events of the whole estate.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.api.deps import get_or_404
from app.core.security import require_admin
from app.db.database import get_db
from app.models.webhook import DeliveryStatus, Webhook, WebhookDelivery
from app.schemas.webhooks import (
    WebhookCreate,
    WebhookDeliveryResponse,
    WebhookEvent,
    WebhookResponse,
    WebhookUpdate,
    WebhookWithSecret,
)
from app.services.webhooks import (
    EVENTS,
    delivery_counts,
    new_secret,
    queue_ping,
    retry_delivery,
    seal,
    seal_state,
)

logger = logging.getLogger(__name__)

router = APIRouter()

MAX_DELIVERIES = 200


def _out(webhook: Webhook, counts: dict[int, dict[str, int]]) -> dict:
    mine = counts.get(webhook.id, {})
    return {
        "id": webhook.id,
        "name": webhook.name,
        "url": webhook.url,
        "events": webhook.events or [],
        "enabled": webhook.enabled,
        "usable": seal_state(webhook) != "foreign",
        "created_at": webhook.created_at,
        "created_by_username": webhook.creator.username if webhook.creator else None,
        "last_success_at": webhook.last_success_at,
        "last_failure_at": webhook.last_failure_at,
        "last_error": webhook.last_error,
        "pending": mine.get(DeliveryStatus.pending.value, 0),
        "failed": mine.get(DeliveryStatus.failed.value, 0),
    }


def _admin_id(token_data: dict) -> int | None:
    try:
        return int(token_data["sub"])
    except (KeyError, TypeError, ValueError):
        return None


@router.get("/events", response_model=list[WebhookEvent])
def list_events(admin: dict = Depends(require_admin)):
    return [{"name": name, "description": text} for name, text in EVENTS.items()]


@router.get("/", response_model=list[WebhookResponse])
def list_webhooks(db: Session = Depends(get_db), admin: dict = Depends(require_admin)):
    counts = delivery_counts(db)
    return [_out(w, counts) for w in db.query(Webhook).order_by(Webhook.id)]


@router.post("/", response_model=WebhookWithSecret, status_code=status.HTTP_201_CREATED)
def create_webhook(
    webhook_in: WebhookCreate,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    webhook = Webhook(
        name=webhook_in.name,
        url=webhook_in.url,
        events=webhook_in.events,
        secret=new_secret(),
        enabled=True,
        created_by=_admin_id(admin),
    )
    seal(webhook)
    db.add(webhook)
    db.commit()
    db.refresh(webhook)
    logger.info("Webhook %s created for %s", webhook.id, webhook.url)
    return {**_out(webhook, {}), "secret": webhook.secret}


@router.patch("/{webhook_id}", response_model=WebhookResponse)
def update_webhook(
    webhook_id: int,
    webhook_in: WebhookUpdate,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    webhook = get_or_404(db, Webhook, webhook_id)
    if seal_state(webhook) == "foreign":
        # Editing it here would make it send, with the other instance's
        # secret, to the other instance's receiver.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Registered by another instance: rotate its secret to use it here",
        )
    changes = webhook_in.model_dump(exclude_unset=True)
    for key, value in changes.items():
        if value is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"{key} cannot be empty",
            )
        setattr(webhook, key, value)
    seal(webhook)
    db.commit()
    db.refresh(webhook)
    return _out(webhook, delivery_counts(db))


@router.post("/{webhook_id}/rotate-secret", response_model=WebhookWithSecret)
def rotate_secret(
    webhook_id: int,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """A new secret, sealed to this instance: also how a staging adopts a
    webhook restored from production, which its receiver will then reject
    until given the new secret."""
    webhook = get_or_404(db, Webhook, webhook_id)
    webhook.secret = new_secret()
    seal(webhook)
    db.commit()
    db.refresh(webhook)
    logger.info("Webhook %s secret rotated", webhook.id)
    return {**_out(webhook, delivery_counts(db)), "secret": webhook.secret}


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_webhook(
    webhook_id: int,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    webhook = get_or_404(db, Webhook, webhook_id)
    db.query(WebhookDelivery).filter(WebhookDelivery.webhook_id == webhook.id).delete(
        synchronize_session=False
    )
    db.delete(webhook)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{webhook_id}/ping", status_code=status.HTTP_202_ACCEPTED)
def ping_webhook(
    webhook_id: int,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Queue a test delivery; its outcome shows in the deliveries."""
    webhook = get_or_404(db, Webhook, webhook_id)
    if seal_state(webhook) == "foreign" or not webhook.enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This webhook cannot send from here",
        )
    queue_ping(db, webhook)
    db.commit()
    return {"status": "queued"}


@router.get("/{webhook_id}/deliveries", response_model=list[WebhookDeliveryResponse])
def list_deliveries(
    webhook_id: int,
    limit: int = Query(50, ge=1, le=MAX_DELIVERIES),
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    get_or_404(db, Webhook, webhook_id)
    return (
        db.query(WebhookDelivery)
        .filter(WebhookDelivery.webhook_id == webhook_id)
        .order_by(WebhookDelivery.id.desc())
        .limit(limit)
        .all()
    )


@router.post(
    "/{webhook_id}/deliveries/{delivery_id}/retry",
    response_model=WebhookDeliveryResponse,
)
def retry(
    webhook_id: int,
    delivery_id: int,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    delivery = get_or_404(db, WebhookDelivery, delivery_id)
    if delivery.webhook_id != webhook_id:
        raise HTTPException(status_code=404, detail="WebhookDelivery not found")
    if delivery.status != DeliveryStatus.failed.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Only an abandoned delivery can be sent again",
        )
    retry_delivery(delivery)
    db.commit()
    db.refresh(delivery)
    return delivery
