"""Threat intelligence feeds: freshness, manual refresh and offline import."""

import logging
from dataclasses import asdict

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import decode_token, require_admin
from app.db.database import get_db
from app.models.threat_intel import FEEDS
from app.parsers.threat_feeds import ThreatFeedError
from app.schemas.threat_intel import FeedResultResponse, ThreatIntelStatusResponse
from app.services.threat_intel import feed_freshness, import_feed
from app.worker.tasks import refresh_threat_intel_task

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/status", response_model=ThreatIntelStatusResponse)
def get_status(db: Session = Depends(get_db), payload: dict = Depends(decode_token)):
    """When each feed was last applied, from where, and whether it is stale."""
    return {
        "enabled": settings.THREAT_INTEL_ENABLED,
        "stale_after_hours": settings.THREAT_INTEL_STALE_AFTER_HOURS,
        "feeds": feed_freshness(db),
    }


@router.post("/refresh", status_code=status.HTTP_202_ACCEPTED)
def refresh(admin: dict = Depends(require_admin)):
    """Queue an immediate pull of both feeds, outside the daily schedule."""
    if not settings.THREAT_INTEL_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "The network refresh is disabled (THREAT_INTEL_ENABLED). "
                "Import the feed files instead."
            ),
        )
    try:
        task = refresh_threat_intel_task.apply_async()
    except Exception as exc:
        logger.error("Failed to enqueue threat intel refresh: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Processing queue is unavailable. Please retry shortly.",
        ) from None
    return {"task_id": task.id}


@router.post("/import", response_model=FeedResultResponse)
def import_file(
    feed: str = Form(..., description="kev or epss"),
    force: bool = Form(False, description="Apply even an older or shrunk snapshot"),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Apply a KEV or EPSS file downloaded out of band.

    Synchronous: the files are a few megabytes, the operation is rare and
    admin-only, and the administrator gets the outcome — or the reason for a
    refusal — in the response rather than in a worker log.
    """
    feed = feed.strip().lower()
    if feed not in FEEDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Feed must be one of: {', '.join(FEEDS)}",
        )

    limit = settings.THREAT_INTEL_MAX_FEED_BYTES
    raw = file.file.read(limit + 1)
    if len(raw) > limit:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"File exceeds {limit // (1024 * 1024)} MB",
        )

    try:
        result = import_feed(db, feed, raw, force=force)
    except ThreatFeedError as exc:
        # Parse errors and refusals are the administrator's to fix: say why.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from None

    logger.info("Threat feed %s imported by user %s: %s", feed, admin.get("sub"), result)
    return asdict(result)
