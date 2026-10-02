"""Administration of the ticketing connector (app/services/ticketing.py).

Admins only, and never scoped: the connector mirrors every team's tickets.
The API holds none of GLPI's credentials; the worker runs the sync, and this
reports what its last run saw.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_request_id
from app.core.security import require_admin
from app.db.database import get_db
from app.schemas.ticketing import TicketingStatus, TicketingSyncQueued
from app.services.glpi import GLPI, LABEL, glpi_identity
from app.services.ticketing import overview
from app.worker.tasks import sync_glpi_task

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/", response_model=TicketingStatus)
def ticketing_status(db: Session = Depends(get_db), admin: dict = Depends(require_admin)):
    identity = glpi_identity()
    base = {
        "connector": GLPI,
        "label": LABEL,
        "enabled": settings.GLPI_SYNC_ENABLED,
        "configured": identity is not None,
        "url": settings.GLPI_URL,
        "interval_minutes": settings.GLPI_SYNC_INTERVAL_MINUTES,
        "team_groups": settings.GLPI_TEAM_GROUPS,
        "export_unmapped_teams": settings.GLPI_EXPORT_UNMAPPED_TEAMS,
    }
    if identity is None:
        return base
    return {**base, **overview(db, identity)}


@router.post(
    "/sync", response_model=TicketingSyncQueued, status_code=status.HTTP_202_ACCEPTED
)
def sync_now(admin: dict = Depends(require_admin)):
    """Run the sync now rather than at the next scheduled run."""
    if not settings.GLPI_SYNC_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The GLPI sync is disabled (GLPI_SYNC_ENABLED)",
        )
    try:
        task = sync_glpi_task.apply_async(headers={"request_id": get_request_id()})
    except Exception as exc:
        logger.error("Failed to enqueue the GLPI sync: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The task queue is unavailable. Please retry shortly.",
        ) from None
    return {"task_id": task.id}
