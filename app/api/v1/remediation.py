from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.deps import get_or_404
from app.db.database import get_db
from app.models.remediation import RemediationAction, RemediationKind
from app.schemas.remediation import (
    ActionHostsResponse,
    PaginatedActionSummaryResponse,
)
from app.services.remediation_plan import (
    ActionFilters,
    action_hosts,
    action_summaries,
    hosts_csv,
    unremediated_summary,
)

router = APIRouter()

MAX_LIMIT = 200


@router.get("/actions", response_model=PaginatedActionSummaryResponse)
def list_actions(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=MAX_LIMIT),
    kind: RemediationKind | None = None,
    search: str | None = Query(None, max_length=128),
    kev_only: bool = False,
    db: Session = Depends(get_db),
):
    """What to deploy, the fix removing the most open risk first.

    The same list as the backlog, folded per KB or fix instead of per CVE:
    that is the unit a remediation team plans, deploys and reports on.
    """
    filters = ActionFilters(
        kind=kind.value if kind else None, search=search or None, kev_only=kev_only
    )
    total, items = action_summaries(db, filters, skip, limit)
    return {"total": total, "items": items, "unremediated": unremediated_summary(db)}


@router.get("/actions/{action_id}", response_model=ActionHostsResponse)
def get_action(action_id: int, db: Session = Depends(get_db)):
    """A fix, its vendor solution, and every host still waiting for it."""
    action = get_or_404(db, RemediationAction, action_id)
    return {"action": action, "hosts": action_hosts(db, action.id)}


@router.get("/actions/{action_id}/hosts.csv", response_class=Response)
def export_action_hosts(action_id: int, db: Session = Depends(get_db)):
    """The hosts to deploy the fix on, for a deployment tool or a ticket."""
    action = get_or_404(db, RemediationAction, action_id)
    content = hosts_csv(action_hosts(db, action.id))
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    # The reference comes from a scanner: keep it filename-safe.
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in action.reference)
    return Response(
        content,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="vigie-{safe}-hosts-{stamp}.csv"'
        },
    )
