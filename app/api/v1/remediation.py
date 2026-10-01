from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy import case, func
from sqlalchemy.orm import Session, joinedload

from app.api.deps import get_in_scope_or_404, get_or_404
from app.core.modules import current_user, require_risk_decision
from app.core.scope import Scope, current_scope
from app.db.database import get_db
from app.models.asset import Asset
from app.models.remediation import FindingRemediation, RemediationAction, RemediationKind
from app.models.ticket import (
    ACTIVE_TICKET_STATUSES,
    RemediationTicket,
    TicketAuditLog,
    TicketFinding,
    TicketStatus,
)
from app.models.user import User
from app.models.vulnerability import AssetVulnerability, Status
from app.schemas.remediation import (
    ActionHostsResponse,
    CreatedTicketsResponse,
    PaginatedActionSummaryResponse,
    PaginatedTicketResponse,
    TeamsResponse,
    TicketDetailResponse,
    TicketResponse,
    TicketUpdate,
)
from app.services.remediation_plan import (
    ActionFilters,
    action_hosts,
    action_summaries,
    hosts_csv,
    unremediated_summary,
)
from app.services.tickets import (
    create_tickets,
    log_ticket_change,
    ticket_finding_ids,
    ticket_metrics,
    tracked_counts,
)

router = APIRouter()

MAX_LIMIT = 200
# Ticket filter for hosts nobody owns yet.
UNASSIGNED_FILTER = "__unassigned__"


def _csv_response(content: str, reference: str, what: str) -> Response:
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    # The reference comes from a scanner: keep it filename-safe.
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in reference)
    return Response(
        content,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="vigie-{safe}-{what}-{stamp}.csv"'
        },
    )


@router.get("/actions", response_model=PaginatedActionSummaryResponse)
def list_actions(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=MAX_LIMIT),
    kind: RemediationKind | None = None,
    search: str | None = Query(None, max_length=128),
    kev_only: bool = False,
    db: Session = Depends(get_db),
    scope: Scope = Depends(current_scope),
):
    """What to deploy, the fix removing the most open risk first.

    The same list as the backlog, folded per KB or fix instead of per CVE:
    that is the unit a remediation team plans, deploys and reports on.
    """
    filters = ActionFilters(
        kind=kind.value if kind else None, search=search or None, kev_only=kev_only
    )
    total, items = action_summaries(db, filters, skip, limit, scope)
    tracked = tracked_counts(db, [item["action"].id for item in items], scope)
    for item in items:
        item["tracked"] = tracked.get(item["action"].id, 0)
    return {
        "total": total,
        "items": items,
        "unremediated": unremediated_summary(db, scope),
    }


@router.get("/actions/{action_id}", response_model=ActionHostsResponse)
def get_action(
    action_id: int, db: Session = Depends(get_db), scope: Scope = Depends(current_scope)
):
    """A fix, its vendor solution, and every host still waiting for it."""
    action = _action_in_scope(db, action_id, scope)
    return {"action": action, "hosts": action_hosts(db, action.id, scope)}


@router.get("/actions/{action_id}/hosts.csv", response_class=Response)
def export_action_hosts(
    action_id: int, db: Session = Depends(get_db), scope: Scope = Depends(current_scope)
):
    """The hosts to deploy the fix on, for a deployment tool or a ticket."""
    action = _action_in_scope(db, action_id, scope)
    return _csv_response(
        hosts_csv(action_hosts(db, action.id, scope)), action.reference, "hosts"
    )


@router.post(
    "/actions/{action_id}/tickets",
    response_model=CreatedTicketsResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_action_tickets(
    action_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
    scope: Scope = Depends(current_scope),
):
    """Ticket the open findings of a fix, one ticket per team owning the hosts.

    Findings already in an active ticket are left there; a team that already
    has one for this fix gets the new findings added to it.
    """
    action = _action_in_scope(db, action_id, scope)
    created, added = create_tickets(db, action, user, scope)
    if not created and not added:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Every open finding of this fix is already in a ticket",
        )
    db.commit()
    metrics = ticket_metrics(db, [ticket.id for ticket in created])
    return {"created": [_ticket_out(t, metrics) for t in created], "added": added}


@router.get("/tickets", response_model=PaginatedTicketResponse)
def list_tickets(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=MAX_LIMIT),
    ticket_status: str | None = Query(
        "active",
        alias="status",
        description="'active' (default), 'all', or one ticket status",
    ),
    owner_team: str | None = Query(None, max_length=128),
    action_id: int | None = None,
    db: Session = Depends(get_db),
    scope: Scope = Depends(current_scope),
):
    """Tickets, the one with the most open risk left first."""
    open_risk = (
        db.query(
            TicketFinding.ticket_id.label("ticket_id"),
            func.sum(
                case(
                    (
                        AssetVulnerability.status == Status.open,
                        AssetVulnerability.risk_score,
                    ),
                    else_=0.0,
                )
            ).label("open_risk"),
        )
        .join(AssetVulnerability, AssetVulnerability.id == TicketFinding.finding_id)
        .group_by(TicketFinding.ticket_id)
        .subquery()
    )
    query = (
        db.query(RemediationTicket)
        .outerjoin(open_risk, open_risk.c.ticket_id == RemediationTicket.id)
        .options(
            joinedload(RemediationTicket.action), joinedload(RemediationTicket.creator)
        )
    )
    query = scope.filter(query, RemediationTicket.owner_team)
    if ticket_status in (None, "active"):
        query = query.filter(RemediationTicket.status.in_(ACTIVE_TICKET_STATUSES))
    elif ticket_status != "all":
        if ticket_status not in {s.value for s in TicketStatus}:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Unknown ticket status",
            )
        query = query.filter(RemediationTicket.status == ticket_status)
    if owner_team == UNASSIGNED_FILTER:
        query = query.filter(RemediationTicket.owner_team.is_(None))
    elif owner_team:
        query = query.filter(RemediationTicket.owner_team == owner_team)
    if action_id is not None:
        query = query.filter(RemediationTicket.action_id == action_id)

    total = query.count()
    tickets = (
        query.order_by(
            func.coalesce(open_risk.c.open_risk, 0.0).desc(), RemediationTicket.id.desc()
        )
        .offset(skip)
        .limit(limit)
        .all()
    )
    metrics = ticket_metrics(db, [ticket.id for ticket in tickets])
    return {"total": total, "items": [_ticket_out(t, metrics) for t in tickets]}


@router.get("/tickets/{ticket_id}", response_model=TicketDetailResponse)
def get_ticket(
    ticket_id: int, db: Session = Depends(get_db), scope: Scope = Depends(current_scope)
):
    """A ticket, the hosts it still waits on, and its history."""
    ticket = get_in_scope_or_404(db, RemediationTicket, ticket_id, scope, _team)
    history = (
        db.query(TicketAuditLog)
        .filter(TicketAuditLog.ticket_id == ticket.id)
        .order_by(TicketAuditLog.created_at.desc(), TicketAuditLog.id.desc())
        .all()
    )
    return {
        "ticket": _ticket_out(ticket, ticket_metrics(db, [ticket.id])),
        "action": ticket.action,
        "hosts": action_hosts(
            db, ticket.action_id, scope, ticket_finding_ids(db, ticket.id)
        ),
        "history": history,
    }


@router.get("/tickets/{ticket_id}/hosts.csv", response_class=Response)
def export_ticket_hosts(
    ticket_id: int, db: Session = Depends(get_db), scope: Scope = Depends(current_scope)
):
    """The hosts of one ticket, for the team's deployment tool."""
    ticket = get_in_scope_or_404(db, RemediationTicket, ticket_id, scope, _team)
    hosts = action_hosts(db, ticket.action_id, scope, ticket_finding_ids(db, ticket.id))
    return _csv_response(hosts_csv(hosts), ticket.action.reference, f"ticket-{ticket.id}")


@router.patch("/tickets/{ticket_id}", response_model=TicketResponse)
def update_ticket(
    ticket_id: int,
    update_in: TicketUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
    scope: Scope = Depends(current_scope),
):
    """Move a ticket, or record where it lives in an external tool.

    The team marks it in progress or deployed; the scans resolve it. Cancelling
    means deciding not to fix: an analyst's call, with a justification.
    """
    ticket = get_in_scope_or_404(db, RemediationTicket, ticket_id, scope, _team)
    changes = update_in.model_dump(exclude_unset=True)
    new_status = changes.pop("status", None)
    note = changes.pop("note", None)

    if new_status and new_status != ticket.status:
        if ticket.status not in ACTIVE_TICKET_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A {ticket.status} ticket cannot be moved by hand",
            )
        if new_status == TicketStatus.cancelled.value:
            require_risk_decision(user)
            if not note:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="A note is required to cancel a ticket",
                )
    else:
        new_status = None

    for key, value in changes.items():
        setattr(ticket, key, value)
    if new_status or note:
        log_ticket_change(
            db,
            ticket,
            ticket.status if new_status else None,
            new_status or ticket.status,
            note,
            user,
        )
        if note:
            ticket.note = note
        if new_status:
            ticket.status = new_status
    db.commit()
    db.refresh(ticket)
    return _ticket_out(ticket, ticket_metrics(db, [ticket.id]))


@router.get("/teams", response_model=TeamsResponse)
def list_teams(db: Session = Depends(get_db), scope: Scope = Depends(current_scope)):
    """Teams owning at least one host, for the ticket filters: those of the
    caller's scope only."""
    rows = (
        db.query(Asset.owner_team)
        .filter(Asset.owner_team.isnot(None))
        .distinct()
        .order_by(Asset.owner_team)
    )
    return {"teams": scope.visible_teams(row.owner_team for row in rows)}


def _ticket_out(ticket: RemediationTicket, metrics: dict[int, dict]) -> dict:
    return {
        "id": ticket.id,
        "action_id": ticket.action_id,
        "owner_team": ticket.owner_team,
        "title": ticket.title,
        "status": ticket.status,
        "note": ticket.note,
        "external_system": ticket.external_system,
        "external_ref": ticket.external_ref,
        "external_url": ticket.external_url,
        "created_by_username": ticket.creator.username if ticket.creator else None,
        "created_at": ticket.created_at,
        "updated_at": ticket.updated_at,
        "resolved_at": ticket.resolved_at,
        "action": ticket.action,
        "metrics": metrics.get(ticket.id, {}),
    }


def _team(ticket: RemediationTicket) -> str | None:
    return ticket.owner_team


def _action_in_scope(db: Session, action_id: int, scope: Scope) -> RemediationAction:
    """A fix the caller's scope has a host for, or the 404 of a missing one.

    A fix is shared, but its title and reference say what another team's
    hosts are missing.
    """
    action = get_or_404(db, RemediationAction, action_id)
    if scope.restricted:
        in_scope = scope.filter(
            db.query(FindingRemediation.finding_id)
            .join(
                AssetVulnerability, AssetVulnerability.id == FindingRemediation.finding_id
            )
            .join(Asset, Asset.id == AssetVulnerability.asset_id)
            .filter(FindingRemediation.action_id == action.id)
        )
        if in_scope.first() is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="RemediationAction not found",
            )
    return action
