"""Remediation tickets: one fix, one team, and a status the scans keep honest.

A ticket gathers the open findings one remediation action closes on the hosts
of one team. The team moves it (in progress, deployed); the scanners decide
when it is done: it resolves once every finding it holds is closed, and reopens
if one comes back. New findings of the same fix on the same team's hosts join
the ticket already open for them rather than waiting for somebody to notice.
"""

import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import case, distinct, func
from sqlalchemy.orm import Session

from app.core.scope import Scope
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
from app.models.vulnerability import AssetVulnerability, Status, Vulnerability

logger = logging.getLogger(__name__)

SYSTEM_ACTOR = "system"
UNASSIGNED = "Unassigned"


@dataclass
class SyncResult:
    attached: int = 0
    resolved: int = 0
    reopened: int = 0


def ticket_title(action: RemediationAction, team: str | None) -> str:
    what = (
        f"Deploy {action.reference}"
        if action.kind == RemediationKind.kb.value
        else action.title or action.reference
    )
    return f"{what} — {team or UNASSIGNED}"[:512]


def _open_findings_of(db: Session, action_id: int) -> list[tuple[int, str | None]]:
    """(finding id, owner team) of every open finding the action closes."""
    rows = (
        db.query(AssetVulnerability.id, Asset.owner_team)
        .join(FindingRemediation, FindingRemediation.finding_id == AssetVulnerability.id)
        .join(Asset, Asset.id == AssetVulnerability.asset_id)
        .filter(
            FindingRemediation.action_id == action_id,
            AssetVulnerability.status == Status.open,
        )
        .distinct()
        .all()
    )
    return [(row.id, row.owner_team) for row in rows]


def _tracked_finding_ids(db: Session, action_ids) -> set[tuple[int, int]]:
    """(action id, finding id) pairs already held by an active ticket."""
    rows = (
        db.query(RemediationTicket.action_id, TicketFinding.finding_id)
        .join(TicketFinding, TicketFinding.ticket_id == RemediationTicket.id)
        .filter(
            RemediationTicket.status.in_(ACTIVE_TICKET_STATUSES),
            RemediationTicket.action_id.in_(list(action_ids)),
        )
        .all()
    )
    return {(row.action_id, row.finding_id) for row in rows}


def _log(db: Session, ticket, old, new, note, user: User | None) -> None:
    db.add(
        TicketAuditLog(
            ticket_id=ticket.id,
            user_id=user.id if user else None,
            username=user.username if user else SYSTEM_ACTOR,
            old_status=old,
            new_status=new,
            note=note,
        )
    )


def create_tickets(
    db: Session, action: RemediationAction, user: User, scope: Scope
) -> tuple[list[RemediationTicket], int]:
    """Put every untracked open finding of ``action`` into a ticket.

    Only for the teams ``scope`` covers: a scoped user tickets their own
    hosts, not another team's. One ticket per team owning the hosts; a team that already has an active
    ticket for this fix gets the new findings added to it instead of a second
    ticket. Returns the tickets created and the number of findings added to
    existing ones.
    """
    db.flush()
    tracked = {f for a, f in _tracked_finding_ids(db, [action.id])}
    by_team: dict[str | None, list[int]] = defaultdict(list)
    for finding_id, team in _open_findings_of(db, action.id):
        if finding_id not in tracked and scope.allows(team):
            by_team[team].append(finding_id)
    if not by_team:
        return [], 0

    existing = {
        ticket.owner_team: ticket
        for ticket in db.query(RemediationTicket)
        .filter(
            RemediationTicket.action_id == action.id,
            RemediationTicket.status.in_(ACTIVE_TICKET_STATUSES),
        )
        .order_by(RemediationTicket.id.desc())
    }

    created: list[RemediationTicket] = []
    added = 0
    for team, finding_ids in by_team.items():
        ticket = existing.get(team)
        if ticket is None:
            ticket = RemediationTicket(
                action_id=action.id,
                owner_team=team,
                title=ticket_title(action, team),
                status=TicketStatus.open.value,
                created_by=user.id,
            )
            db.add(ticket)
            db.flush()
            _log(db, ticket, None, ticket.status, None, user)
            created.append(ticket)
        else:
            added += len(finding_ids)
        db.add_all(
            TicketFinding(ticket_id=ticket.id, finding_id=finding_id)
            for finding_id in finding_ids
        )
    db.flush()
    return created, added


def sync_tickets(db: Session, now: datetime | None = None) -> SyncResult:
    """Bring every ticket in line with its findings, after they changed.

    Run after an ingestion, a triage decision and the daily pass. Order
    matters: a finding that came back reopens its own ticket before the
    untracked ones are handed out, so it is never counted twice.
    """
    now = now or datetime.now(UTC)
    result = SyncResult()
    # The production session does not autoflush: the statuses just changed by
    # the caller must reach the database before they are counted.
    db.flush()

    open_count = func.sum(case((AssetVulnerability.status == Status.open, 1), else_=0))
    counts = {
        row.ticket_id: (row.total, row.open or 0)
        for row in db.query(
            TicketFinding.ticket_id,
            func.count(TicketFinding.id).label("total"),
            open_count.label("open"),
        )
        .join(AssetVulnerability, AssetVulnerability.id == TicketFinding.finding_id)
        .group_by(TicketFinding.ticket_id)
    }

    # 1. A resolved ticket whose finding came back is work again.
    for ticket in db.query(RemediationTicket).filter(
        RemediationTicket.status == TicketStatus.resolved.value
    ):
        if counts.get(ticket.id, (0, 0))[1] > 0:
            _log(
                db,
                ticket,
                ticket.status,
                TicketStatus.open.value,
                "A finding of this ticket was detected again.",
                None,
            )
            ticket.status = TicketStatus.open.value
            ticket.resolved_at = None
            result.reopened += 1
    db.flush()

    active = (
        db.query(RemediationTicket)
        .filter(RemediationTicket.status.in_(ACTIVE_TICKET_STATUSES))
        .order_by(RemediationTicket.id)
        .all()
    )

    # 2. New findings of a fix join the team's active ticket for it.
    if active:
        target: dict[tuple[int, str | None], RemediationTicket] = {}
        for ticket in active:
            target.setdefault((ticket.action_id, ticket.owner_team), ticket)
        action_ids = {ticket.action_id for ticket in active}
        tracked = _tracked_finding_ids(db, action_ids)
        rows = (
            db.query(
                FindingRemediation.action_id, AssetVulnerability.id, Asset.owner_team
            )
            .join(
                AssetVulnerability, AssetVulnerability.id == FindingRemediation.finding_id
            )
            .join(Asset, Asset.id == AssetVulnerability.asset_id)
            .filter(
                FindingRemediation.action_id.in_(action_ids),
                AssetVulnerability.status == Status.open,
            )
            .distinct()
        )
        for action_id, finding_id, team in rows:
            joined = target.get((action_id, team))
            if joined is None or (action_id, finding_id) in tracked:
                continue
            db.add(TicketFinding(ticket_id=joined.id, finding_id=finding_id))
            tracked.add((action_id, finding_id))
            total, opened = counts.get(joined.id, (0, 0))
            counts[joined.id] = (total + 1, opened + 1)
            result.attached += 1

    # 3. Nothing left open: the scans confirm the work is done.
    for ticket in active:
        total, opened = counts.get(ticket.id, (0, 0))
        if total and not opened:
            _log(
                db,
                ticket,
                ticket.status,
                TicketStatus.resolved.value,
                "Every finding of this ticket is closed.",
                None,
            )
            ticket.status = TicketStatus.resolved.value
            ticket.resolved_at = now
            result.resolved += 1

    db.flush()
    if result.attached or result.resolved or result.reopened:
        logger.info(
            "Tickets: %d finding(s) attached, %d resolved, %d reopened",
            result.attached,
            result.resolved,
            result.reopened,
        )
    return result


def ticket_metrics(db: Session, ticket_ids: list[int]) -> dict[int, dict]:
    """What is left to do in each ticket, from its open findings."""
    if not ticket_ids:
        return {}
    is_open = AssetVulnerability.status == Status.open
    now = datetime.now(UTC)
    rows = (
        db.query(
            TicketFinding.ticket_id,
            func.count(TicketFinding.id).label("findings_total"),
            func.sum(case((is_open, 1), else_=0)).label("findings_open"),
            func.count(distinct(case((is_open, AssetVulnerability.asset_id)))).label(
                "hosts_open"
            ),
            func.count(distinct(AssetVulnerability.asset_id)).label("hosts_total"),
            func.coalesce(
                func.sum(case((is_open, AssetVulnerability.risk_score), else_=0.0)), 0.0
            ).label("open_risk"),
            func.max(case((is_open, AssetVulnerability.risk_score))).label("max_risk"),
            func.min(case((is_open, AssetVulnerability.remediation_deadline))).label(
                "next_deadline"
            ),
            func.sum(case((is_open & Vulnerability.in_kev.is_(True), 1), else_=0)).label(
                "kev"
            ),
            func.sum(
                case(
                    (is_open & (AssetVulnerability.remediation_deadline < now), 1),
                    else_=0,
                )
            ).label("overdue"),
        )
        .join(AssetVulnerability, AssetVulnerability.id == TicketFinding.finding_id)
        .join(Vulnerability, Vulnerability.id == AssetVulnerability.vulnerability_id)
        .filter(TicketFinding.ticket_id.in_(ticket_ids))
        .group_by(TicketFinding.ticket_id)
    )
    return {
        row.ticket_id: {
            "findings_total": row.findings_total,
            "findings_open": row.findings_open or 0,
            "hosts_open": row.hosts_open,
            "hosts_total": row.hosts_total,
            "open_risk": round(float(row.open_risk or 0.0), 2),
            "max_risk": float(row.max_risk or 0.0),
            "next_deadline": row.next_deadline,
            "kev": row.kev or 0,
            "overdue": row.overdue or 0,
        }
        for row in rows
    }


def tracked_counts(db: Session, action_ids: list[int], scope: Scope) -> dict[int, int]:
    """Open findings of each action already held by an active ticket, among
    the hosts ``scope`` covers."""
    if not action_ids:
        return {}
    rows = (
        db.query(
            RemediationTicket.action_id,
            func.count(distinct(TicketFinding.finding_id)).label("tracked"),
        )
        .join(TicketFinding, TicketFinding.ticket_id == RemediationTicket.id)
        .join(AssetVulnerability, AssetVulnerability.id == TicketFinding.finding_id)
        .join(Asset, Asset.id == AssetVulnerability.asset_id)
        .filter(
            RemediationTicket.action_id.in_(action_ids),
            RemediationTicket.status.in_(ACTIVE_TICKET_STATUSES),
            AssetVulnerability.status == Status.open,
        )
        .group_by(RemediationTicket.action_id)
    )
    rows = scope.filter(rows)
    return {row.action_id: row.tracked for row in rows}


def ticket_finding_ids(db: Session, ticket_id: int) -> list[int]:
    rows = db.query(TicketFinding.finding_id).filter(TicketFinding.ticket_id == ticket_id)
    return [row.finding_id for row in rows]
