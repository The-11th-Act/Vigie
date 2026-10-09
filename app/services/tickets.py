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
from app.services.webhooks import emit, ticket_data

logger = logging.getLogger(__name__)

SYSTEM_ACTOR = "system"
# Bound-parameter friendly IN () lists, as elsewhere.
CHUNK_SIZE = 500
UNASSIGNED = "Unassigned"


@dataclass
class SyncResult:
    attached: int = 0
    resolved: int = 0
    reopened: int = 0
    moved: int = 0
    cancelled: int = 0
    # Tickets now on the fix their findings call for, and findings that went
    # to another ticket (or back to the plan) because their fix changed.
    retargeted: int = 0
    followed: int = 0


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


def log_ticket_change(
    db: Session, ticket, old, new, note, user: User | None, actor: str | None = None
) -> None:
    """Record a step of a ticket's history, and tell the webhooks of a move.

    Every change goes through here, the scans' and the people's alike: a
    status that moved without a trail, or without its event, is a bug.
    ``old`` is None for a note alone. ``actor`` names a non-human author
    other than the scans (a ticketing connector: "glpi").
    """
    actor = user.username if user else (actor or SYSTEM_ACTOR)
    db.add(
        TicketAuditLog(
            ticket_id=ticket.id,
            user_id=user.id if user else None,
            username=actor,
            old_status=old,
            new_status=new,
            note=note,
        )
    )
    if old is not None and old != new:
        emit(db, "ticket.status_changed", ticket_data(ticket, new, old, actor, note))


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
            log_ticket_change(db, ticket, None, ticket.status, None, user)
            emit(
                db,
                "ticket.created",
                ticket_data(ticket, ticket.status, None, user.username, None),
            )
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

    # 0. A finding whose host now belongs to another team leaves its former
    #    team's ticket; step 2 hands it to the new team's, if it has one.
    released = _release_moved_findings(db)
    result.moved = sum(released.values())

    counts = _finding_counts(db)

    # 1. A resolved ticket whose finding came back is work again.
    for ticket in db.query(RemediationTicket).filter(
        RemediationTicket.status == TicketStatus.resolved.value
    ):
        if counts.get(ticket.id, (0, 0))[1] > 0:
            log_ticket_change(
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

    # 1b. A finding whose fix changed (a later KB) takes its ticket along, or
    #     goes to the ticket of its new fix.
    if _follow_changed_fixes(db, result):
        counts = _finding_counts(db)

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

    # 3. Nothing left open: the scans confirm the work is done. Nothing left
    #    at all, because every host moved away: the team has nothing to do.
    for ticket in active:
        total, opened = counts.get(ticket.id, (0, 0))
        if not total and ticket.id in released:
            log_ticket_change(
                db,
                ticket,
                ticket.status,
                TicketStatus.cancelled.value,
                "Every host of this ticket moved to another team.",
                None,
            )
            ticket.status = TicketStatus.cancelled.value
            result.cancelled += 1
        elif total and not opened:
            log_ticket_change(
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
    if (
        result.attached
        or result.resolved
        or result.reopened
        or result.moved
        or result.followed
    ):
        logger.info(
            "Tickets: %d finding(s) attached, %d moved with their host, "
            "%d following a new fix (%d ticket(s) retargeted), "
            "%d resolved, %d reopened, %d cancelled",
            result.attached,
            result.moved,
            result.followed,
            result.retargeted,
            result.resolved,
            result.reopened,
            result.cancelled,
        )
    return result


def _finding_counts(db: Session) -> dict[int, tuple[int, int]]:
    """(findings, open findings) held by each ticket."""
    open_count = func.sum(case((AssetVulnerability.status == Status.open, 1), else_=0))
    return {
        row.ticket_id: (row.total, row.open or 0)
        for row in db.query(
            TicketFinding.ticket_id,
            func.count(TicketFinding.id).label("total"),
            open_count.label("open"),
        )
        .join(AssetVulnerability, AssetVulnerability.id == TicketFinding.finding_id)
        .group_by(TicketFinding.ticket_id)
    }


def _follow_changed_fixes(db: Session, result: SyncResult) -> bool:
    """Keep each active ticket on the fix its open findings now call for.

    A finding's fix changes when a later KB supersedes the one it was
    ticketed for (MSRC), or when the scanner asks for the next cumulative
    update itself. The ticket used to keep the finding in its counts but lose
    it from its host list: "3 open findings" and nowhere to deploy.

    - Every open finding of the ticket moved to the same fix, which its team
      has no active ticket for: the ticket follows them (same ticket and
      history, the new fix, a note).
    - Otherwise each moved finding joins its team's active ticket for its new
      fix, or, without one, leaves for the plan's untracked findings; a ticket
      left with no finding at all is cancelled.

    A finding is followed only when its new fix is clear: its one fix, or
    among several the only one its team has an active ticket for. Returns
    whether anything changed.
    """
    tickets = (
        db.query(RemediationTicket)
        .filter(RemediationTicket.status.in_(ACTIVE_TICKET_STATUSES))
        .order_by(RemediationTicket.id)
        .all()
    )
    if not tickets:
        return False
    held: dict[int, list[TicketFinding]] = defaultdict(list)
    for link in (
        db.query(TicketFinding)
        .join(RemediationTicket, RemediationTicket.id == TicketFinding.ticket_id)
        .join(AssetVulnerability, AssetVulnerability.id == TicketFinding.finding_id)
        .filter(
            RemediationTicket.status.in_(ACTIVE_TICKET_STATUSES),
            AssetVulnerability.status == Status.open,
        )
        .order_by(TicketFinding.id)
    ):
        held[link.ticket_id].append(link)
    fixes: dict[int, set[int]] = defaultdict(set)
    finding_ids = list({link.finding_id for links in held.values() for link in links})
    for i in range(0, len(finding_ids), CHUNK_SIZE):
        for finding_id, action_id in db.query(
            FindingRemediation.finding_id, FindingRemediation.action_id
        ).filter(FindingRemediation.finding_id.in_(finding_ids[i : i + CHUNK_SIZE])):
            fixes[finding_id].add(action_id)

    # The findings are open: whether one is already in a ticket is known here.
    membership = {
        (link.ticket_id, link.finding_id) for links in held.values() for link in links
    }
    team_tickets: dict[tuple[int, str | None], RemediationTicket] = {}
    for ticket in tickets:
        team_tickets.setdefault((ticket.action_id, ticket.owner_team), ticket)

    def new_fix(finding_id: int, team: str | None) -> int | None:
        current = fixes.get(finding_id, set())
        if len(current) == 1:
            return next(iter(current))
        ticketed = [a for a in current if (a, team) in team_tickets]
        return ticketed[0] if len(ticketed) == 1 else None

    changed = False
    for ticket in tickets:
        team = ticket.owner_team
        stray = [
            link
            for link in held.get(ticket.id, [])
            if ticket.action_id not in fixes.get(link.finding_id, set())
        ]
        targets: dict[int, int] = {}
        for link in stray:
            fix_id = new_fix(link.finding_id, team)
            if fix_id is not None:
                targets[link.id] = fix_id
        movable = [link for link in stray if link.id in targets]
        if not movable:
            continue
        changed = True
        destinations = {targets[link.id] for link in movable}

        # The whole ticket moves to one fix nobody on the team tickets yet.
        if (
            len(movable) == len(held[ticket.id])
            and len(destinations) == 1
            and (next(iter(destinations)), team) not in team_tickets
        ):
            old = ticket.action
            new = db.get(RemediationAction, next(iter(destinations)))
            if new is None:  # pragma: no cover - a link's action always exists
                continue
            if team_tickets.get((old.id, team)) is ticket:
                del team_tickets[(old.id, team)]
            team_tickets[(new.id, team)] = ticket
            ticket.action = new
            ticket.title = ticket_title(new, team)
            log_ticket_change(
                db,
                ticket,
                ticket.status,
                ticket.status,
                f"Its findings now call for {new.reference} instead of "
                f"{old.reference}: the ticket follows.",
                None,
            )
            result.retargeted += 1
            result.followed += len(movable)
            continue

        joined: dict[str, int] = defaultdict(int)
        for link in movable:
            target = team_tickets.get((targets[link.id], team))
            if target is not None and target is not ticket:
                if (target.id, link.finding_id) not in membership:
                    db.add(TicketFinding(ticket_id=target.id, finding_id=link.finding_id))
                    membership.add((target.id, link.finding_id))
                joined[f"the ticket #{target.id} of {target.action.reference}"] += 1
            else:
                fix = db.get(RemediationAction, targets[link.id])
                reference = fix.reference if fix else "another fix"
                joined[f"the plan's untracked findings of {reference}"] += 1
            db.delete(link)
            result.followed += 1
        db.flush()
        note = "; ".join(
            f"{count} finding(s) now call for another fix and went to {where}"
            for where, count in sorted(joined.items())
        )
        remaining = db.query(TicketFinding).filter_by(ticket_id=ticket.id).count()
        if remaining:
            log_ticket_change(db, ticket, ticket.status, ticket.status, note, None)
        else:
            log_ticket_change(
                db, ticket, ticket.status, TicketStatus.cancelled.value, note, None
            )
            ticket.status = TicketStatus.cancelled.value
            result.cancelled += 1
            if team_tickets.get((ticket.action_id, team)) is ticket:
                del team_tickets[(ticket.action_id, team)]
    db.flush()
    return changed


def _release_moved_findings(db: Session) -> dict[int, int]:
    """Take out of their ticket the open findings of a host that changed team.

    Their ticket is the former team's, which no longer sees the host (scopes)
    and has no reason to deploy there. A closed finding stays where it was:
    it was fixed while the host was that team's. Resolved tickets are covered
    too, or a finding coming back would reopen the former team's ticket.
    Returns the number of findings taken out, per ticket.
    """
    rows = (
        db.query(TicketFinding, RemediationTicket, Asset.owner_team)
        .join(RemediationTicket, RemediationTicket.id == TicketFinding.ticket_id)
        .join(AssetVulnerability, AssetVulnerability.id == TicketFinding.finding_id)
        .join(Asset, Asset.id == AssetVulnerability.asset_id)
        .filter(
            RemediationTicket.status.in_(
                [*ACTIVE_TICKET_STATUSES, TicketStatus.resolved.value]
            ),
            AssetVulnerability.status == Status.open,
            func.coalesce(Asset.owner_team, "")
            != func.coalesce(RemediationTicket.owner_team, ""),
        )
        .order_by(RemediationTicket.id)
        .all()
    )
    moved: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    tickets: dict[int, RemediationTicket] = {}
    for link, ticket, team in rows:
        db.delete(link)
        moved[ticket.id][team or UNASSIGNED] += 1
        tickets[ticket.id] = ticket
    for ticket_id, teams in moved.items():
        ticket = tickets[ticket_id]
        note = "; ".join(
            f"{count} finding(s) moved with their host to {team}"
            for team, count in sorted(teams.items())
        )
        log_ticket_change(db, ticket, ticket.status, ticket.status, note, None)
    db.flush()
    return {ticket_id: sum(teams.values()) for ticket_id, teams in moved.items()}


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
