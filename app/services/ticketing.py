"""Mirror remediation tickets in the ticketing tool the teams work in.

Vigie keeps its own tickets (app/services/tickets.py): one fix, one team, a
status the scans keep honest. A connector mirrors them in an external tool
(GLPI first, app/services/glpi.py):

- export: an active ticket with no external link is created in the tool;
- the team's progress comes back: the external ticket in progress makes the
  Vigie ticket in progress, solved or closed makes it deployed; the scans
  still decide when it is resolved;
- Vigie's own decisions go out: a ticket resolved by the scans or cancelled
  is solved in the tool; a ticket with work again (a finding came back) is
  reopened there, or replaced when the tool's ticket is closed for good.

Each side's changes are told from the other's by the external state last
seen or set (``external_state``). A link is sealed to the instance and to the
tool's server, like a webhook: a staging restored from production shows
production's links but never acts on them.
"""

import hashlib
import hmac
import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Literal, Protocol

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.scope import EVERYTHING
from app.models.remediation import RemediationAction
from app.models.ticket import (
    ACTIVE_TICKET_STATUSES,
    RemediationTicket,
    TicketConnectorStatus,
    TicketStatus,
)
from app.services.remediation_plan import HostEntry, action_hosts
from app.services.tickets import log_ticket_change, ticket_finding_ids, ticket_metrics

logger = logging.getLogger(__name__)

# Linked tickets checked, and tickets exported, per run: a first run on a
# large backlog spreads over several, rather than holding the worker.
TICKETS_PER_RUN = 50
MAX_ERROR_LENGTH = 512

SealState = Literal["current", "previous", "foreign"]


class ExternalState(str, Enum):
    """An external ticket's state, in terms every connector maps to."""

    open = "open"
    in_progress = "in_progress"
    solved = "solved"
    closed = "closed"
    gone = "gone"  # deleted in the tool: no longer synced


DONE_STATES = {ExternalState.solved.value, ExternalState.closed.value}

# The team's progress in the tool, as a Vigie status.
STATUS_FROM_STATE = {
    ExternalState.open.value: TicketStatus.open.value,
    ExternalState.in_progress.value: TicketStatus.in_progress.value,
    ExternalState.solved.value: TicketStatus.deployed.value,
    ExternalState.closed.value: TicketStatus.deployed.value,
}

FINISHED_STATUSES = (TicketStatus.resolved.value, TicketStatus.cancelled.value)


class ConnectorUnavailable(RuntimeError):
    """The tool cannot be reached, or refuses Vigie: the run stops there."""


class ExternalTicketError(RuntimeError):
    """This ticket cannot be synced now; the others can."""


class ExternalTicketClosed(ExternalTicketError):
    """Closed for good in the tool: it cannot be reopened, only replaced."""


@dataclass
class ExternalTicket:
    ref: str
    url: str | None
    state: ExternalState


@dataclass
class TicketExport:
    """What a connector needs to describe a ticket in its tool."""

    ticket_id: int
    title: str
    owner_team: str | None
    action: RemediationAction
    metrics: dict
    hosts: list[HostEntry]


class ConnectorIdentity(Protocol):
    """What the seal and the administration screen need: no credentials."""

    @property
    def name(self) -> str:
        """Stored in external_system."""

    @property
    def label(self) -> str:
        """Shown to people: "GLPI"."""

    @property
    def target(self) -> str:
        """The tool's server; part of the seal."""

    @property
    def teams(self) -> frozenset[str | None] | None:
        """Owner teams whose tickets are exported (None for hosts no team
        owns); None: every team."""


class TicketConnector(ConnectorIdentity, Protocol):
    def open(self) -> None: ...

    def close(self) -> None:
        """Never raises: called on the way out of a failed run too."""

    def create(self, export: TicketExport) -> ExternalTicket: ...

    def state(self, ref: str) -> ExternalState: ...

    def solve(self, ref: str, message: str) -> ExternalState: ...

    def reopen(self, ref: str, message: str) -> ExternalState:
        """Raises ExternalTicketClosed when the ticket can only be replaced."""


@dataclass
class SyncRun:
    exported: int = 0
    pulled: int = 0  # Vigie statuses moved by the team's changes in the tool
    solved: int = 0
    reopened: int = 0
    replaced: int = 0
    gone: int = 0
    foreign: int = 0
    errors: int = 0
    error: str | None = field(default=None, repr=False)

    def as_dict(self) -> dict:
        counts = asdict(self)
        counts.pop("error")
        return counts


# --- Seal -------------------------------------------------------------------


def _seal_with(key: str, connector: ConnectorIdentity, ticket: RemediationTicket) -> str:
    message = (
        f"vigie-ticket\x00{connector.name}\x00{connector.target}"
        f"\x00{ticket.id}\x00{ticket.external_ref}"
    ).encode()
    return hmac.new(key.encode(), message, hashlib.sha256).hexdigest()


def seal_link(ticket: RemediationTicket, connector: ConnectorIdentity) -> None:
    ticket.external_seal = _seal_with(settings.SECRET_KEY, connector, ticket)


def link_state(ticket: RemediationTicket, connector: ConnectorIdentity) -> SealState:
    """Who wrote this link: this instance for this server, this instance
    before a key rotation, or anyone else (another instance, another server,
    a hand edit of the database)."""
    seal = ticket.external_seal
    if ticket.external_system != connector.name or not seal:
        return "foreign"
    if hmac.compare_digest(seal, _seal_with(settings.SECRET_KEY, connector, ticket)):
        return "current"
    for key in settings.PREVIOUS_SECRET_KEYS.values():
        if hmac.compare_digest(seal, _seal_with(key, connector, ticket)):
            return "previous"
    return "foreign"


def reseal_links(db: Session, connector: ConnectorIdentity) -> int:
    """Move every link sealed with a retired key to the current one.

    Run by the daily pass: a finished ticket is no longer synced, hence no
    longer resealed on the way, and would turn foreign once its key is
    dropped, then be ignored for good if a finding reopened it. The caller
    commits.
    """
    resealed = 0
    for ticket in db.query(RemediationTicket).filter(
        RemediationTicket.external_system == connector.name
    ):
        if link_state(ticket, connector) == "previous":
            seal_link(ticket, connector)
            resealed += 1
    return resealed


def _unlinked(db: Session, connector: ConnectorIdentity):
    """Active tickets with no external link, by hand or by a connector, among
    the connector's teams; None when it exports no team at all."""
    query = db.query(RemediationTicket).filter(
        RemediationTicket.status.in_(ACTIVE_TICKET_STATUSES),
        RemediationTicket.external_system.is_(None),
        RemediationTicket.external_ref.is_(None),
    )
    if connector.teams is None:
        return query
    named = [team for team in connector.teams if team is not None]
    conditions = [RemediationTicket.owner_team.in_(named)] if named else []
    if None in connector.teams:
        conditions.append(RemediationTicket.owner_team.is_(None))
    return query.filter(or_(*conditions)) if conditions else None


# --- Run --------------------------------------------------------------------


def sync_tickets_with(
    db: Session,
    connector: TicketConnector,
    now: datetime | None = None,
    limit: int = TICKETS_PER_RUN,
) -> SyncRun:
    """One run of ``connector``: linked tickets first, then the exports.

    Commits after each ticket, so that a ticket created in the tool is linked
    in Vigie at once: a run that failed half-way creates no duplicate on the
    next. A ticket is locked while it is handled (SKIP LOCKED), so two runs
    that overlap never handle it twice.
    """
    now = now or datetime.now(UTC)
    run = SyncRun()
    status = db.get(TicketConnectorStatus, connector.name)
    if status is None:
        status = TicketConnectorStatus(name=connector.name)
        db.add(status)
    status.last_run_at = now
    try:
        connector.open()
        try:
            _sync_linked(db, connector, run, now, limit)
            _export(db, connector, run, now, limit)
        finally:
            connector.close()
    except ConnectorUnavailable as exc:
        run.error = str(exc)[:MAX_ERROR_LENGTH]
        status.last_error = run.error
        status.last_result = run.as_dict()
        db.commit()
        logger.warning("%s sync stopped: %s", connector.label, run.error)
        return run
    status.last_success_at = now
    status.last_error = None
    status.last_result = run.as_dict()
    db.commit()
    logger.info("%s sync: %s", connector.label, run.as_dict())
    return run


def _next(db: Session, query, seen: set[int]) -> RemediationTicket | None:
    if seen:
        query = query.filter(RemediationTicket.id.notin_(seen))
    ticket = query.with_for_update(skip_locked=True).first()
    if ticket is not None:
        seen.add(ticket.id)
    return ticket


def _sync_linked(
    db: Session, connector: TicketConnector, run: SyncRun, now: datetime, limit: int
) -> None:
    """Tickets linked by this connector that may have something to sync:
    active ones (the team may have moved them), finished ones the tool does
    not know are done. Least recently synced first."""
    query = (
        db.query(RemediationTicket)
        .filter(
            RemediationTicket.external_system == connector.name,
            or_(
                RemediationTicket.external_state.is_(None),
                RemediationTicket.external_state != ExternalState.gone.value,
            ),
            or_(
                RemediationTicket.status.in_(ACTIVE_TICKET_STATUSES),
                and_(
                    RemediationTicket.status.in_(FINISHED_STATUSES),
                    or_(
                        RemediationTicket.external_state.is_(None),
                        RemediationTicket.external_state.notin_(DONE_STATES),
                    ),
                ),
            ),
        )
        .order_by(
            RemediationTicket.external_synced_at.asc().nulls_first(),
            RemediationTicket.id,
        )
    )
    seen: set[int] = set()
    for _ in range(limit):
        ticket = _next(db, query, seen)
        if ticket is None:
            return
        _sync_one(db, connector, ticket, run, now)
        ticket.external_synced_at = now
        db.commit()


def _sync_one(
    db: Session,
    connector: TicketConnector,
    ticket: RemediationTicket,
    run: SyncRun,
    now: datetime,
) -> None:
    sealed = link_state(ticket, connector)
    if sealed == "foreign":
        run.foreign += 1
        return
    if sealed == "previous":
        seal_link(ticket, connector)

    ref = ticket.external_ref or ""
    try:
        remote = connector.state(ref)
        if remote == ExternalState.gone:
            ticket.external_state = remote.value
            ticket.external_error = f"The {connector.label} ticket no longer exists"
            _note(db, ticket, connector, f"{connector.label} ticket {ref} was deleted")
            run.gone += 1
            return

        # Solved then closed is the tool closing what was done (GLPI does it
        # on its own after a delay), not the team's work.
        changed = remote.value != ticket.external_state and not (
            remote.value in DONE_STATES and ticket.external_state in DONE_STATES
        )
        if ticket.status in ACTIVE_TICKET_STATUSES:
            if changed:
                # The team moved it in the tool.
                wanted = STATUS_FROM_STATE[remote.value]
                if wanted != ticket.status:
                    log_ticket_change(
                        db,
                        ticket,
                        ticket.status,
                        wanted,
                        f"Set in {connector.label} (ticket {ref})",
                        None,
                        actor=connector.name,
                    )
                    ticket.status = wanted
                    run.pulled += 1
            elif (
                remote.value in DONE_STATES
                and ticket.status != TicketStatus.deployed.value
            ):
                # Done in the tool, but Vigie has work again: a finding came
                # back after the scans resolved it, or someone moved it back.
                remote = _reopen(db, connector, ticket, run)
        elif ticket.external_state not in DONE_STATES and remote.value not in DONE_STATES:
            remote = connector.solve(ref, _finished_message(ticket))
            run.solved += 1

        ticket.external_state = remote.value
        ticket.external_error = None
    except ExternalTicketError as exc:
        ticket.external_error = str(exc)[:MAX_ERROR_LENGTH]
        run.errors += 1
        logger.warning("%s sync of ticket %s failed: %s", connector.label, ticket.id, exc)


def _reopen(
    db: Session, connector: TicketConnector, ticket: RemediationTicket, run: SyncRun
) -> ExternalState:
    ref = ticket.external_ref or ""
    message = (
        "Vigie has work again on this ticket: a finding it holds is open "
        f"(Vigie status: {ticket.status})."
    )
    try:
        state = connector.reopen(ref, message)
        run.reopened += 1
        return state
    except ExternalTicketClosed:
        created = connector.create(_export_of(db, ticket))
        _link(ticket, connector, created)
        _note(
            db,
            ticket,
            connector,
            f"{connector.label} ticket {ref} is closed; replaced by {created.ref}",
        )
        run.replaced += 1
        return created.state


def _finished_message(ticket: RemediationTicket) -> str:
    if ticket.status == TicketStatus.resolved.value:
        return (
            "Resolved in Vigie: the scans confirm every finding of this ticket "
            "is closed."
        )
    return f"Cancelled in Vigie: {ticket.note or 'no further action planned'}"


def _export(
    db: Session, connector: TicketConnector, run: SyncRun, now: datetime, limit: int
) -> None:
    unlinked = _unlinked(db, connector)
    if unlinked is None:
        return
    query = unlinked.order_by(RemediationTicket.id)

    seen: set[int] = set()
    for _ in range(limit):
        ticket = _next(db, query, seen)
        if ticket is None:
            return
        try:
            created = connector.create(_export_of(db, ticket))
        except ExternalTicketError as exc:
            ticket.external_error = str(exc)[:MAX_ERROR_LENGTH]
            run.errors += 1
            logger.warning(
                "%s export of ticket %s failed: %s", connector.label, ticket.id, exc
            )
        else:
            _link(ticket, connector, created)
            ticket.external_state = created.state.value
            ticket.external_error = None
            _note(
                db,
                ticket,
                connector,
                f"Exported to {connector.label} as {created.ref}",
            )
            run.exported += 1
        ticket.external_synced_at = now
        db.commit()


def _link(
    ticket: RemediationTicket, connector: TicketConnector, created: ExternalTicket
) -> None:
    ticket.external_system = connector.name
    ticket.external_ref = created.ref
    ticket.external_url = created.url
    seal_link(ticket, connector)


def _note(
    db: Session, ticket: RemediationTicket, connector: TicketConnector, note: str
) -> None:
    log_ticket_change(db, ticket, None, ticket.status, note, None, actor=connector.name)


def _export_of(db: Session, ticket: RemediationTicket) -> TicketExport:
    # The connector acts for the whole estate: the ticket's own team is the
    # only scope that matters, and its findings already say which hosts.
    hosts = action_hosts(
        db, ticket.action_id, EVERYTHING, ticket_finding_ids(db, ticket.id)
    )
    return TicketExport(
        ticket_id=ticket.id,
        title=ticket.title,
        owner_team=ticket.owner_team,
        action=ticket.action,
        metrics=ticket_metrics(db, [ticket.id]).get(ticket.id, {}),
        hosts=hosts,
    )


# --- Overview ---------------------------------------------------------------


def overview(db: Session, connector: ConnectorIdentity) -> dict:
    """Where the connector stands, for the administration screen."""
    linked = foreign = gone = errors = 0
    for ticket in db.query(RemediationTicket).filter(
        RemediationTicket.external_system == connector.name
    ):
        linked += 1
        if link_state(ticket, connector) == "foreign":
            foreign += 1
        elif ticket.external_state == ExternalState.gone.value:
            gone += 1
        elif ticket.external_error:
            errors += 1
    pending = _unlinked(db, connector)
    failed_exports = (
        pending.filter(RemediationTicket.external_error.isnot(None)).count()
        if pending is not None
        else 0
    )
    status = db.get(TicketConnectorStatus, connector.name)
    return {
        "linked": linked,
        "foreign": foreign,
        "gone": gone,
        "errors": errors + failed_exports,
        "pending_export": pending.count() if pending is not None else 0,
        "last_run_at": status.last_run_at if status else None,
        "last_success_at": status.last_success_at if status else None,
        "last_error": status.last_error if status else None,
        "last_result": status.last_result if status else None,
    }
