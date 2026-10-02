from datetime import datetime
from enum import Enum

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.db.database import Base


class TicketStatus(str, Enum):
    """Where a remediation ticket stands.

    ``deployed`` is the team's word, ``resolved`` the scanners': a ticket is
    resolved only once every finding it holds is closed, and reopens if one
    comes back. Stored as a plain string, like remediation kinds.
    """

    open = "open"
    in_progress = "in_progress"
    deployed = "deployed"  # the team says it is done, awaiting a scan to confirm
    resolved = "resolved"  # confirmed: every finding closed
    cancelled = "cancelled"  # decided not to do: its findings are untracked again


ACTIVE_TICKET_STATUSES = {
    TicketStatus.open.value,
    TicketStatus.in_progress.value,
    TicketStatus.deployed.value,
}
# What a person may set; resolution is reserved to the scans.
USER_TICKET_STATUSES = ACTIVE_TICKET_STATUSES | {TicketStatus.cancelled.value}


class RemediationTicket(Base):
    """One fix to deploy, for one team, on the findings it closes.

    Tickets are split by the team owning the hosts: a rollup concerning the
    workstation and the server teams is two pieces of work with two owners.
    """

    __tablename__ = "remediation_tickets"

    id: Mapped[int] = mapped_column(primary_key=True)
    action_id: Mapped[int] = mapped_column(
        ForeignKey("remediation_actions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # None: hosts no team owns yet.
    owner_team: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16),
        default=TicketStatus.open.value,
        server_default=TicketStatus.open.value,
        nullable=False,
        index=True,
    )
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Filled by a ticketing connector (app/services/ticketing.py), or by hand.
    external_system: Mapped[str | None] = mapped_column(String(32), nullable=True)
    external_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    external_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # Connector links only. The seal binds the link to this instance and to
    # the connector's server: a staging restored from production does not
    # touch production's tickets. The state is the external ticket's as last
    # seen or set (ExternalState), to tell its own changes from Vigie's.
    external_seal: Mapped[str | None] = mapped_column(String(128), nullable=True)
    external_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    external_synced_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    external_error: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    action = relationship("RemediationAction")
    creator = relationship("User")
    findings = relationship(
        "TicketFinding", back_populates="ticket", cascade="all, delete-orphan"
    )


class TicketFinding(Base):
    """A finding a ticket closes. It stays linked once closed: that is what
    lets the ticket reopen when the finding comes back."""

    __tablename__ = "ticket_findings"

    __table_args__ = (
        UniqueConstraint("ticket_id", "finding_id", name="uq_ticket_finding"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_id: Mapped[int] = mapped_column(
        ForeignKey("remediation_tickets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("asset_vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    ticket = relationship("RemediationTicket", back_populates="findings")


class TicketAuditLog(Base):
    """Append-only trail of a ticket: who moved it, when, and why."""

    __tablename__ = "ticket_audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    ticket_id: Mapped[int] = mapped_column(
        ForeignKey("remediation_tickets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[int | None] = mapped_column(nullable=True)
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    old_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    new_status: Mapped[str] = mapped_column(String(16), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class TicketConnectorStatus(Base):
    """Last run of a ticketing connector, for the administration screen.

    One row per connector, written by the worker: the API, which holds none
    of the connector's credentials, can only report what the last run saw.
    """

    __tablename__ = "ticket_connector_status"

    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_success_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Counters of the last run (exported, pulled, pushed...).
    last_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
