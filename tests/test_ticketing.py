"""Ticketing connector, the generic sync: against an in-memory tool.

The GLPI client itself is in tests/test_glpi.py.
"""

import pytest

from app.core.config import settings
from app.core.scope import EVERYTHING
from app.models.asset import Asset
from app.models.remediation import RemediationAction
from app.models.ticket import (
    RemediationTicket,
    TicketAuditLog,
    TicketConnectorStatus,
    TicketStatus,
)
from app.models.vulnerability import AssetVulnerability, Status
from app.parsers.utils import remediation
from app.services.ingestion import ingest_findings
from app.services.ticketing import (
    ConnectorUnavailable,
    ExternalState,
    ExternalTicket,
    ExternalTicketClosed,
    ExternalTicketError,
    link_state,
    overview,
    reseal_links,
    sync_tickets_with,
)
from app.services.tickets import create_tickets, sync_tickets

ROLLUP = remediation("kb", "KB5034127", title="January rollup")
HOSTS = {"10.0.0.1": "Servers", "10.0.0.2": "Servers", "10.0.1.1": "Workplace"}
OTHER_KEY = "another-instance-signing-key-0123456789abcdef"


class FakeTool:
    """A ticketing tool in memory, implementing the TicketConnector protocol."""

    name = "glpi"
    label = "GLPI"

    def __init__(self, target="https://glpi.test/apirest.php", teams=None):
        self.target = target
        self.teams = teams
        self.tickets: dict[str, dict] = {}
        self.calls: list[tuple] = []
        self.next_id = 100
        self.down = False
        self.refuse: set[int] = set()  # Vigie ticket ids whose creation fails
        self.sessions = 0

    def open(self):
        if self.down:
            raise ConnectorUnavailable("GLPI unreachable: connection refused")
        self.sessions += 1

    def close(self):
        self.calls.append(("close",))

    def create(self, export):
        self.calls.append(("create", export.ticket_id))
        if export.ticket_id in self.refuse:
            raise ExternalTicketError("GLPI POST Ticket: HTTP 400 ERROR_BAD_ARRAY")
        ref = str(self.next_id)
        self.next_id += 1
        self.tickets[ref] = {"state": ExternalState.open, "export": export, "notes": []}
        return ExternalTicket(ref, f"https://glpi.test/front/{ref}", ExternalState.open)

    def state(self, ref):
        self.calls.append(("state", ref))
        ticket = self.tickets.get(ref)
        return ticket["state"] if ticket else ExternalState.gone

    def solve(self, ref, message):
        self.calls.append(("solve", ref))
        self.tickets[ref]["state"] = ExternalState.solved
        self.tickets[ref]["notes"].append(message)
        return ExternalState.solved

    def reopen(self, ref, message):
        self.calls.append(("reopen", ref))
        if self.tickets[ref]["state"] == ExternalState.closed:
            raise ExternalTicketClosed(f"GLPI ticket {ref} is closed")
        self.tickets[ref]["state"] = ExternalState.in_progress
        self.tickets[ref]["notes"].append(message)
        return ExternalState.in_progress

    def made(self, kind):
        return [call for call in self.calls if call[0] == kind]


def finding(ip, cve="CVE-2024-0001"):
    return {
        "ip_address": ip,
        "hostname": None,
        "operating_system": None,
        "cve_id": cve,
        "title": "Test",
        "description": None,
        "cvss_score": 8.0,
        "severity": "High",
        "remediations": [ROLLUP],
    }


@pytest.fixture
def tickets(db_session, admin_user):
    """One ticket per team: Servers (two hosts), Workplace, and Unassigned."""
    for ip, team in HOSTS.items():
        db_session.add(Asset(ip_address=ip, owner_team=team))
    db_session.add(Asset(ip_address="10.0.9.9"))
    db_session.commit()
    ingest_findings(
        db_session,
        [finding(ip) for ip in [*HOSTS, "10.0.9.9"]],
        "nessus",
        scanned_addresses={*HOSTS, "10.0.9.9"},
    )
    action = db_session.query(RemediationAction).filter_by(reference="KB5034127").one()
    created, _ = create_tickets(db_session, action, admin_user, EVERYTHING)
    db_session.commit()
    return {ticket.owner_team: ticket for ticket in created}


@pytest.fixture
def tool():
    return FakeTool()


def history(db_session, ticket):
    return [
        (row.username, row.old_status, row.new_status, row.note)
        for row in db_session.query(TicketAuditLog)
        .filter_by(ticket_id=ticket.id)
        .order_by(TicketAuditLog.id)
    ]


def set_findings(db_session, ticket, status):
    finding_ids = [link.finding_id for link in ticket.findings]
    for row in db_session.query(AssetVulnerability).filter(
        AssetVulnerability.id.in_(finding_ids)
    ):
        row.status = status
    db_session.commit()
    sync_tickets(db_session)
    db_session.commit()


class TestExport:
    def test_every_active_ticket_is_created_once(self, db_session, tickets, tool):
        run = sync_tickets_with(db_session, tool)

        assert run.exported == 3
        servers = tickets["Servers"]
        assert servers.external_system == "glpi"
        assert servers.external_ref in tool.tickets
        assert servers.external_url.startswith("https://glpi.test/front/")
        assert servers.external_state == "open"
        assert link_state(servers, tool) == "current"
        assert history(db_session, servers)[-1] == (
            "glpi",
            None,
            "open",
            f"Exported to GLPI as {servers.external_ref}",
        )
        # The next run finds nothing to create.
        assert sync_tickets_with(db_session, tool).exported == 0
        assert len(tool.made("create")) == 3

    def test_the_export_describes_the_work(self, db_session, tickets, tool):
        sync_tickets_with(db_session, tool)

        export = tool.tickets[tickets["Servers"].external_ref]["export"]
        assert export.title == "Deploy KB5034127 — Servers"
        assert export.action.reference == "KB5034127"
        assert export.metrics["findings_open"] == 2
        assert sorted(host.ip_address for host in export.hosts) == [
            "10.0.0.1",
            "10.0.0.2",
        ]

    def test_only_the_teams_of_the_connector(self, db_session, tickets):
        tool = FakeTool(teams=frozenset({"Servers", None}))

        assert sync_tickets_with(db_session, tool).exported == 2
        assert tickets["Workplace"].external_ref is None
        assert tickets[None].external_system == "glpi"

    def test_a_ticket_linked_by_hand_is_left_alone(self, db_session, tickets, tool):
        tickets["Workplace"].external_ref = "SEC-1234"
        db_session.commit()

        assert sync_tickets_with(db_session, tool).exported == 2
        assert tickets["Workplace"].external_system is None

    def test_a_refused_ticket_does_not_stop_the_others(self, db_session, tickets, tool):
        tool.refuse.add(tickets["Servers"].id)

        run = sync_tickets_with(db_session, tool)

        assert (run.exported, run.errors) == (2, 1)
        assert tickets["Servers"].external_ref is None
        assert "HTTP 400" in tickets["Servers"].external_error
        assert overview(db_session, tool)["errors"] == 1

    def test_a_large_backlog_spreads_over_several_runs(self, db_session, tickets, tool):
        assert sync_tickets_with(db_session, tool, limit=2).exported == 2
        assert sync_tickets_with(db_session, tool, limit=2).exported == 1


class TestTheTeamWorksInTheTool:
    def test_progress_and_completion_come_back(self, db_session, tickets, tool):
        sync_tickets_with(db_session, tool)
        servers = tickets["Servers"]
        tool.tickets[servers.external_ref]["state"] = ExternalState.in_progress

        assert sync_tickets_with(db_session, tool).pulled == 1
        assert servers.status == "in_progress"
        assert history(db_session, servers)[-1][:3] == ("glpi", "open", "in_progress")

        tool.tickets[servers.external_ref]["state"] = ExternalState.solved
        sync_tickets_with(db_session, tool)
        # Done for the team; resolved only once the scans confirm it.
        assert servers.status == "deployed"

    def test_an_unchanged_tool_does_not_undo_a_change_in_vigie(
        self, db_session, tickets, tool
    ):
        sync_tickets_with(db_session, tool)
        servers = tickets["Servers"]
        servers.status = TicketStatus.deployed.value
        db_session.commit()

        assert sync_tickets_with(db_session, tool).pulled == 0
        assert servers.status == "deployed"


class TestVigieDecides:
    def test_resolved_by_the_scans_is_solved_in_the_tool_once(
        self, db_session, tickets, tool
    ):
        sync_tickets_with(db_session, tool)
        servers = tickets["Servers"]
        set_findings(db_session, servers, Status.remediated)
        assert servers.status == "resolved"

        assert sync_tickets_with(db_session, tool).solved == 1
        ticket = tool.tickets[servers.external_ref]
        assert ticket["state"] == ExternalState.solved
        assert "scans confirm" in ticket["notes"][-1]
        # Done on both sides: no longer polled.
        tool.calls.clear()
        sync_tickets_with(db_session, tool)
        assert ("state", servers.external_ref) not in tool.calls

    def test_cancelled_is_solved_with_the_reason(self, db_session, tickets, tool):
        sync_tickets_with(db_session, tool)
        workplace = tickets["Workplace"]
        workplace.status = TicketStatus.cancelled.value
        workplace.note = "Hosts decommissioned next week"
        db_session.commit()

        sync_tickets_with(db_session, tool)

        notes = tool.tickets[workplace.external_ref]["notes"]
        assert notes == ["Cancelled in Vigie: Hosts decommissioned next week"]

    def test_a_finding_coming_back_reopens_the_tool_ticket(
        self, db_session, tickets, tool
    ):
        sync_tickets_with(db_session, tool)
        servers = tickets["Servers"]
        set_findings(db_session, servers, Status.remediated)
        sync_tickets_with(db_session, tool)
        set_findings(db_session, servers, Status.open)
        assert servers.status == "open"

        assert sync_tickets_with(db_session, tool).reopened == 1
        assert tool.tickets[servers.external_ref]["state"] == ExternalState.in_progress
        assert servers.external_state == "in_progress"
        # Its own reopening is not mistaken for the team's progress.
        assert sync_tickets_with(db_session, tool).pulled == 0
        assert servers.status == "open"

    def test_a_closed_tool_ticket_is_replaced(self, db_session, tickets, tool):
        sync_tickets_with(db_session, tool)
        servers = tickets["Servers"]
        first = servers.external_ref
        set_findings(db_session, servers, Status.remediated)
        sync_tickets_with(db_session, tool)
        # GLPI closes a solved ticket on its own after a delay: not the
        # team's doing, it must not pass the reopened ticket as deployed.
        tool.tickets[first]["state"] = ExternalState.closed
        set_findings(db_session, servers, Status.open)

        run = sync_tickets_with(db_session, tool)

        assert (run.replaced, run.pulled) == (1, 0)
        assert servers.status == "open"
        assert servers.external_ref != first
        assert servers.external_state == "open"
        assert link_state(servers, tool) == "current"
        assert history(db_session, servers)[-1][3] == (
            f"GLPI ticket {first} is closed; replaced by {servers.external_ref}"
        )

    def test_a_ticket_deleted_in_the_tool_is_no_longer_synced(
        self, db_session, tickets, tool
    ):
        sync_tickets_with(db_session, tool)
        servers = tickets["Servers"]
        del tool.tickets[servers.external_ref]

        assert sync_tickets_with(db_session, tool).gone == 1
        assert servers.external_state == "gone"
        assert servers.external_error == "The GLPI ticket no longer exists"
        tool.calls.clear()
        sync_tickets_with(db_session, tool)
        assert ("state", servers.external_ref) not in tool.calls
        assert overview(db_session, tool)["gone"] == 1


class TestOneInstanceOneServer:
    def test_a_staging_restored_from_production_leaves_its_links_alone(
        self, db_session, tickets, tool, monkeypatch
    ):
        sync_tickets_with(db_session, tool)
        tool.tickets[tickets["Servers"].external_ref]["state"] = ExternalState.solved
        monkeypatch.setattr(settings, "SECRET_KEY", OTHER_KEY)
        tool.calls.clear()

        run = sync_tickets_with(db_session, tool)

        assert run.foreign == 3
        assert tool.made("state") == [] and tool.made("create") == []
        assert tickets["Servers"].status == "open"
        assert overview(db_session, tool)["foreign"] == 3

    def test_another_server_is_another_tool(self, db_session, tickets, tool):
        sync_tickets_with(db_session, tool)
        moved = FakeTool(target="https://glpi-new.test/apirest.php")

        assert sync_tickets_with(db_session, moved).foreign == 3

    def test_a_rotated_key_keeps_its_links(self, db_session, tickets, tool, monkeypatch):
        sync_tickets_with(db_session, tool)
        old_key = settings.SECRET_KEY
        monkeypatch.setattr(settings, "SECRET_KEY", OTHER_KEY)
        monkeypatch.setattr(settings, "PREVIOUS_SECRET_KEYS", {"k1": old_key})
        servers = tickets["Servers"]
        assert link_state(servers, tool) == "previous"

        assert reseal_links(db_session, tool) == 3
        assert link_state(servers, tool) == "current"

    def test_a_link_edited_in_the_database_is_foreign(self, db_session, tickets, tool):
        sync_tickets_with(db_session, tool)
        tickets["Servers"].external_ref = "1"

        assert link_state(tickets["Servers"], tool) == "foreign"


class TestRuns:
    def test_an_unreachable_tool_changes_nothing_and_says_why(
        self, db_session, tickets, tool
    ):
        tool.down = True

        run = sync_tickets_with(db_session, tool)

        assert run.error == "GLPI unreachable: connection refused"
        assert tickets["Servers"].external_ref is None
        status = db_session.get(TicketConnectorStatus, "glpi")
        assert status.last_error == run.error
        assert status.last_success_at is None

        tool.down = False
        sync_tickets_with(db_session, tool)
        assert status.last_error is None
        assert status.last_success_at is not None
        assert status.last_result["exported"] == 3

    def test_the_session_is_closed_after_a_run(self, db_session, tickets, tool):
        sync_tickets_with(db_session, tool)
        assert tool.calls[-1] == ("close",)

    def test_overview(self, db_session, tickets, tool):
        before = overview(db_session, tool)
        assert (before["linked"], before["pending_export"]) == (0, 3)

        sync_tickets_with(db_session, tool)

        after = overview(db_session, tool)
        assert (after["linked"], after["pending_export"], after["errors"]) == (3, 0, 0)
        assert after["last_result"]["exported"] == 3

    def test_with_the_production_session_settings(self, db_session, tickets, tool):
        """SessionLocal does not autoflush: each step must stand on its own."""
        db_session.autoflush = False
        sync_tickets_with(db_session, tool)
        servers = tickets["Servers"]
        tool.tickets[servers.external_ref]["state"] = ExternalState.in_progress

        sync_tickets_with(db_session, tool)

        stored = db_session.query(RemediationTicket).filter_by(id=servers.id).one()
        assert stored.status == "in_progress"
