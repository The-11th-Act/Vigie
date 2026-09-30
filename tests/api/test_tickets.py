"""Remediation tickets: one fix per team, kept honest by the scans."""

import csv
import io

import pytest

from app.core.config import settings
from app.core.security import decode_token, require_admin
from app.main import app
from app.models.asset import Asset
from app.models.remediation import RemediationAction
from app.models.ticket import RemediationTicket, TicketFinding
from app.models.vulnerability import AssetVulnerability
from app.parsers.utils import remediation
from app.services.ingestion import ingest_findings
from tests.conftest import _make_user

ROLLUP = remediation("kb", "KB5034127", title="January rollup")
HOSTS = {"10.0.0.1": "Servers", "10.0.0.2": "Servers", "10.0.1.1": "Workplace"}


def finding(ip, cve="CVE-2024-0001", fixes=(ROLLUP,), cvss=8.0):
    return {
        "ip_address": ip,
        "hostname": None,
        "operating_system": None,
        "cve_id": cve,
        "title": "Test",
        "description": None,
        "cvss_score": cvss,
        "severity": "High",
        "remediations": list(fixes),
    }


@pytest.fixture
def estate(db_session):
    """Two server hosts, a workstation, and one host nobody owns."""
    for ip, team in HOSTS.items():
        db_session.add(Asset(ip_address=ip, owner_team=team))
    db_session.add(Asset(ip_address="10.0.9.9"))
    db_session.commit()
    ingest_findings(
        db_session,
        [finding(ip) for ip in [*HOSTS, "10.0.9.9"]]
        + [finding("10.0.0.1", cve="CVE-2024-0002")],
        "nessus",
        scanned_addresses={*HOSTS, "10.0.9.9"},
    )
    return db_session.query(RemediationAction).filter_by(reference="KB5034127").one()


def create(client, action):
    return client.post(f"/api/v1/remediation/actions/{action.id}/tickets")


def tickets(client, **params):
    response = client.get("/api/v1/remediation/tickets", params=params)
    assert response.status_code == 200, response.text
    return response.json()["items"]


def by_team(client, **params):
    return {ticket["owner_team"]: ticket for ticket in tickets(client, **params)}


@pytest.fixture
def act_as(client, db_session):
    def switch(role):
        user = _make_user(db_session, f"t-{role}", role)
        app.dependency_overrides.pop(require_admin, None)
        app.dependency_overrides[decode_token] = lambda: {
            "sub": str(user.id),
            "role": role,
            "username": user.username,
        }
        return user

    return switch


class TestCreation:
    def test_one_ticket_per_team_owning_the_hosts(self, client, estate):
        response = create(client, estate)

        assert response.status_code == 201
        created = {t["owner_team"]: t for t in response.json()["created"]}
        assert set(created) == {"Servers", "Workplace", None}
        assert created["Servers"]["title"] == "Deploy KB5034127 — Servers"
        assert created[None]["title"] == "Deploy KB5034127 — Unassigned"
        servers = created["Servers"]["metrics"]
        assert (servers["findings_open"], servers["hosts_open"]) == (3, 2)
        assert created["Servers"]["created_by_username"] == "admin"

    def test_twice_is_a_conflict(self, client, estate):
        create(client, estate)
        assert create(client, estate).status_code == 409

    def test_the_fix_says_how_much_is_tracked(self, client, estate):
        create(client, estate)
        [item] = client.get("/api/v1/remediation/actions").json()["items"]
        assert item["tracked"] == item["findings"] == 5

    def test_a_new_team_gets_its_own_ticket_the_others_keep_theirs(
        self, client, db_session, estate
    ):
        create(client, estate)
        db_session.add(Asset(ip_address="10.0.2.1", owner_team="OT"))
        db_session.commit()
        ingest_findings(db_session, [finding("10.0.2.1")], "nessus")

        response = create(client, estate)

        assert [t["owner_team"] for t in response.json()["created"]] == ["OT"]
        assert len(tickets(client)) == 4


class TestFollowingTheScans:
    def test_a_new_host_of_the_team_joins_its_ticket(self, client, db_session, estate):
        create(client, estate)
        db_session.add(Asset(ip_address="10.0.0.3", owner_team="Servers"))
        db_session.commit()

        ingest_findings(db_session, [finding("10.0.0.3")], "nessus")

        assert by_team(client)["Servers"]["metrics"]["hosts_open"] == 3

    def test_resolved_once_every_finding_is_closed(self, client, db_session, estate):
        create(client, estate)
        for link in (
            db_session.query(AssetVulnerability)
            .join(AssetVulnerability.asset)
            .filter(Asset.owner_team == "Workplace")
        ):
            response = client.patch(
                f"/api/v1/vulnerabilities/findings/{link.id}",
                json={"status": "Remediated"},
            )
            assert response.status_code == 200

        workplace = by_team(client, status="all")["Workplace"]
        assert workplace["status"] == "resolved"
        assert workplace["resolved_at"] is not None
        assert "Workplace" not in by_team(client)  # no longer active

    def test_scans_resolve_and_reopen_it(self, client, db_session, estate, monkeypatch):
        """The production session does not autoflush: statuses changed by the
        ingestion must still be seen by the ticket sync."""
        monkeypatch.setattr(settings, "AUTO_REMEDIATE_AFTER_MISSES", 1)
        create(client, estate)
        db_session.autoflush = False
        try:
            # The workstation comes back clean: its finding closes.
            ingest_findings(db_session, [], "nessus", scanned_addresses={"10.0.1.1"})
            assert by_team(client, status="all")["Workplace"]["status"] == "resolved"

            # And the fix is undone: the finding, and its ticket, reopen.
            ingest_findings(db_session, [finding("10.0.1.1")], "nessus")
            assert by_team(client)["Workplace"]["status"] == "open"
        finally:
            db_session.autoflush = True

        history = client.get(
            f"/api/v1/remediation/tickets/{by_team(client)['Workplace']['id']}"
        ).json()["history"]
        assert [entry["new_status"] for entry in history] == [
            "open",
            "resolved",
            "open",
        ]
        assert history[0]["username"] == "system"

    def test_an_accepted_risk_counts_as_closed(self, client, db_session, estate):
        create(client, estate)
        [link] = (
            db_session.query(AssetVulnerability)
            .join(AssetVulnerability.asset)
            .filter(Asset.owner_team == "Workplace")
            .all()
        )
        client.patch(
            f"/api/v1/vulnerabilities/findings/{link.id}",
            json={"status": "Risk Accepted", "status_note": "Isolated kiosk."},
        )
        assert by_team(client, status="all")["Workplace"]["status"] == "resolved"


class TestAHostChangingTeam:
    """A finding follows its host to its new team's ticket: the old team no
    longer sees the host (scopes), the new one would not see the work."""

    def _move(self, client, db_session, ip, team):
        asset = db_session.query(Asset).filter_by(ip_address=ip).one()
        response = client.put(f"/api/v1/assets/{asset.id}", json={"owner_team": team})
        assert response.status_code == 200, response.text

    def test_it_joins_the_new_team_ticket(self, client, db_session, estate):
        create(client, estate)

        self._move(client, db_session, "10.0.0.2", "Workplace")

        teams = by_team(client)
        assert teams["Servers"]["metrics"]["hosts_open"] == 1
        assert teams["Workplace"]["metrics"]["hosts_open"] == 2
        history = client.get(
            f"/api/v1/remediation/tickets/{teams['Servers']['id']}"
        ).json()["history"]
        assert history[0]["username"] == "system"
        assert "Workplace" in history[0]["note"]

    def test_a_ticket_left_empty_is_cancelled(self, client, db_session, estate):
        create(client, estate)

        self._move(client, db_session, "10.0.1.1", "Servers")

        workplace = by_team(client, status="all")["Workplace"]
        assert workplace["status"] == "cancelled"
        assert by_team(client)["Servers"]["metrics"]["hosts_open"] == 3

    def test_without_a_ticket_there_it_waits_to_be_ticketed(
        self, client, db_session, estate
    ):
        create(client, estate)

        self._move(client, db_session, "10.0.0.2", "Lab")

        assert by_team(client)["Servers"]["metrics"]["hosts_open"] == 1
        assert "Lab" not in by_team(client)
        assert create(client, estate).status_code == 201
        assert by_team(client)["Lab"]["metrics"]["hosts_open"] == 1

    def test_a_closed_finding_stays_with_the_team_that_fixed_it(
        self, client, db_session, estate
    ):
        create(client, estate)
        asset = db_session.query(Asset).filter_by(ip_address="10.0.0.2").one()
        [finding_row] = db_session.query(AssetVulnerability).filter_by(asset_id=asset.id)
        client.patch(
            f"/api/v1/vulnerabilities/findings/{finding_row.id}",
            json={"status": "Remediated"},
        )

        self._move(client, db_session, "10.0.0.2", "Workplace")

        servers = by_team(client)["Servers"]
        assert servers["metrics"]["hosts_total"] == 2
        assert servers["metrics"]["hosts_open"] == 1


class TestMovingATicket:
    def ticket(self, client, estate, team="Servers"):
        create(client, estate)
        return by_team(client)[team]

    def patch(self, client, ticket, **body):
        return client.patch(f"/api/v1/remediation/tickets/{ticket['id']}", json=body)

    def test_a_remediator_moves_it_along(self, client, act_as, estate):
        ticket = self.ticket(client, estate)
        act_as("remediator")

        assert self.patch(client, ticket, status="in_progress").status_code == 200
        response = self.patch(
            client, ticket, status="deployed", note="Pushed with SCCM, wave 1."
        )

        assert response.json()["status"] == "deployed"
        assert response.json()["note"] == "Pushed with SCCM, wave 1."

    def test_nobody_resolves_it_by_hand(self, client, estate):
        ticket = self.ticket(client, estate)
        assert self.patch(client, ticket, status="resolved").status_code == 422

    def test_cancelling_is_an_analyst_decision(self, client, act_as, estate):
        ticket = self.ticket(client, estate)
        act_as("remediator")
        response = self.patch(client, ticket, status="cancelled", note="Not needed.")
        assert response.status_code == 403

    def test_cancelling_needs_a_reason(self, client, estate):
        ticket = self.ticket(client, estate)
        assert self.patch(client, ticket, status="cancelled").status_code == 422

    def test_a_cancelled_ticket_frees_its_findings(self, client, estate):
        ticket = self.ticket(client, estate)
        response = self.patch(
            client, ticket, status="cancelled", note="Hosts decommissioned next week."
        )
        assert response.json()["status"] == "cancelled"
        assert self.patch(client, ticket, status="open").status_code == 409

        created = create(client, estate).json()["created"]
        assert [t["owner_team"] for t in created] == ["Servers"]

    def test_the_external_reference_is_recorded(self, client, estate):
        ticket = self.ticket(client, estate)
        response = self.patch(
            client,
            ticket,
            external_system="jira",
            external_ref="SEC-1234",
            external_url="https://jira.example.com/browse/SEC-1234",
        )
        assert response.json()["external_ref"] == "SEC-1234"

    def test_only_web_links(self, client, estate):
        ticket = self.ticket(client, estate)
        response = self.patch(client, ticket, external_url="javascript:alert(1)")
        assert response.status_code == 422


class TestReading:
    def test_a_ticket_shows_only_its_team_hosts(self, client, estate):
        create(client, estate)
        ticket = by_team(client)["Servers"]

        body = client.get(f"/api/v1/remediation/tickets/{ticket['id']}").json()

        assert {host["ip_address"] for host in body["hosts"]} == {"10.0.0.1", "10.0.0.2"}
        assert body["action"]["reference"] == "KB5034127"

    def test_its_hosts_export(self, client, estate):
        create(client, estate)
        ticket = by_team(client)["Workplace"]

        response = client.get(f"/api/v1/remediation/tickets/{ticket['id']}/hosts.csv")

        _, *rows = csv.reader(io.StringIO(response.content.decode("utf-8-sig")))
        assert [row[1] for row in rows] == ["10.0.1.1"]

    def test_the_most_risk_left_comes_first(self, client, estate):
        create(client, estate)
        assert [t["owner_team"] for t in tickets(client)][0] == "Servers"

    def test_filters(self, client, estate):
        create(client, estate)
        assert [t["owner_team"] for t in tickets(client, owner_team="Workplace")] == [
            "Workplace"
        ]
        assert [
            t["owner_team"] for t in tickets(client, owner_team="__unassigned__")
        ] == [None]
        assert tickets(client, status="resolved") == []
        response = client.get("/api/v1/remediation/tickets", params={"status": "nope"})
        assert response.status_code == 422

    def test_the_teams(self, client, estate):
        response = client.get("/api/v1/remediation/teams")
        assert response.json()["teams"] == ["Servers", "Workplace"]

    def test_deleting_a_host_keeps_the_ticket_and_its_history(
        self, client, db_session, estate
    ):
        create(client, estate)
        db_session.delete(db_session.query(Asset).filter_by(ip_address="10.0.9.9").one())
        db_session.commit()

        ticket = db_session.query(RemediationTicket).filter_by(owner_team=None).one()
        assert db_session.query(TicketFinding).filter_by(ticket_id=ticket.id).count() == 0
        body = client.get(f"/api/v1/remediation/tickets/{ticket.id}").json()
        assert body["hosts"] == []
        assert len(body["history"]) == 1
