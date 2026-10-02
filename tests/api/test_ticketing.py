"""Administration of the ticketing connector, and the links it owns."""

import pytest

from app.core.config import settings
from app.core.scope import EVERYTHING
from app.core.security import decode_token, require_admin
from app.main import app
from app.models.asset import Asset
from app.models.remediation import RemediationAction
from app.models.ticket import TicketConnectorStatus
from app.parsers.utils import remediation
from app.services.glpi import glpi_identity
from app.services.ingestion import ingest_findings
from app.services.ticketing import seal_link
from app.services.tickets import create_tickets
from app.worker import tasks
from tests.conftest import _make_user

URL = "https://glpi.example.com/apirest.php"
STATUS = "/api/v1/admin/ticketing/"


@pytest.fixture
def ticket(db_session, admin_user):
    db_session.add(Asset(ip_address="10.0.0.1", owner_team="Servers"))
    db_session.commit()
    ingest_findings(
        db_session,
        [
            {
                "ip_address": "10.0.0.1",
                "hostname": None,
                "operating_system": None,
                "cve_id": "CVE-2024-0001",
                "title": "Test",
                "description": None,
                "cvss_score": 8.0,
                "severity": "High",
                "remediations": [remediation("kb", "KB5034127")],
            }
        ],
        "nessus",
    )
    action = db_session.query(RemediationAction).one()
    (created,), _ = create_tickets(db_session, action, admin_user, EVERYTHING)
    db_session.commit()
    return created


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr(settings, "GLPI_URL", URL)


def link(db_session, ticket, ref="42"):
    """As the connector links a ticket."""
    ticket.external_system = "glpi"
    ticket.external_ref = ref
    ticket.external_url = f"https://glpi.example.com/front/ticket.form.php?id={ref}"
    ticket.external_state = "open"
    seal_link(ticket, glpi_identity())
    db_session.commit()


class TestStatus:
    def test_not_configured(self, client):
        body = client.get(STATUS).json()

        assert (body["connector"], body["enabled"], body["configured"]) == (
            "glpi",
            False,
            False,
        )
        assert body["linked"] == 0 and body["last_run_at"] is None

    def test_what_the_last_run_saw(self, client, db_session, ticket, configured):
        link(db_session, ticket)
        db_session.add(
            TicketConnectorStatus(
                name="glpi", last_error="GLPI refused the session (HTTP 401)"
            )
        )
        db_session.commit()

        body = client.get(STATUS).json()

        assert body["configured"] is True
        assert body["url"] == URL
        assert (body["linked"], body["foreign"], body["pending_export"]) == (1, 0, 0)
        assert body["last_error"] == "GLPI refused the session (HTTP 401)"

    def test_a_link_from_another_instance_is_counted_apart(
        self, client, db_session, ticket, configured, monkeypatch
    ):
        link(db_session, ticket)
        monkeypatch.setattr(
            settings, "SECRET_KEY", "another-instance-key-0123456789abcdef"
        )

        assert client.get(STATUS).json()["foreign"] == 1

    def test_admins_only(self, client, db_session):
        user = _make_user(db_session, "analyst-1", "analyst")
        app.dependency_overrides.pop(require_admin, None)
        app.dependency_overrides[decode_token] = lambda: {
            "sub": str(user.id),
            "role": "analyst",
            "username": user.username,
        }

        assert client.get(STATUS).status_code == 403
        assert client.post(STATUS + "sync").status_code == 403


class TestSyncNow:
    def test_refused_while_the_sync_is_disabled(self, client):
        assert client.post(STATUS + "sync").status_code == 409

    def test_queued_for_the_worker(self, client, configured, monkeypatch):
        monkeypatch.setattr(settings, "GLPI_SYNC_ENABLED", True)
        queued = []

        class Result:
            id = "task-1"

        def apply_async(**kwargs):
            queued.append(kwargs)
            return Result()

        monkeypatch.setattr(tasks.sync_glpi_task, "apply_async", apply_async)

        response = client.post(STATUS + "sync")

        assert response.status_code == 202
        assert response.json() == {"task_id": "task-1"}
        assert len(queued) == 1

    def test_an_unavailable_queue_is_a_503(self, client, configured, monkeypatch):
        monkeypatch.setattr(settings, "GLPI_SYNC_ENABLED", True)

        def apply_async(**kwargs):
            raise ConnectionError("redis down")

        monkeypatch.setattr(tasks.sync_glpi_task, "apply_async", apply_async)

        response = client.post(STATUS + "sync")

        assert response.status_code == 503
        assert "redis" not in response.text


class TestLinksOwnedByTheConnector:
    def path(self, ticket):
        return f"/api/v1/remediation/tickets/{ticket.id}"

    def test_shown_with_their_sync_state(self, client, db_session, ticket, configured):
        link(db_session, ticket)
        ticket.external_error = "GLPI PUT Ticket/42: HTTP 403"
        db_session.commit()

        item = client.get("/api/v1/remediation/tickets").json()["items"][0]

        assert (item["external_system"], item["external_ref"]) == ("glpi", "42")
        assert item["external_state"] == "open"
        assert item["external_error"] == "GLPI PUT Ticket/42: HTTP 403"

    def test_cannot_be_edited_by_hand(self, client, db_session, ticket, configured):
        link(db_session, ticket)

        response = client.patch(self.path(ticket), json={"external_ref": "43"})

        assert response.status_code == 409
        assert ticket.external_ref == "42"

    def test_the_screen_resending_them_unchanged_is_fine(
        self, client, db_session, ticket, configured
    ):
        link(db_session, ticket)

        response = client.patch(
            self.path(ticket),
            json={
                "status": "in_progress",
                "external_ref": "42",
                "external_url": ticket.external_url,
            },
        )

        assert response.status_code == 200, response.text
        assert response.json()["status"] == "in_progress"

    def test_a_hand_written_link_cannot_pass_for_one(self, client, ticket):
        response = client.patch(
            self.path(ticket), json={"external_system": "glpi", "external_ref": "42"}
        )

        assert response.status_code == 422
        assert ticket.external_system is None

    def test_other_links_stay_editable(self, client, ticket):
        response = client.patch(
            self.path(ticket), json={"external_system": "jira", "external_ref": "SEC-1"}
        )

        assert response.status_code == 200
        assert response.json()["external_ref"] == "SEC-1"
