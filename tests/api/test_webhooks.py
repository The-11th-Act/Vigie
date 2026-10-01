"""Administration of webhooks, and the ticket events they receive."""

import json

import pytest

from app.core.config import settings
from app.models.asset import Asset
from app.models.vulnerability import AssetVulnerability
from app.models.webhook import DeliveryStatus, Webhook, WebhookDelivery
from tests.api import test_tickets
from tests.api.test_tickets import by_team, create

# The ticket tests' estate and role switch, shared rather than copied.
estate = test_tickets.estate
act_as = test_tickets.act_as

BASE = "/api/v1/admin/webhooks/"
OTHER_KEY = "another-instance-signing-key-0123456789abcdef"


def register(client, events=("ticket.created", "ticket.status_changed"), **fields):
    body = {
        "name": "SOC",
        "url": "https://hooks.example.com/vigie",
        "events": list(events),
        **fields,
    }
    return client.post(BASE, json=body)


def events_of(db_session, event):
    return [
        json.loads(row.body)["data"]
        for row in db_session.query(WebhookDelivery)
        .filter_by(event=event)
        .order_by(WebhookDelivery.id)
    ]


class TestAdministration:
    def test_the_secret_is_shown_once(self, client):
        created = register(client)
        assert created.status_code == 201, created.text
        assert created.json()["secret"].startswith("whsec_")
        assert created.json()["usable"] is True

        (listed,) = client.get(BASE).json()
        assert "secret" not in listed
        assert listed["events"] == ["ticket.created", "ticket.status_changed"]

    @pytest.mark.parametrize(
        "fields",
        [
            {"url": "http://hooks.example.com/x"},
            {"url": "https://127.0.0.1/x"},
            {"events": []},
            {"events": ["scan.exploded"]},
            {"name": "  "},
        ],
    )
    def test_refuses_what_could_never_work(self, client, fields):
        assert register(client, **fields).status_code == 422

    def test_the_known_events(self, client):
        names = [event["name"] for event in client.get(BASE + "events").json()]
        assert "ticket.status_changed" in names and "scan.completed" in names

    def test_admins_only(self, client, act_as):
        act_as("analyst")
        assert client.get(BASE).status_code == 403
        assert register(client).status_code == 403

    def test_edit_ping_and_delete(self, client, db_session):
        webhook_id = register(client).json()["id"]

        response = client.patch(
            f"{BASE}{webhook_id}", json={"events": ["scan.failed"], "enabled": True}
        )
        assert response.status_code == 200, response.text
        assert response.json()["events"] == ["scan.failed"]

        assert client.post(f"{BASE}{webhook_id}/ping").status_code == 202
        (ping,) = client.get(f"{BASE}{webhook_id}/deliveries").json()
        assert (ping["event"], ping["status"]) == ("ping", "pending")
        assert client.get(BASE).json()[0]["pending"] == 1

        assert client.delete(f"{BASE}{webhook_id}").status_code == 204
        assert client.get(BASE).json() == []
        assert db_session.query(WebhookDelivery).count() == 0

    def test_only_an_abandoned_delivery_is_sent_again(self, client, db_session):
        webhook_id = register(client).json()["id"]
        client.post(f"{BASE}{webhook_id}/ping")
        delivery = db_session.query(WebhookDelivery).one()
        url = f"{BASE}{webhook_id}/deliveries/{delivery.id}/retry"

        assert client.post(url).status_code == 409

        delivery.status = DeliveryStatus.failed.value
        delivery.attempts = 7
        db_session.commit()
        retried = client.post(url).json()
        assert (retried["status"], retried["attempts"]) == ("pending", 0)

    def test_a_webhook_of_another_instance_is_inert_until_adopted(
        self, client, db_session, monkeypatch
    ):
        """Staging restored from production: production's webhooks are there,
        sealed by production's key."""
        created = register(client).json()
        monkeypatch.setattr(settings, "SECRET_KEY", OTHER_KEY)

        assert client.get(BASE).json()[0]["usable"] is False
        url = f"{BASE}{created['id']}"
        assert client.patch(url, json={"name": "Mine"}).status_code == 409
        assert client.post(url + "/ping").status_code == 409

        adopted = client.post(url + "/rotate-secret").json()
        assert adopted["usable"] is True
        assert adopted["secret"] != created["secret"]


class TestTicketEvents:
    def test_creation_and_moves_are_sent(self, client, db_session, estate):
        register(client)

        create(client, estate)
        servers = by_team(client)["Servers"]
        client.patch(
            f"/api/v1/remediation/tickets/{servers['id']}",
            json={"status": "in_progress", "note": "Change approved"},
        )
        # A note alone is not a move.
        client.patch(
            f"/api/v1/remediation/tickets/{servers['id']}", json={"note": "Tonight"}
        )

        created = events_of(db_session, "ticket.created")
        assert {event["ticket"]["owner_team"] for event in created} == {
            "Servers",
            "Workplace",
            None,
        }
        (moved,) = events_of(db_session, "ticket.status_changed")
        assert moved["ticket"]["status"] == "in_progress"
        assert moved["ticket"]["previous_status"] == "open"
        assert moved["ticket"]["action"]["reference"] == "KB5034127"
        assert (moved["actor"], moved["note"]) == ("admin", "Change approved")

    def test_a_resolution_by_the_scans_is_sent(self, client, db_session, estate):
        create(client, estate)
        register(client, events=["ticket.status_changed"])
        for link in (
            db_session.query(AssetVulnerability)
            .join(AssetVulnerability.asset)
            .filter(Asset.owner_team == "Workplace")
        ):
            client.patch(
                f"/api/v1/vulnerabilities/findings/{link.id}",
                json={"status": "Remediated"},
            )

        (resolved,) = events_of(db_session, "ticket.status_changed")
        assert resolved["ticket"]["status"] == "resolved"
        assert resolved["actor"] == "system"

    def test_nothing_is_queued_without_a_webhook(self, client, db_session, estate):
        create(client, estate)
        assert db_session.query(Webhook).count() == 0
        assert db_session.query(WebhookDelivery).count() == 0
