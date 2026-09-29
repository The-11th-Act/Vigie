"""Team in charge of each asset, from OWNER_TEAM_RULES or set by hand."""

import pytest

from app.core.config import settings
from app.models.asset import Asset
from app.services.asset_policy import criticality_for, owner_team_for
from app.services.ingestion import ingest_findings

RULES = {"10.0.0.0/8": "Infrastructure", "10.20.0.0/16": "Workplace", "bad": "X"}


@pytest.fixture
def team_rules(monkeypatch):
    monkeypatch.setattr(settings, "OWNER_TEAM_RULES", RULES)


def finding(ip):
    return {
        "ip_address": ip,
        "hostname": None,
        "operating_system": None,
        "cve_id": "CVE-2024-0001",
        "title": "Test",
        "description": None,
        "cvss_score": 7.0,
        "severity": "High",
    }


class TestRules:
    def test_the_most_specific_subnet_wins(self, team_rules):
        assert owner_team_for("10.1.2.3") == "Infrastructure"
        assert owner_team_for("10.20.1.1") == "Workplace"

    def test_unmatched_or_unparseable_means_unassigned(self, team_rules):
        assert owner_team_for("192.168.1.1") is None
        assert owner_team_for("not-an-ip") is None
        assert owner_team_for(None) is None

    def test_without_rules_nobody_is_assigned(self):
        assert owner_team_for("10.1.2.3") is None

    def test_criticality_rules_still_work(self, monkeypatch):
        """Both maps now share one lookup."""
        monkeypatch.setattr(
            settings,
            "CRITICALITY_RULES",
            {"10.0.0.0/8": "Low", "10.0.5.0/24": "Critical"},
        )
        assert criticality_for("10.0.5.9").value == "Critical"
        assert criticality_for("10.9.9.9").value == "Low"


class TestAtIngestion:
    def test_a_new_asset_gets_its_team(self, db_session, team_rules):
        ingest_findings(db_session, [finding("10.20.0.5")], "nessus")
        assert db_session.query(Asset).one().owner_team == "Workplace"

    def test_a_known_asset_without_team_gets_one(self, db_session, team_rules):
        db_session.add(Asset(ip_address="10.1.0.1"))
        db_session.commit()

        ingest_findings(db_session, [finding("10.1.0.1")], "nessus")

        assert db_session.query(Asset).one().owner_team == "Infrastructure"

    def test_a_team_set_by_hand_is_never_overwritten(self, db_session, team_rules):
        db_session.add(Asset(ip_address="10.1.0.1", owner_team="DBA"))
        db_session.commit()

        ingest_findings(db_session, [finding("10.1.0.1")], "nessus")

        assert db_session.query(Asset).one().owner_team == "DBA"


class TestApi:
    def test_a_created_asset_follows_the_rules(self, client, team_rules):
        response = client.post("/api/v1/assets/", json={"ip_address": "10.20.3.3"})
        assert response.json()["owner_team"] == "Workplace"

    def test_an_explicit_team_wins(self, client, team_rules):
        response = client.post(
            "/api/v1/assets/", json={"ip_address": "10.20.3.4", "owner_team": " DBA "}
        )
        assert response.json()["owner_team"] == "DBA"

    def test_it_can_be_changed_and_cleared(self, client, db_session):
        asset = Asset(ip_address="10.5.5.5", owner_team="DBA")
        db_session.add(asset)
        db_session.commit()

        response = client.put(f"/api/v1/assets/{asset.id}", json={"owner_team": "Web"})
        assert response.json()["owner_team"] == "Web"
        response = client.put(f"/api/v1/assets/{asset.id}", json={"owner_team": ""})
        assert response.json()["owner_team"] is None

    def test_assets_filter_by_team(self, client, db_session):
        db_session.add_all(
            [
                Asset(ip_address="10.6.0.1", owner_team="DBA"),
                Asset(ip_address="10.6.0.2", owner_team="Web"),
            ]
        )
        db_session.commit()

        items = client.get("/api/v1/assets/", params={"owner_team": "DBA"}).json()[
            "items"
        ]
        assert [item["ip_address"] for item in items] == ["10.6.0.1"]
