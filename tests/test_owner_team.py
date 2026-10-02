"""Dynamic rules for assets: tags, hostname regex and subnet CIDRs."""

import pytest

from app.core.config import settings
from app.models.asset import Asset, Criticality
from app.services.asset_policy import (
    criticality_for,
    environment_for,
    exposure_for,
    owner_team_for,
)
from app.services.ingestion import ingest_findings

RULES = {"10.0.0.0/8": "Infrastructure", "10.20.0.0/16": "Workplace", "bad": "X"}


@pytest.fixture
def team_rules(monkeypatch):
    monkeypatch.setattr(settings, "OWNER_TEAM_RULES", RULES)


def finding(ip, hostname=None, tags=None):
    return {
        "ip_address": ip,
        "hostname": hostname,
        "operating_system": None,
        "cve_id": "CVE-2024-0001",
        "title": "Test",
        "description": None,
        "cvss_score": 7.0,
        "severity": "High",
        "tags": tags,
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


class TestHostnameRegexRules:
    def test_hostname_regex_assigns_team(self, monkeypatch):
        monkeypatch.setattr(
            settings,
            "OWNER_TEAM_HOSTNAME_RULES",
            {"^infra-.*": "Infrastructure", ".*-db.*": "Database"},
        )
        assert (
            owner_team_for("192.168.1.1", hostname="infra-switch-01") == "Infrastructure"
        )
        assert owner_team_for("192.168.1.1", hostname="mysql-db-prod") == "Database"
        assert owner_team_for("192.168.1.1", hostname="web-app-01") is None

    def test_hostname_regex_assigns_environment_and_criticality(self, monkeypatch):
        monkeypatch.setattr(
            settings,
            "ENVIRONMENT_HOSTNAME_RULES",
            {"^prd-.*": "production", ".*-stg.*": "staging"},
        )
        monkeypatch.setattr(
            settings,
            "CRITICALITY_HOSTNAME_RULES",
            {"^prd-.*": "Critical", ".*-dev.*": "Low"},
        )
        assert environment_for("192.168.1.1", hostname="prd-api-01") == "production"
        assert environment_for("192.168.1.1", hostname="app-stg-01") == "staging"
        assert (
            criticality_for("192.168.1.1", hostname="prd-api-01") == Criticality.critical
        )
        assert criticality_for("192.168.1.1", hostname="test-dev-box") == Criticality.low

    def test_hostname_regex_assigns_exposure(self, monkeypatch):
        monkeypatch.setattr(
            settings,
            "INTERNET_FACING_HOSTNAME_PATTERNS",
            ["^dmz-.*", r".*-ext\..*"],
        )
        assert exposure_for("10.0.0.1", hostname="dmz-proxy-01") is True
        assert exposure_for("10.0.0.1", hostname="mail-ext.example.com") is True
        assert exposure_for("10.0.0.1", hostname="internal-srv") is False

    def test_malformed_regex_is_ignored_without_crashing(self, monkeypatch):
        monkeypatch.setattr(
            settings,
            "OWNER_TEAM_HOSTNAME_RULES",
            {"[invalid(regex": "BadTeam", ".*valid.*": "GoodTeam"},
        )
        assert owner_team_for("10.1.1.1", hostname="a-valid-host") == "GoodTeam"
        assert owner_team_for("10.1.1.1", hostname="other") is None


class TestTagRules:
    def test_tag_rules_assign_team_and_env(self, monkeypatch):
        monkeypatch.setattr(
            settings,
            "OWNER_TEAM_TAG_RULES",
            {"team:infra": "Infrastructure", "workplace": "Workplace"},
        )
        monkeypatch.setattr(
            settings,
            "ENVIRONMENT_TAG_RULES",
            {"prod": "production", "staging": "staging"},
        )
        assert (
            owner_team_for("192.168.1.1", tags=["team:infra", "web"]) == "Infrastructure"
        )
        assert environment_for("192.168.1.1", tags=["prod"]) == "production"

    def test_tag_rules_assign_criticality_and_exposure(self, monkeypatch):
        monkeypatch.setattr(
            settings,
            "CRITICALITY_TAG_RULES",
            {"pci-dss": "Critical", "tier-1": "Critical"},
        )
        monkeypatch.setattr(
            settings,
            "INTERNET_FACING_TAGS",
            ["dmz", "public"],
        )
        assert criticality_for("192.168.1.1", tags=["pci-dss"]) == Criticality.critical
        assert exposure_for("10.1.1.1", tags=["dmz"]) is True
        assert exposure_for("10.1.1.1", tags=["internal"]) is False


class TestPrecedence:
    def test_tag_overrides_hostname_and_subnet(self, monkeypatch):
        monkeypatch.setattr(settings, "OWNER_TEAM_RULES", {"10.0.0.0/8": "SubnetTeam"})
        monkeypatch.setattr(
            settings, "OWNER_TEAM_HOSTNAME_RULES", {"^host-.*": "HostnameTeam"}
        )
        monkeypatch.setattr(settings, "OWNER_TEAM_TAG_RULES", {"tag-team": "TagTeam"})

        # 1. With all three present, Tag wins
        assert (
            owner_team_for("10.1.2.3", hostname="host-01", tags=["tag-team"]) == "TagTeam"
        )
        # 2. Without tag, Hostname wins over Subnet
        assert (
            owner_team_for("10.1.2.3", hostname="host-01", tags=["other-tag"])
            == "HostnameTeam"
        )
        # 3. Without matching tag or hostname, Subnet wins
        assert owner_team_for("10.1.2.3", hostname="unmatched", tags=[]) == "SubnetTeam"
        # 4. Without any match, falls back to None
        assert owner_team_for("192.168.1.1", hostname="unmatched", tags=[]) is None

    def test_criticality_precedence(self, monkeypatch):
        monkeypatch.setattr(settings, "CRITICALITY_RULES", {"10.0.0.0/8": "Low"})
        monkeypatch.setattr(settings, "CRITICALITY_HOSTNAME_RULES", {"^prd-.*": "High"})
        monkeypatch.setattr(settings, "CRITICALITY_TAG_RULES", {"pci-dss": "Critical"})

        assert criticality_for("10.1.1.1", "prd-srv", ["pci-dss"]) == Criticality.critical
        assert criticality_for("10.1.1.1", "prd-srv", []) == Criticality.high
        assert criticality_for("10.1.1.1", "dev-srv", []) == Criticality.low
        assert criticality_for("192.168.1.1", "dev-srv", []) == Criticality.medium


class TestAtIngestion:
    def test_a_new_asset_gets_its_team(self, db_session, team_rules):
        ingest_findings(db_session, [finding("10.20.0.5")], "nessus")
        assert db_session.query(Asset).one().owner_team == "Workplace"

    def test_ingestion_applies_hostname_and_tag_rules(self, db_session, monkeypatch):
        monkeypatch.setattr(
            settings, "OWNER_TEAM_HOSTNAME_RULES", {"^infra-.*": "Infrastructure"}
        )
        monkeypatch.setattr(settings, "ENVIRONMENT_TAG_RULES", {"prod": "production"})
        monkeypatch.setattr(settings, "CRITICALITY_TAG_RULES", {"vip": "Critical"})
        monkeypatch.setattr(settings, "INTERNET_FACING_TAGS", ["public"])

        ingest_findings(
            db_session,
            [
                finding(
                    "192.168.1.50",
                    hostname="infra-router-01",
                    tags=["prod", "vip", "public"],
                )
            ],
            "nessus",
        )

        asset = db_session.query(Asset).one()
        assert asset.owner_team == "Infrastructure"
        assert asset.environment == "production"
        assert asset.business_criticality == Criticality.critical
        assert asset.internet_facing is True
        assert set(asset.tags) == {"prod", "vip", "public"}

    def test_ingestion_merges_tags_from_subsequent_findings(self, db_session):
        ingest_findings(
            db_session,
            [finding("192.168.1.60", hostname="srv-01", tags=["web"])],
            "nessus",
        )
        assert db_session.query(Asset).one().tags == ["web"]

        ingest_findings(
            db_session,
            [finding("192.168.1.60", hostname="srv-01", tags=["db", "web"])],
            "nessus",
        )
        asset = db_session.query(Asset).one()
        assert set(asset.tags) == {"web", "db"}

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


class TestRuleSettings:
    """A typo in a rule refuses to start: it would otherwise disable the rule
    silently, a warning per asset at most."""

    def build(self, **values):
        from app.core.config import Settings

        return Settings(_env_file=None, SECRET_KEY="x" * 40, **values)

    @pytest.mark.parametrize(
        "name",
        [
            "CRITICALITY_HOSTNAME_RULES",
            "OWNER_TEAM_HOSTNAME_RULES",
            "ENVIRONMENT_HOSTNAME_RULES",
        ],
    )
    def test_a_malformed_regex_is_refused(self, name):
        value = "High" if name.startswith("CRITICALITY") else "Ops"
        with pytest.raises(ValueError, match="invalid regular expression"):
            self.build(**{name: {"[unclosed": value}})

    def test_a_malformed_exposure_pattern_is_refused(self):
        with pytest.raises(ValueError, match="invalid regular expression"):
            self.build(INTERNET_FACING_HOSTNAME_PATTERNS=["(dmz"])

    @pytest.mark.parametrize(
        "name", ["CRITICALITY_HOSTNAME_RULES", "CRITICALITY_TAG_RULES"]
    )
    def test_an_unknown_criticality_is_refused(self, name):
        with pytest.raises(ValueError, match="is not one of"):
            self.build(**{name: {"pci": "Urgent"}})

    def test_valid_rules_load(self):
        loaded = self.build(
            CRITICALITY_HOSTNAME_RULES={"^prd-": "critical"},
            CRITICALITY_TAG_RULES={"pci": "High"},
            INTERNET_FACING_HOSTNAME_PATTERNS=[r"\.dmz\."],
        )
        assert loaded.CRITICALITY_TAG_RULES == {"pci": "High"}
