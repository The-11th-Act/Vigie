import pytest

from app.models.asset import Asset
from app.models.vulnerability import AssetVulnerability, Status, Vulnerability


class TestAssets:
    def test_get_empty_assets(self, client):
        response = client.get("/api/v1/assets/")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["items"] == []

    def test_create_asset(self, client):
        response = client.post(
            "/api/v1/assets/",
            json={
                "ip_address": "192.168.1.10",
                "hostname": "web-server-01",
                "operating_system": "Ubuntu 22.04",
                "business_criticality": "High",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["ip_address"] == "192.168.1.10"
        assert data["hostname"] == "web-server-01"
        assert data["business_criticality"] == "High"
        assert "id" in data

    def test_create_duplicate_ip(self, client, db_session):
        db_session.add(Asset(ip_address="10.0.0.1", hostname="srv-01"))
        db_session.commit()

        response = client.post(
            "/api/v1/assets/",
            json={"ip_address": "10.0.0.1", "hostname": "srv-02"},
        )
        assert response.status_code == 409

    def test_get_asset_by_id(self, client, db_session):
        db_session.add(Asset(ip_address="10.0.0.5", hostname="srv-05"))
        db_session.commit()
        db_session.expire_all()

        asset = db_session.query(Asset).filter(Asset.ip_address == "10.0.0.5").first()
        response = client.get(f"/api/v1/assets/{asset.id}")
        assert response.status_code == 200
        assert response.json()["ip_address"] == "10.0.0.5"

    def test_get_asset_not_found(self, client):
        response = client.get("/api/v1/assets/9999")
        assert response.status_code == 404

    def test_update_asset(self, client, db_session):
        db_session.add(Asset(ip_address="10.0.0.10", hostname="srv-10"))
        db_session.commit()
        db_session.expire_all()

        asset = db_session.query(Asset).filter(Asset.ip_address == "10.0.0.10").first()
        response = client.put(
            f"/api/v1/assets/{asset.id}",
            json={"business_criticality": "Critical", "operating_system": "Windows"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["business_criticality"] == "Critical"
        assert data["operating_system"] == "Windows"

    def test_criticality_change_rescores_open_findings(self, client, db_session):
        """Risk derives from criticality; stale scores would misrank the backlog."""
        asset = Asset(ip_address="10.0.0.11")
        vuln = Vulnerability(
            cve_id="CVE-2024-6001", title="Rescore me", cvss_score=6.0, severity="Medium"
        )
        db_session.add_all([asset, vuln])
        db_session.flush()
        link = AssetVulnerability(
            asset_id=asset.id,
            vulnerability_id=vuln.id,
            status=Status.open,
            risk_score=6.0,
        )
        db_session.add(link)
        db_session.commit()

        client.put(
            f"/api/v1/assets/{asset.id}", json={"business_criticality": "Critical"}
        )

        db_session.refresh(link)
        assert link.risk_score == 9.0  # 6.0 * 1.5

    def test_delete_asset(self, client, db_session):
        db_session.add(Asset(ip_address="10.0.0.20", hostname="srv-20"))
        db_session.commit()
        db_session.expire_all()

        asset = db_session.query(Asset).filter(Asset.ip_address == "10.0.0.20").first()
        response = client.delete(f"/api/v1/assets/{asset.id}")
        assert response.status_code == 204

        db_session.expire_all()
        assert db_session.query(Asset).filter(Asset.id == asset.id).first() is None

    def test_search_assets(self, client, db_session):
        db_session.add(Asset(ip_address="192.168.1.50", hostname="web-prod-01"))
        db_session.add(Asset(ip_address="192.168.1.51", hostname="db-prod-01"))
        db_session.commit()

        response = client.get("/api/v1/assets/?search=web-prod")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["items"][0]["hostname"] == "web-prod-01"

    def test_limit_above_maximum_is_rejected(self, client):
        # The limit is now declared with le=MAX_LIMIT, so an oversized page size
        # is an explicit 422 rather than being silently clamped.
        response = client.get("/api/v1/assets/?limit=10000")
        assert response.status_code == 422

    def test_limit_at_maximum_is_accepted(self, client):
        response = client.get("/api/v1/assets/?limit=500")
        assert response.status_code == 200


class TestInternetExposure:
    def test_defaults_to_internal(self, client):
        response = client.post("/api/v1/assets/", json={"ip_address": "10.30.0.1"})
        assert response.status_code == 201
        assert response.json()["internet_facing"] is False

    def test_can_be_set_on_creation_and_update(self, client):
        created = client.post(
            "/api/v1/assets/", json={"ip_address": "10.30.0.2", "internet_facing": True}
        ).json()
        assert created["internet_facing"] is True

        updated = client.put(
            f"/api/v1/assets/{created['id']}", json={"internet_facing": False}
        )
        assert updated.status_code == 200
        assert updated.json()["internet_facing"] is False

    @pytest.mark.parametrize("field", ["internet_facing", "business_criticality"])
    def test_explicit_null_is_rejected(self, client, db_session, field):
        """Regression: a null criticality reached a NOT NULL column as a 500."""
        asset = Asset(ip_address="10.30.0.3")
        db_session.add(asset)
        db_session.commit()

        response = client.put(f"/api/v1/assets/{asset.id}", json={field: None})

        assert response.status_code == 422

    def test_exposure_change_rescores_open_findings(self, client, db_session):
        asset = Asset(ip_address="10.30.0.4")
        vuln = Vulnerability(
            cve_id="CVE-2024-6002", title="Exposed", cvss_score=5.0, severity="Medium"
        )
        db_session.add_all([asset, vuln])
        db_session.flush()
        link = AssetVulnerability(
            asset_id=asset.id,
            vulnerability_id=vuln.id,
            status=Status.open,
            risk_score=5.0,
        )
        db_session.add(link)
        db_session.commit()

        client.put(f"/api/v1/assets/{asset.id}", json={"internet_facing": True})

        db_session.refresh(link)
        assert link.risk_score == 6.0  # 5.0 x 1.2


class TestAssetTags:
    def test_create_asset_with_tags(self, client):
        response = client.post(
            "/api/v1/assets/",
            json={
                "ip_address": "10.40.0.1",
                "hostname": "tagged-srv",
                "tags": ["pci-dss", "web", "dmz"],
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["tags"] == ["pci-dss", "web", "dmz"]

    def test_update_asset_tags(self, client, db_session):
        asset = Asset(ip_address="10.40.0.2", tags=["old-tag"])
        db_session.add(asset)
        db_session.commit()

        response = client.put(
            f"/api/v1/assets/{asset.id}",
            json={"tags": ["new-tag", "production"]},
        )
        assert response.status_code == 200
        assert response.json()["tags"] == ["new-tag", "production"]

    def test_filter_assets_by_tag(self, client, db_session):
        db_session.add_all(
            [
                Asset(ip_address="10.40.0.10", tags=["prod", "web"]),
                Asset(ip_address="10.40.0.11", tags=["prod", "db"]),
                Asset(ip_address="10.40.0.12", tags=["staging"]),
            ]
        )
        db_session.commit()

        res_prod = client.get("/api/v1/assets/", params={"tag": "prod"}).json()
        assert res_prod["total"] == 2
        ips = {item["ip_address"] for item in res_prod["items"]}
        assert ips == {"10.40.0.10", "10.40.0.11"}

        res_db = client.get("/api/v1/assets/", params={"tag": "db"}).json()
        assert res_db["total"] == 1
        assert res_db["items"][0]["ip_address"] == "10.40.0.11"

    def test_a_tag_filter_matches_whole_tags_whatever_their_case(
        self, client, db_session
    ):
        db_session.add_all(
            [
                Asset(ip_address="10.40.1.1", tags=["pci_dss"]),
                Asset(ip_address="10.40.1.2", tags=["pciXdss"]),
                Asset(ip_address="10.40.1.3", tags=["PCI_DSS", "webapp"]),
                Asset(ip_address="10.40.1.4", tags=["50%-done"]),
            ]
        )
        db_session.commit()

        def ips(tag):
            items = client.get("/api/v1/assets/", params={"tag": tag}).json()["items"]
            return {item["ip_address"] for item in items}

        # _ and % are not wildcards; case is ignored, as the rules ignore it.
        assert ips("pci_dss") == {"10.40.1.1", "10.40.1.3"}
        assert ips("50%-done") == {"10.40.1.4"}
        # A whole tag, not a piece of one.
        assert ips("web") == set()
        assert ips("WEBAPP") == {"10.40.1.3"}

    def test_tags_are_kept_once_and_bounded(self, client):
        created = client.post(
            "/api/v1/assets/",
            json={"ip_address": "10.40.2.1", "tags": ["PCI", "pci", " Web ", "web"]},
        )
        assert created.status_code == 201
        assert created.json()["tags"] == ["PCI", "Web"]

        too_many = client.post(
            "/api/v1/assets/",
            json={"ip_address": "10.40.2.2", "tags": [f"t{i}" for i in range(51)]},
        )
        assert too_many.status_code == 422

    def test_dynamic_rules_evaluated_with_tags_and_hostname_on_create(
        self, client, monkeypatch
    ):
        from app.core.config import settings

        monkeypatch.setattr(
            settings,
            "CRITICALITY_TAG_RULES",
            {"pci-dss": "Critical"},
        )
        monkeypatch.setattr(
            settings,
            "OWNER_TEAM_HOSTNAME_RULES",
            {"^infra-.*": "Infrastructure"},
        )
        monkeypatch.setattr(
            settings,
            "INTERNET_FACING_TAGS",
            ["dmz"],
        )

        response = client.post(
            "/api/v1/assets/",
            json={
                "ip_address": "10.40.0.20",
                "hostname": "infra-switch-01",
                "tags": ["pci-dss", "dmz"],
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["business_criticality"] == "Critical"
        assert data["owner_team"] == "Infrastructure"
        assert data["internet_facing"] is True
