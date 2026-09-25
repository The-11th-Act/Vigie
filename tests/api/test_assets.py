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
