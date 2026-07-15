from app.models.asset import Asset
from app.models.vulnerability import Vulnerability, AssetVulnerability


class TestAssetVulnerabilities:
    def test_get_asset_vulns_empty(self, client, db_session):
        asset = Asset(ip_address="10.0.0.1", hostname="srv-01")
        db_session.add(asset)
        db_session.commit()

        response = client.get(f"/api/v1/vulnerabilities/assets/{asset.id}")
        assert response.status_code == 200
        assert response.json()["total"] == 0

    def test_get_asset_vulns_with_data(self, client, db_session):
        asset = Asset(ip_address="10.0.0.2", hostname="srv-02")
        db_session.add(asset)
        db_session.flush()

        vuln = Vulnerability(cve_id="CVE-2024-AV1", title="Test", cvss_score=8.0, severity="High")
        db_session.add(vuln)
        db_session.flush()

        db_session.add(AssetVulnerability(asset_id=asset.id, vulnerability_id=vuln.id, status="Open"))
        db_session.add(AssetVulnerability(asset_id=asset.id, vulnerability_id=vuln.id, status="Remediated"))
        db_session.commit()

        response = client.get(f"/api/v1/vulnerabilities/assets/{asset.id}")
        assert response.status_code == 200
        assert response.json()["total"] == 2

    def test_filter_by_status(self, client, db_session):
        asset = Asset(ip_address="10.0.0.3", hostname="srv-03")
        db_session.add(asset)
        db_session.flush()

        vuln = Vulnerability(cve_id="CVE-2024-AV2", title="Test", cvss_score=5.0, severity="Medium")
        db_session.add(vuln)
        db_session.flush()

        db_session.add(AssetVulnerability(asset_id=asset.id, vulnerability_id=vuln.id, status="Open"))
        db_session.add(AssetVulnerability(asset_id=asset.id, vulnerability_id=vuln.id, status="Remediated"))
        db_session.commit()

        response = client.get(f"/api/v1/vulnerabilities/assets/{asset.id}?status_filter=Open")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["items"][0]["status"] == "Open"