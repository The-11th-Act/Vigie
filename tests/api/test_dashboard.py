from app.models.asset import Asset
from app.models.vulnerability import Vulnerability, AssetVulnerability


class TestDashboard:
    def test_empty_stats(self, client):
        response = client.get("/api/v1/dashboard/stats")
        assert response.status_code == 200
        data = response.json()
        assert data["total_assets"] == 0
        assert data["total_open_vulnerabilities"] == 0
        assert data["severity_breakdown"] == {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        assert data["overdue_count"] == 0

    def test_stats_with_data(self, client, db_session):
        asset = Asset(ip_address="10.0.0.1", hostname="srv-01")
        db_session.add(asset)
        db_session.flush()

        db_session.add(Vulnerability(cve_id="CVE-2024-D1", title="Critical vuln", cvss_score=9.5, severity="Critical"))
        db_session.add(Vulnerability(cve_id="CVE-2024-D2", title="High vuln", cvss_score=7.5, severity="High"))
        db_session.flush()

        vuln1 = db_session.query(Vulnerability).filter(Vulnerability.cve_id == "CVE-2024-D1").first()
        vuln2 = db_session.query(Vulnerability).filter(Vulnerability.cve_id == "CVE-2024-D2").first()

        db_session.add(AssetVulnerability(asset_id=asset.id, vulnerability_id=vuln1.id, status="Open"))
        db_session.add(AssetVulnerability(asset_id=asset.id, vulnerability_id=vuln2.id, status="Open"))
        db_session.add(AssetVulnerability(asset_id=asset.id, vulnerability_id=vuln1.id, status="Remediated"))
        db_session.commit()

        response = client.get("/api/v1/dashboard/stats")
        assert response.status_code == 200
        data = response.json()
        assert data["total_assets"] == 1
        assert data["severity_breakdown"]["Critical"] == 1
        assert data["severity_breakdown"]["High"] == 1
        assert "Remediated" in data["status_breakdown"]


class TestHealth:
    def test_health_check(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    def test_root(self, client):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "online"
        assert "project" in data