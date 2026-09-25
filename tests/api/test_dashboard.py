from datetime import UTC, datetime, timedelta

from app.models.asset import Asset
from app.models.vulnerability import AssetVulnerability, Vulnerability


class TestDashboard:
    def test_empty_stats(self, client):
        response = client.get("/api/v1/dashboard/stats")
        assert response.status_code == 200
        data = response.json()
        assert data["total_assets"] == 0
        assert data["total_open_vulnerabilities"] == 0
        assert data["severity_breakdown"] == {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
        }
        assert data["overdue_count"] == 0

    def test_stats_with_data(self, client, db_session):
        asset = Asset(ip_address="10.0.0.1", hostname="srv-01")
        db_session.add(asset)
        db_session.flush()

        db_session.add(
            Vulnerability(
                cve_id="CVE-2024-D1",
                title="Critical vuln",
                cvss_score=9.5,
                severity="Critical",
            )
        )
        db_session.add(
            Vulnerability(
                cve_id="CVE-2024-D2", title="High vuln", cvss_score=7.5, severity="High"
            )
        )
        db_session.flush()

        vuln1 = (
            db_session.query(Vulnerability)
            .filter(Vulnerability.cve_id == "CVE-2024-D1")
            .first()
        )
        vuln2 = (
            db_session.query(Vulnerability)
            .filter(Vulnerability.cve_id == "CVE-2024-D2")
            .first()
        )

        db_session.add(
            AssetVulnerability(
                asset_id=asset.id, vulnerability_id=vuln1.id, status="Open"
            )
        )
        db_session.add(
            AssetVulnerability(
                asset_id=asset.id, vulnerability_id=vuln2.id, status="Open"
            )
        )
        db_session.commit()

        response = client.get("/api/v1/dashboard/stats")
        assert response.status_code == 200
        data = response.json()
        assert data["total_assets"] == 1
        assert data["severity_breakdown"]["Critical"] == 1
        assert data["severity_breakdown"]["High"] == 1
        assert data["total_open_vulnerabilities"] == 2


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


class TestThreatContextOnTheDashboard:
    def seed(self, db_session):
        asset = Asset(ip_address="10.60.0.1", internet_facing=True)
        kev = Vulnerability(
            cve_id="CVE-2024-3400",
            title="PAN-OS",
            cvss_score=10.0,
            severity="Critical",
            in_kev=True,
        )
        likely = Vulnerability(
            cve_id="CVE-2024-0002",
            title="Likely",
            cvss_score=5.0,
            severity="Medium",
            epss_score=0.4,
        )
        db_session.add_all([asset, kev, likely])
        db_session.flush()
        db_session.add_all(
            [
                AssetVulnerability(
                    asset_id=asset.id,
                    vulnerability_id=kev.id,
                    risk_score=10.0,
                    remediation_deadline=datetime.now(UTC) - timedelta(days=2),
                ),
                AssetVulnerability(
                    asset_id=asset.id, vulnerability_id=likely.id, risk_score=6.9
                ),
            ]
        )
        db_session.commit()

    def test_counts_kev_and_likely_exploits(self, client, db_session):
        self.seed(db_session)

        data = client.get("/api/v1/dashboard/stats").json()

        assert data["kev_open_count"] == 1
        assert data["kev_overdue_count"] == 1
        assert data["high_epss_open_count"] == 1
        assert [f["feed"] for f in data["threat_intel"]["feeds"]] == ["kev", "epss"]

    def test_top_risks_carry_the_threat_context(self, client, db_session):
        self.seed(db_session)

        top = client.get("/api/v1/dashboard/top-risks").json()[0]

        assert top["cve_id"] == "CVE-2024-3400"
        assert top["in_kev"] is True
        assert top["internet_facing"] is True
        assert {"kev", "internet_facing"} <= {f["code"] for f in top["risk_factors"]}
