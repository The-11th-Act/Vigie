import pytest

from app.models.asset import Asset
from app.models.vulnerability import AssetVulnerability, Status, Vulnerability


@pytest.fixture
def finding(db_session):
    asset = Asset(ip_address="10.1.0.1", hostname="triage-host")
    db_session.add(asset)
    db_session.flush()

    vuln = Vulnerability(
        cve_id="CVE-2024-7000", title="Triage me", cvss_score=8.0, severity="High"
    )
    db_session.add(vuln)
    db_session.flush()

    link = AssetVulnerability(
        asset_id=asset.id,
        vulnerability_id=vuln.id,
        status=Status.open,
        risk_score=8.0,
    )
    db_session.add(link)
    db_session.commit()
    return link


class TestFindingLifecycle:
    def test_mark_remediated_sets_fixed_at(self, client, finding):
        response = client.patch(
            f"/api/v1/vulnerabilities/findings/{finding.id}",
            json={"status": "Remediated"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "Remediated"
        assert data["fixed_at"] is not None

    def test_risk_accepted_requires_a_note(self, client, finding):
        response = client.patch(
            f"/api/v1/vulnerabilities/findings/{finding.id}",
            json={"status": "Risk Accepted"},
        )
        assert response.status_code == 422
        assert "status_note" in response.json()["detail"]

    def test_false_positive_requires_a_note(self, client, finding):
        response = client.patch(
            f"/api/v1/vulnerabilities/findings/{finding.id}",
            json={"status": "False Positive"},
        )
        assert response.status_code == 422

    def test_risk_accepted_with_note_succeeds(self, client, finding):
        response = client.patch(
            f"/api/v1/vulnerabilities/findings/{finding.id}",
            json={
                "status": "Risk Accepted",
                "status_note": "Compensating control in place until Q4.",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "Risk Accepted"
        assert data["status_note"] == "Compensating control in place until Q4."

    def test_blank_note_is_rejected(self, client, finding):
        response = client.patch(
            f"/api/v1/vulnerabilities/findings/{finding.id}",
            json={"status": "Risk Accepted", "status_note": "   "},
        )
        assert response.status_code == 422

    def test_reopening_clears_fixed_at(self, client, finding):
        client.patch(
            f"/api/v1/vulnerabilities/findings/{finding.id}",
            json={"status": "Remediated"},
        )
        response = client.patch(
            f"/api/v1/vulnerabilities/findings/{finding.id}",
            json={"status": "Open"},
        )
        assert response.status_code == 200
        assert response.json()["fixed_at"] is None

    def test_invalid_status_is_rejected(self, client, finding):
        response = client.patch(
            f"/api/v1/vulnerabilities/findings/{finding.id}",
            json={"status": "Totally Fixed Probably"},
        )
        assert response.status_code == 422

    def test_unknown_finding_returns_404(self, client):
        response = client.patch(
            "/api/v1/vulnerabilities/findings/999999",
            json={"status": "Remediated"},
        )
        assert response.status_code == 404


class TestFindingsBacklog:
    def test_ordered_by_risk_descending(self, client, db_session):
        asset = Asset(ip_address="10.2.0.1")
        db_session.add(asset)
        db_session.flush()

        for i, score in enumerate([3.0, 9.5, 6.0]):
            vuln = Vulnerability(
                cve_id=f"CVE-2024-80{i}0",
                title=f"Vuln {i}",
                cvss_score=score,
                severity="High",
            )
            db_session.add(vuln)
            db_session.flush()
            db_session.add(
                AssetVulnerability(
                    asset_id=asset.id,
                    vulnerability_id=vuln.id,
                    status=Status.open,
                    risk_score=score,
                )
            )
        db_session.commit()

        response = client.get("/api/v1/vulnerabilities/findings")
        assert response.status_code == 200
        scores = [item["risk_score"] for item in response.json()["items"]]
        assert scores == sorted(scores, reverse=True)

    def test_min_risk_filter(self, client, finding):
        assert client.get("/api/v1/vulnerabilities/findings?min_risk=9").json()["total"] == 0
        assert client.get("/api/v1/vulnerabilities/findings?min_risk=5").json()["total"] == 1

    def test_response_exposes_risk_level(self, client, finding):
        item = client.get("/api/v1/vulnerabilities/findings").json()["items"][0]
        assert item["risk_level"] == "High"
        assert item["is_overdue"] is False

    def test_status_filter(self, client, finding):
        response = client.get("/api/v1/vulnerabilities/findings?status_filter=Remediated")
        assert response.json()["total"] == 0


class TestDashboardRiskMetrics:
    def test_stats_include_risk_aggregates(self, client, finding):
        data = client.get("/api/v1/dashboard/stats").json()
        assert data["average_risk_score"] == 8.0
        assert data["max_risk_score"] == 8.0
        assert data["remediation_rate_percent"] == 0.0

    def test_top_risks(self, client, finding):
        data = client.get("/api/v1/dashboard/top-risks").json()
        assert len(data) == 1
        assert data[0]["cve_id"] == "CVE-2024-7000"
        assert data[0]["risk_level"] == "High"
        assert data[0]["hostname"] == "triage-host"
