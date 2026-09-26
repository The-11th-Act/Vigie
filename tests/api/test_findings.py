from datetime import UTC, datetime, timedelta

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


class TestRiskFactors:
    def test_a_plain_finding_has_no_factor(self, client, finding):
        items = client.get("/api/v1/vulnerabilities/findings").json()["items"]
        assert items[0]["risk_factors"] == []

    def test_threat_context_is_explained(self, client, db_session, finding):
        finding.asset.internet_facing = True
        finding.vulnerability.in_kev = True
        db_session.commit()

        item = client.get("/api/v1/vulnerabilities/findings").json()["items"][0]

        codes = {factor["code"] for factor in item["risk_factors"]}
        assert codes == {"kev", "internet_facing", "context_cap"}
        assert item["vulnerability"]["in_kev"] is True
        assert item["asset"]["internet_facing"] is True


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
        assert (
            client.get("/api/v1/vulnerabilities/findings?min_risk=9").json()["total"] == 0
        )
        assert (
            client.get("/api/v1/vulnerabilities/findings?min_risk=5").json()["total"] == 1
        )

    def test_response_exposes_risk_level(self, client, finding):
        item = client.get("/api/v1/vulnerabilities/findings").json()["items"][0]
        assert item["risk_level"] == "High"
        assert item["is_overdue"] is False

    def test_status_filter(self, client, finding):
        response = client.get("/api/v1/vulnerabilities/findings?status_filter=Remediated")
        assert response.json()["total"] == 0


class TestTriageAudit:
    """Regression: status and status_note are overwritten in place, so without
    an audit trail nobody could tell who accepted a risk, or when."""

    def test_status_change_is_recorded(self, client, finding):
        client.patch(
            f"/api/v1/vulnerabilities/findings/{finding.id}",
            json={"status": "Remediated"},
        )

        history = client.get(
            f"/api/v1/vulnerabilities/findings/{finding.id}/history"
        ).json()
        assert len(history) == 1
        assert history[0]["old_status"] == "Open"
        assert history[0]["new_status"] == "Remediated"

    def test_records_who_made_the_decision(self, client, finding, admin_user):
        client.patch(
            f"/api/v1/vulnerabilities/findings/{finding.id}",
            json={
                "status": "Risk Accepted",
                "status_note": "Mitigated by network segmentation.",
            },
        )

        entry = client.get(
            f"/api/v1/vulnerabilities/findings/{finding.id}/history"
        ).json()[0]
        assert entry["user_id"] == admin_user.id
        assert entry["username"] == "admin"
        assert entry["status_note"] == "Mitigated by network segmentation."

    def test_history_is_ordered_most_recent_first(self, client, finding):
        for status in ("Remediated", "Open", "False Positive"):
            client.patch(
                f"/api/v1/vulnerabilities/findings/{finding.id}",
                json={"status": status, "status_note": "because"},
            )

        history = client.get(
            f"/api/v1/vulnerabilities/findings/{finding.id}/history"
        ).json()
        assert [e["new_status"] for e in history] == [
            "False Positive",
            "Open",
            "Remediated",
        ]

    def test_rejected_change_leaves_no_trace(self, client, finding):
        """A 422 must not write an entry for a decision that never happened."""
        response = client.patch(
            f"/api/v1/vulnerabilities/findings/{finding.id}",
            json={"status": "Risk Accepted"},
        )
        assert response.status_code == 422

        history = client.get(
            f"/api/v1/vulnerabilities/findings/{finding.id}/history"
        ).json()
        assert history == []

    def test_history_of_unknown_finding_is_404(self, client):
        response = client.get("/api/v1/vulnerabilities/findings/999999/history")
        assert response.status_code == 404


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


@pytest.fixture
def threat_backlog(db_session):
    """Four open findings; three share a score so the tie-break shows."""

    def add(cve, risk, in_kev=False, epss=None, exposed=False, overdue=False):
        asset = Asset(ip_address=f"10.50.0.{len(cve)}{cve[-1]}", internet_facing=exposed)
        vuln = Vulnerability(
            cve_id=cve,
            title=cve,
            cvss_score=7.0,
            severity="High",
            in_kev=in_kev,
            epss_score=epss,
        )
        db_session.add_all([asset, vuln])
        db_session.flush()
        deadline = datetime.now(UTC) + timedelta(days=-3 if overdue else 30)
        db_session.add(
            AssetVulnerability(
                asset_id=asset.id,
                vulnerability_id=vuln.id,
                status=Status.open,
                risk_score=risk,
                remediation_deadline=deadline,
            )
        )

    add("CVE-2024-0001", 7.0, in_kev=True, epss=0.02, overdue=True)
    add("CVE-2024-0002", 7.0, epss=0.6, exposed=True)
    add("CVE-2024-0003", 7.0)
    add("CVE-2024-0004", 9.0)
    db_session.commit()


def cves(client, **params):
    response = client.get("/api/v1/vulnerabilities/findings", params=params)
    assert response.status_code == 200
    return [item["vulnerability"]["cve_id"] for item in response.json()["items"]]


class TestThreatFilters:
    def test_equal_scores_rank_kev_then_likelier_exploits_first(
        self, client, threat_backlog
    ):
        assert cves(client) == [
            "CVE-2024-0004",  # highest score
            "CVE-2024-0001",  # KEV
            "CVE-2024-0002",  # EPSS 60 %
            "CVE-2024-0003",  # no intel
        ]

    def test_kev_only(self, client, threat_backlog):
        assert cves(client, kev_only=True) == ["CVE-2024-0001"]

    def test_min_epss_excludes_unscored_cves(self, client, threat_backlog):
        assert cves(client, min_epss=0.5) == ["CVE-2024-0002"]
        assert cves(client, min_epss=0.01) == ["CVE-2024-0001", "CVE-2024-0002"]

    def test_internet_facing_only(self, client, threat_backlog):
        assert cves(client, internet_facing_only=True) == ["CVE-2024-0002"]

    def test_filters_combine(self, client, threat_backlog):
        assert cves(client, kev_only=True, overdue_only=True) == ["CVE-2024-0001"]
        assert cves(client, kev_only=True, internet_facing_only=True) == []

    def test_an_epss_above_one_is_rejected(self, client):
        response = client.get(
            "/api/v1/vulnerabilities/findings", params={"min_epss": 1.5}
        )
        assert response.status_code == 422

    def test_the_total_follows_the_filters(self, client, threat_backlog):
        response = client.get(
            "/api/v1/vulnerabilities/findings", params={"kev_only": True}
        )
        assert response.json()["total"] == 1


class TestSaturatedScores:
    def test_findings_at_the_ceiling_are_ordered_by_their_unclamped_rank(
        self, client, db_session
    ):
        """Regression: among findings at 10.0 the order fell back to insertion.
        The more urgent one is created first here, so an id-based order would
        put it last."""
        for ip, cve, rank in (
            ("10.80.0.1", "CVE-2024-8001", 13.5),
            ("10.80.0.2", "CVE-2024-8002", 11.0),
        ):
            asset = Asset(ip_address=ip)
            vuln = Vulnerability(
                cve_id=cve, title=cve, cvss_score=10.0, severity="Critical"
            )
            db_session.add_all([asset, vuln])
            db_session.flush()
            db_session.add(
                AssetVulnerability(
                    asset_id=asset.id,
                    vulnerability_id=vuln.id,
                    status=Status.open,
                    risk_score=10.0,
                    risk_rank=rank,
                )
            )
        db_session.commit()

        assert cves(client) == ["CVE-2024-8001", "CVE-2024-8002"]
