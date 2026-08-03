from app.models.asset import Asset
from app.models.vulnerability import AssetVulnerability, Status, Vulnerability


class TestVulnerabilities:
    def test_get_empty(self, client):
        response = client.get("/api/v1/vulnerabilities/")
        assert response.status_code == 200
        assert response.json()["total"] == 0

    def test_create_vulnerability(self, client):
        response = client.post(
            "/api/v1/vulnerabilities/",
            json={
                "cve_id": "CVE-2024-12345",
                "title": "Test SQL Injection",
                "description": "A test vulnerability",
                "cvss_score": 8.5,
                "severity": "High",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["cve_id"] == "CVE-2024-12345"
        assert data["cvss_score"] == 8.5

    def test_create_duplicate_cve(self, client, db_session):
        db_session.add(
            Vulnerability(
                cve_id="CVE-2024-99999",
                title="Existing",
                cvss_score=5.0,
                severity="Medium",
            )
        )
        db_session.commit()

        response = client.post(
            "/api/v1/vulnerabilities/",
            json={
                "cve_id": "CVE-2024-99999",
                "title": "Duplicate",
                "cvss_score": 7.0,
                "severity": "High",
            },
        )
        assert response.status_code == 409

    def test_invalid_cvss(self, client):
        response = client.post(
            "/api/v1/vulnerabilities/",
            json={
                "cve_id": "CVE-2024-00001",
                "title": "Test",
                "cvss_score": 15.0,
                "severity": "Critical",
            },
        )
        assert response.status_code == 422

    def test_invalid_severity(self, client):
        response = client.post(
            "/api/v1/vulnerabilities/",
            json={
                "cve_id": "CVE-2024-00002",
                "title": "Test",
                "cvss_score": 5.0,
                "severity": "SuperCritical",
            },
        )
        assert response.status_code == 422

    def test_filter_by_severity(self, client, db_session):
        db_session.add(
            Vulnerability(
                cve_id="CVE-2024-A", title="A", cvss_score=9.0, severity="Critical"
            )
        )
        db_session.add(
            Vulnerability(
                cve_id="CVE-2024-B", title="B", cvss_score=5.0, severity="Medium"
            )
        )
        db_session.commit()

        response = client.get("/api/v1/vulnerabilities/?severity=Critical")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["items"][0]["cve_id"] == "CVE-2024-A"

    def test_search_vulnerabilities(self, client, db_session):
        db_session.add(
            Vulnerability(
                cve_id="CVE-2024-SEARCH1",
                title="Apache Log4j RCE",
                cvss_score=10.0,
                severity="Critical",
            )
        )
        db_session.add(
            Vulnerability(
                cve_id="CVE-2024-SEARCH2",
                title="Nginx DoS",
                cvss_score=4.0,
                severity="Medium",
            )
        )
        db_session.commit()

        response = client.get("/api/v1/vulnerabilities/?search=Apache")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert "Apache" in data["items"][0]["title"]


class TestVulnerabilityUpdate:
    def test_updates_metadata(self, client, db_session):
        db_session.add(
            Vulnerability(
                cve_id="CVE-2024-5000",
                title="Typo in titel",
                cvss_score=5.0,
                severity="Medium",
            )
        )
        db_session.commit()
        vuln_id = (
            db_session.query(Vulnerability).filter_by(cve_id="CVE-2024-5000").one().id
        )

        response = client.put(
            f"/api/v1/vulnerabilities/{vuln_id}", json={"title": "Corrected title"}
        )
        assert response.status_code == 200
        assert response.json()["title"] == "Corrected title"

    def test_partial_update_leaves_other_fields_alone(self, client, db_session):
        db_session.add(
            Vulnerability(
                cve_id="CVE-2024-5001",
                title="Keep me",
                cvss_score=5.0,
                severity="Medium",
            )
        )
        db_session.commit()
        vuln_id = (
            db_session.query(Vulnerability).filter_by(cve_id="CVE-2024-5001").one().id
        )

        response = client.put(
            f"/api/v1/vulnerabilities/{vuln_id}", json={"cvss_score": 8.0}
        )
        assert response.json()["title"] == "Keep me"
        assert response.json()["cvss_score"] == 8.0

    def test_score_change_rescores_open_findings(self, client, db_session):
        """Risk derives from CVSS; leaving stale scores would misrank the backlog."""
        asset = Asset(ip_address="10.4.0.1")
        db_session.add(asset)
        db_session.flush()

        vuln = Vulnerability(
            cve_id="CVE-2024-5002", title="Rescore me", cvss_score=4.0, severity="Medium"
        )
        db_session.add(vuln)
        db_session.flush()

        link = AssetVulnerability(
            asset_id=asset.id,
            vulnerability_id=vuln.id,
            status=Status.open,
            risk_score=4.0,
        )
        db_session.add(link)
        db_session.commit()

        client.put(f"/api/v1/vulnerabilities/{vuln.id}", json={"cvss_score": 9.0})

        db_session.refresh(link)
        assert link.risk_score == 9.0  # Medium criticality -> 1.0x

    def test_rejects_out_of_range_score(self, client, db_session):
        db_session.add(
            Vulnerability(
                cve_id="CVE-2024-5003", title="X", cvss_score=5.0, severity="Medium"
            )
        )
        db_session.commit()
        vuln_id = (
            db_session.query(Vulnerability).filter_by(cve_id="CVE-2024-5003").one().id
        )

        response = client.put(
            f"/api/v1/vulnerabilities/{vuln_id}", json={"cvss_score": 42}
        )
        assert response.status_code == 422

    def test_unknown_vulnerability_is_404(self, client):
        response = client.put("/api/v1/vulnerabilities/999999", json={"title": "x"})
        assert response.status_code == 404


class TestVulnerabilityDelete:
    def _make(self, db_session, cve="CVE-2024-6000"):
        vuln = Vulnerability(
            cve_id=cve, title="Doomed", cvss_score=5.0, severity="Medium"
        )
        db_session.add(vuln)
        db_session.commit()
        db_session.refresh(vuln)
        return vuln

    def test_admin_can_delete(self, client, db_session):
        vuln = self._make(db_session)

        assert client.delete(f"/api/v1/vulnerabilities/{vuln.id}").status_code == 204
        assert db_session.get(Vulnerability, vuln.id) is None

    def test_analyst_cannot_delete(self, client, db_session):
        """Deletion discards triage history across potentially many assets."""
        vuln = self._make(db_session, cve="CVE-2024-6001")

        from app.core.security import decode_token, require_admin
        from app.main import app as fastapi_app

        admin_override = fastapi_app.dependency_overrides[require_admin]
        # require_admin must run for real, reading an analyst identity: simply
        # dropping its override would still see the admin that decode_token is
        # stubbed to return.
        fastapi_app.dependency_overrides.pop(require_admin, None)
        fastapi_app.dependency_overrides[decode_token] = lambda: {
            "sub": "2",
            "role": "analyst",
            "username": "analyst",
        }
        try:
            response = client.delete(f"/api/v1/vulnerabilities/{vuln.id}")
        finally:
            fastapi_app.dependency_overrides[require_admin] = admin_override
            fastapi_app.dependency_overrides[decode_token] = admin_override

        assert response.status_code == 403
        assert db_session.get(Vulnerability, vuln.id) is not None

    def test_unknown_vulnerability_is_404(self, client):
        assert client.delete("/api/v1/vulnerabilities/999999").status_code == 404
