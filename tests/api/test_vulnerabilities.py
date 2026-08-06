from app.models.vulnerability import Vulnerability


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
