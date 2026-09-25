import io
import json

import pytest

from app.core.config import settings
from app.models.vulnerability import Vulnerability
from tests.conftest import VALID_PASSWORD


def kev_file(*cves, released="2026-09-25"):
    body = json.dumps(
        {
            "catalogVersion": "2026.09.25",
            "dateReleased": released,
            "vulnerabilities": [{"cveID": cve} for cve in cves],
        }
    ).encode()
    return {"file": ("kev.json", io.BytesIO(body), "application/json")}


@pytest.fixture
def tracked(db_session):
    vuln = Vulnerability(
        cve_id="CVE-2024-3400", title="PAN-OS", cvss_score=10.0, severity="Critical"
    )
    db_session.add(vuln)
    db_session.commit()
    return vuln


class TestStatus:
    def test_reports_both_feeds_as_stale_before_any_pull(self, client):
        data = client.get("/api/v1/threat-intel/status").json()

        assert data["enabled"] is settings.THREAT_INTEL_ENABLED
        assert [f["feed"] for f in data["feeds"]] == ["kev", "epss"]
        assert all(f["stale"] for f in data["feeds"])

    def test_an_import_makes_the_feed_fresh(self, client, tracked):
        client.post(
            "/api/v1/threat-intel/import",
            data={"feed": "kev"},
            files=kev_file("CVE-2024-3400"),
        )

        feeds = {
            f["feed"]: f
            for f in client.get("/api/v1/threat-intel/status").json()["feeds"]
        }

        assert feeds["kev"]["stale"] is False
        assert feeds["kev"]["source"] == "import"
        assert feeds["kev"]["source_version"] == "2026.09.25"
        assert feeds["epss"]["stale"] is True


class TestImport:
    def test_applies_a_kev_file(self, client, db_session, tracked):
        response = client.post(
            "/api/v1/threat-intel/import",
            data={"feed": "kev"},
            files=kev_file("CVE-2024-3400"),
        )

        assert response.status_code == 200
        assert response.json()["changed"] == 1
        db_session.refresh(tracked)
        assert tracked.in_kev is True

    def test_an_unknown_feed_is_rejected(self, client):
        response = client.post(
            "/api/v1/threat-intel/import",
            data={"feed": "nvd"},
            files=kev_file("CVE-2024-1"),
        )
        assert response.status_code == 400

    def test_a_malformed_file_says_why(self, client):
        response = client.post(
            "/api/v1/threat-intel/import",
            data={"feed": "kev"},
            files={"file": ("kev.json", io.BytesIO(b"<html/>"), "text/html")},
        )
        assert response.status_code == 400
        assert "JSON" in response.json()["detail"]

    def test_an_oversized_file_is_rejected(self, client, monkeypatch):
        monkeypatch.setattr(settings, "THREAT_INTEL_MAX_FEED_BYTES", 10)
        response = client.post(
            "/api/v1/threat-intel/import",
            data={"feed": "kev"},
            files=kev_file("CVE-2024-1"),
        )
        assert response.status_code == 413

    def test_an_older_snapshot_needs_force(self, client, tracked):
        client.post(
            "/api/v1/threat-intel/import",
            data={"feed": "kev"},
            files=kev_file("CVE-2024-3400"),
        )
        older = kev_file("CVE-2024-3400", released="2026-01-01")

        refused = client.post(
            "/api/v1/threat-intel/import", data={"feed": "kev"}, files=older
        )
        assert refused.status_code == 400
        assert "force" in refused.json()["detail"]

        older = kev_file("CVE-2024-3400", released="2026-01-01")
        forced = client.post(
            "/api/v1/threat-intel/import",
            data={"feed": "kev", "force": "true"},
            files=older,
        )
        assert forced.status_code == 200


class TestRefresh:
    def test_is_refused_while_the_network_pull_is_disabled(self, client, monkeypatch):
        monkeypatch.setattr(settings, "THREAT_INTEL_ENABLED", False)
        assert client.post("/api/v1/threat-intel/refresh").status_code == 409

    def test_queues_a_refresh(self, client, monkeypatch):
        class FakeTask:
            id = "refresh-task"

        monkeypatch.setattr(settings, "THREAT_INTEL_ENABLED", True)
        monkeypatch.setattr(
            "app.api.v1.threat_intel.refresh_threat_intel_task.apply_async",
            lambda *a, **k: FakeTask(),
        )

        response = client.post("/api/v1/threat-intel/refresh")

        assert response.status_code == 202
        assert response.json() == {"task_id": "refresh-task"}

    def test_an_unreachable_queue_is_a_503(self, client, monkeypatch):
        def broker_down(*_a, **_k):
            raise ConnectionError("redis down")

        monkeypatch.setattr(settings, "THREAT_INTEL_ENABLED", True)
        monkeypatch.setattr(
            "app.api.v1.threat_intel.refresh_threat_intel_task.apply_async", broker_down
        )

        assert client.post("/api/v1/threat-intel/refresh").status_code == 503


class TestAccessControl:
    @pytest.fixture
    def analyst_headers(self, unauthenticated_client, other_user):
        login = unauthenticated_client.post(
            "/api/v1/auth/login",
            json={"username": other_user.username, "password": VALID_PASSWORD},
        )
        return {"Authorization": f"Bearer {login.json()['access_token']}"}

    def test_an_analyst_can_read_the_status(
        self, unauthenticated_client, analyst_headers
    ):
        response = unauthenticated_client.get(
            "/api/v1/threat-intel/status", headers=analyst_headers
        )
        assert response.status_code == 200

    @pytest.mark.parametrize(
        "path", ["/api/v1/threat-intel/refresh", "/api/v1/threat-intel/import"]
    )
    def test_an_analyst_cannot_change_the_feeds(
        self, unauthenticated_client, analyst_headers, path
    ):
        response = unauthenticated_client.post(
            path,
            headers=analyst_headers,
            data={"feed": "kev"},
            files=kev_file("CVE-2024-1"),
        )
        assert response.status_code == 403

    def test_the_status_requires_authentication(self, unauthenticated_client):
        assert (
            unauthenticated_client.get("/api/v1/threat-intel/status").status_code == 401
        )
