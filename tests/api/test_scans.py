"""Access control and input validation on the scan upload endpoint.

Regression: this endpoint previously had no authentication at all, letting
anyone inject arbitrary assets and findings or saturate the worker pool.
"""

import io

import pytest

from app.core.config import settings


@pytest.fixture
def no_broker(monkeypatch):
    """Stub the Celery dispatch so tests never need a running Redis."""

    class FakeTask:
        id = "fake-task-id"

    def fake_delay(*args, **kwargs):
        return FakeTask()

    monkeypatch.setattr("app.api.v1.scans.process_scan_file_task.delay", fake_delay)


def xml_file(content=b"<?xml version='1.0'?><report/>", name="scan.xml"):
    return {"file": (name, io.BytesIO(content), "application/xml")}


class TestScanUploadAuth:
    def test_upload_requires_authentication(self, unauthenticated_client):
        response = unauthenticated_client.post(
            "/api/v1/scans/upload",
            data={"scan_type": "nessus"},
            files=xml_file(),
        )
        assert response.status_code == 401

    def test_status_requires_authentication(self, unauthenticated_client):
        response = unauthenticated_client.get("/api/v1/scans/status/some-task-id")
        assert response.status_code == 401


class TestScanUploadValidation:
    def test_accepts_valid_upload(self, client, no_broker):
        response = client.post(
            "/api/v1/scans/upload",
            data={"scan_type": "nessus"},
            files=xml_file(),
        )
        assert response.status_code == 202
        assert response.json()["task_id"] == "fake-task-id"

    def test_scan_type_is_case_insensitive(self, client, no_broker):
        response = client.post(
            "/api/v1/scans/upload",
            data={"scan_type": "  OpenVAS  "},
            files=xml_file(),
        )
        assert response.status_code == 202
        assert response.json()["scan_type"] == "openvas"

    def test_rejects_unknown_scan_type(self, client, no_broker):
        response = client.post(
            "/api/v1/scans/upload",
            data={"scan_type": "qualys"},
            files=xml_file(),
        )
        assert response.status_code == 400

    def test_rejects_wrong_extension(self, client, no_broker):
        response = client.post(
            "/api/v1/scans/upload",
            data={"scan_type": "nessus"},
            files=xml_file(name="payload.exe"),
        )
        assert response.status_code == 400

    def test_rejects_empty_file(self, client, no_broker):
        response = client.post(
            "/api/v1/scans/upload",
            data={"scan_type": "nessus"},
            files=xml_file(content=b""),
        )
        assert response.status_code == 400

    def test_rejects_oversized_file(self, client, no_broker, monkeypatch):
        monkeypatch.setattr(settings, "MAX_SCAN_UPLOAD_BYTES", 1024)
        response = client.post(
            "/api/v1/scans/upload",
            data={"scan_type": "nessus"},
            files=xml_file(content=b"x" * 4096),
        )
        assert response.status_code == 413

    def test_broker_failure_returns_503(self, client, monkeypatch):
        def boom(*args, **kwargs):
            raise ConnectionError("redis is down")

        monkeypatch.setattr("app.api.v1.scans.process_scan_file_task.delay", boom)

        response = client.post(
            "/api/v1/scans/upload",
            data={"scan_type": "nessus"},
            files=xml_file(),
        )
        assert response.status_code == 503
        # The raw exception must not leak to the client.
        assert "redis" not in response.json()["detail"].lower()
