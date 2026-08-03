"""Access control and input validation on the scan upload endpoint.

Regression: this endpoint previously had no authentication at all, letting
anyone inject arbitrary assets and findings or saturate the worker pool.
"""
import io

import pytest

from app.core.config import settings
from app.models.scan import ScanJob, ScanStatus


@pytest.fixture
def no_broker(monkeypatch):
    """Stub the Celery dispatch so tests never need a running Redis.

    Records the arguments so tests can assert the worker is handed a *path*
    rather than the file contents.
    """

    class FakeTask:
        id = "fake-task-id"

    calls = []

    def fake_delay(*args, **kwargs):
        calls.append(args)
        return FakeTask()

    monkeypatch.setattr("app.api.v1.scans.process_scan_file_task.delay", fake_delay)
    return calls


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


class TestScanStaging:
    """The upload is written to disk; only its path reaches the broker."""

    def test_file_is_staged_and_path_is_queued(
        self, client, no_broker, scan_upload_dir
    ):
        client.post(
            "/api/v1/scans/upload",
            data={"scan_type": "nessus"},
            files=xml_file(content=b"<?xml version='1.0'?><report/>"),
        )

        staged = list(scan_upload_dir.iterdir())
        assert len(staged) == 1
        assert staged[0].read_bytes() == b"<?xml version='1.0'?><report/>"

        queued_path, queued_type, _job_id = no_broker[0]
        assert queued_path == str(staged[0])
        assert queued_type == "nessus"

    def test_client_supplied_name_cannot_escape_the_directory(
        self, client, no_broker, scan_upload_dir
    ):
        client.post(
            "/api/v1/scans/upload",
            data={"scan_type": "nessus"},
            files=xml_file(name="../../../../etc/passwd.xml"),
        )

        staged = list(scan_upload_dir.iterdir())
        assert len(staged) == 1
        assert staged[0].parent == scan_upload_dir

    def test_staged_file_is_removed_when_queueing_fails(
        self, client, monkeypatch, scan_upload_dir
    ):
        def boom(*args, **kwargs):
            raise ConnectionError("redis is down")

        monkeypatch.setattr("app.api.v1.scans.process_scan_file_task.delay", boom)

        client.post(
            "/api/v1/scans/upload",
            data={"scan_type": "nessus"},
            files=xml_file(),
        )
        assert list(scan_upload_dir.iterdir()) == []


class TestScanHistory:
    def test_upload_records_a_scan_job(self, client, no_broker, db_session):
        response = client.post(
            "/api/v1/scans/upload",
            data={"scan_type": "nessus"},
            files=xml_file(name="corp-scan.nessus"),
        )
        job_id = response.json()["scan_job_id"]

        job = db_session.get(ScanJob, job_id)
        assert job.filename == "corp-scan.nessus"
        assert job.scan_type == "nessus"
        assert job.task_id == "fake-task-id"
        assert job.status == ScanStatus.pending
        # The `client` fixture authenticates as user 1.
        assert job.uploaded_by == 1

    def test_history_lists_uploads(self, client, no_broker):
        client.post(
            "/api/v1/scans/upload",
            data={"scan_type": "nessus"},
            files=xml_file(),
        )

        response = client.get("/api/v1/scans/")
        assert response.status_code == 200
        assert response.json()["total"] == 1

    def test_status_reads_from_the_job_table(self, client, no_broker):
        client.post(
            "/api/v1/scans/upload",
            data={"scan_type": "nessus"},
            files=xml_file(),
        )

        response = client.get("/api/v1/scans/status/fake-task-id")
        assert response.status_code == 200
        assert response.json()["scan_type"] == "nessus"

    def test_unknown_task_id_is_404(self, client):
        assert client.get("/api/v1/scans/status/nope").status_code == 404

    def test_another_users_scan_is_not_readable(self, client, db_session, no_broker):
        """A task id belonging to someone else must not be readable.

        Regression: the endpoint used to return any task's result to any
        authenticated caller.
        """
        db_session.add(
            ScanJob(
                task_id="someone-elses-task",
                scan_type="nessus",
                filename="theirs.nessus",
                uploaded_by=999,
            )
        )
        db_session.commit()

        # The `client` fixture is an admin, who is allowed to see everything;
        # override the role to exercise the analyst path.
        from app.core.security import decode_token
        from app.main import app as fastapi_app

        fastapi_app.dependency_overrides[decode_token] = lambda: {
            "sub": "1",
            "role": "analyst",
            "username": "analyst",
        }
        try:
            response = client.get("/api/v1/scans/status/someone-elses-task")
            assert response.status_code == 404

            listing = client.get("/api/v1/scans/")
            assert listing.json()["total"] == 0
        finally:
            fastapi_app.dependency_overrides.pop(decode_token, None)

    def test_admin_can_read_any_scan(self, client, db_session):
        db_session.add(
            ScanJob(
                task_id="other-task",
                scan_type="openvas",
                filename="theirs.xml",
                uploaded_by=999,
            )
        )
        db_session.commit()

        response = client.get("/api/v1/scans/status/other-task")
        assert response.status_code == 200
