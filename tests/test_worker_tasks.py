"""Celery task orchestration.

The API-level tests cover the upload; these cover what the worker does with it:
the ScanJob state machine, cleanup of the staged file, and the guards on the
CrowdStrike sync.
"""

import pytest

from app.core.config import settings
from app.models.asset import Asset
from app.models.scan import ScanJob, ScanStatus
from app.worker.tasks import process_scan_file_task, sync_crowdstrike_task

NESSUS_REPORT = b"""<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="test">
    <ReportHost name="10.7.0.1">
      <HostProperties>
        <tag name="host-ip">10.7.0.1</tag>
        <tag name="operating-system">Ubuntu 22.04</tag>
      </HostProperties>
      <ReportItem severity="3" pluginName="Test finding">
        <cve>CVE-2024-4242</cve>
        <cvss3_base_score>8.1</cvss3_base_score>
        <description>Something bad.</description>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""


@pytest.fixture
def worker_session(db_session, monkeypatch):
    """Point the task's session factory at the test session.

    The task opens its own session; without this it would talk to a separate
    connection and never see the fixture's uncommitted data.
    """
    monkeypatch.setattr(db_session, "close", lambda: None)
    monkeypatch.setattr("app.worker.tasks.SessionLocal", lambda: db_session)
    return db_session


@pytest.fixture
def scan_job(worker_session):
    job = ScanJob(scan_type="nessus", filename="report.nessus", uploaded_by=1)
    worker_session.add(job)
    worker_session.commit()
    worker_session.refresh(job)
    return job


def staged_file(tmp_path, content=NESSUS_REPORT, name="report.nessus"):
    path = tmp_path / name
    path.write_bytes(content)
    return str(path)


class TestScanProcessing:
    def test_successful_run_records_counters_and_removes_the_file(
        self, worker_session, scan_job, tmp_path
    ):
        path = staged_file(tmp_path)

        result = process_scan_file_task.apply(args=(path, "nessus", scan_job.id)).get()

        assert result["status"] == "success"
        worker_session.refresh(scan_job)
        assert scan_job.status == ScanStatus.success
        assert scan_job.processed_records == 1
        assert scan_job.new_assets == 1
        assert scan_job.finished_at is not None
        # The staged copy is only dropped once its contents are persisted.
        assert not (tmp_path / "report.nessus").exists()

    def test_findings_actually_reach_the_database(
        self, worker_session, scan_job, tmp_path
    ):
        process_scan_file_task.apply(
            args=(staged_file(tmp_path), "nessus", scan_job.id)
        ).get()

        asset = worker_session.query(Asset).filter_by(ip_address="10.7.0.1").one()
        assert asset.operating_system == "Ubuntu 22.04"

    def test_unsupported_scan_type_fails_without_retrying(
        self, worker_session, scan_job, tmp_path
    ):
        path = staged_file(tmp_path)

        result = process_scan_file_task.apply(args=(path, "qualys", scan_job.id)).get()

        assert result["status"] == "error"
        worker_session.refresh(scan_job)
        assert scan_job.status == ScanStatus.failed
        assert "qualys" in scan_job.message
        assert not (tmp_path / "report.nessus").exists()

    def test_missing_file_fails_outright(self, worker_session, scan_job, tmp_path):
        """A file that is not there will not reappear on a retry."""
        result = process_scan_file_task.apply(
            args=(str(tmp_path / "gone.nessus"), "nessus", scan_job.id)
        ).get()

        assert result["status"] == "error"
        worker_session.refresh(scan_job)
        assert scan_job.status == ScanStatus.failed

    def test_runs_without_a_job_id(self, worker_session, tmp_path):
        """The job record is bookkeeping; ingestion must not depend on it."""
        result = process_scan_file_task.apply(
            args=(staged_file(tmp_path), "nessus", None)
        ).get()

        assert result["status"] == "success"

    def test_adopts_the_request_id_of_the_upload(
        self, worker_session, scan_job, tmp_path, monkeypatch
    ):
        seen = {}
        monkeypatch.setattr(
            "app.worker.tasks.set_request_id", lambda rid: seen.update(rid=rid)
        )

        process_scan_file_task.apply(
            args=(staged_file(tmp_path), "nessus", scan_job.id),
            headers={"request_id": "upload-trace-1"},
        ).get()

        assert seen.get("rid") == "upload-trace-1"


class TestCrowdStrikeSync:
    def test_disabled_sync_is_a_no_op(self, monkeypatch):
        monkeypatch.setattr(settings, "CROWDSTRIKE_SYNC_ENABLED", False)

        result = sync_crowdstrike_task.apply().get()

        assert result["status"] == "skipped"

    def test_enabled_without_credentials_is_skipped_not_crashed(self, monkeypatch):
        monkeypatch.setattr(settings, "CROWDSTRIKE_SYNC_ENABLED", True)
        monkeypatch.setattr(settings, "CROWDSTRIKE_CLIENT_ID", None)
        monkeypatch.setattr(settings, "CROWDSTRIKE_CLIENT_SECRET", None)

        result = sync_crowdstrike_task.apply().get()

        assert result["status"] == "skipped"
        assert "credentials" in result["message"]

    def test_ingests_what_the_client_returns(self, worker_session, monkeypatch):
        monkeypatch.setattr(settings, "CROWDSTRIKE_SYNC_ENABLED", True)
        monkeypatch.setattr(settings, "CROWDSTRIKE_CLIENT_ID", "id")
        monkeypatch.setattr(settings, "CROWDSTRIKE_CLIENT_SECRET", "secret")
        monkeypatch.setattr(
            "app.parsers.crowdstrike.fetch_vulnerabilities_from_settings",
            lambda: [
                {
                    "ip_address": "10.8.0.1",
                    "hostname": "cs-host",
                    "operating_system": "Windows Server 2019",
                    "cve_id": "CVE-2024-9090",
                    "title": "CVE-2024-9090",
                    "description": "From Spotlight.",
                    "cvss_score": 7.2,
                    "severity": "High",
                }
            ],
        )

        result = sync_crowdstrike_task.apply().get()

        assert result["status"] == "success"
        assert result["processed_records"] == 1
        # Polled findings go through the same pipeline as uploaded ones.
        asset = worker_session.query(Asset).filter_by(ip_address="10.8.0.1").one()
        assert asset.hostname == "cs-host"
