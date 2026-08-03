import logging
import os
from datetime import datetime, timezone

from app.db.database import SessionLocal
from app.models.scan import ScanJob, ScanStatus
from app.parsers.nessus import parse_nessus_report
from app.parsers.openvas import parse_openvas_report
from app.services.ingestion import ingest_findings
from app.worker.celery_app import celery_app

logger = logging.getLogger(__name__)

PARSERS = {
    "nessus": parse_nessus_report,
    "openvas": parse_openvas_report,
}


@celery_app.task(
    name="app.worker.tasks.process_scan_file_task",
    bind=True,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_backoff_max=300,
    retry_jitter=True,
    max_retries=3,
    soft_time_limit=600,
    time_limit=900,
)
def process_scan_file_task(self, scan_file_path: str, scan_type: str, scan_job_id=None):
    """Parse a staged scan report and ingest its findings.

    Takes the path to a file on the shared upload volume rather than its
    contents: routing the report itself through the broker would serialise up
    to 50 MB into Redis for every upload.

    Transient failures (database blips, lock contention) are retried with
    exponential backoff; a malformed scan type is a permanent error and is
    returned immediately without burning retries.
    """
    scan_type = (scan_type or "").lower()
    parser = PARSERS.get(scan_type)
    if parser is None:
        logger.error("Unsupported scan type: %s", scan_type)
        message = f"Unsupported scan type: {scan_type}"
        _finalize_job(scan_job_id, ScanStatus.failed, message=message)
        _discard(scan_file_path)
        return {"status": "error", "message": message}

    db = SessionLocal()
    try:
        _mark_running(db, scan_job_id)

        with open(scan_file_path, "rb") as handle:
            raw = handle.read()

        findings = parser(raw)
        result = ingest_findings(db, findings, scan_type)

        _apply_result(db, scan_job_id, result)
        # Only drop the staged file once its contents are safely persisted.
        _discard(scan_file_path)
        return {"status": "success", **result.as_dict()}
    except FileNotFoundError:
        # A missing file will never reappear on a retry, so fail it outright.
        db.rollback()
        message = f"Staged scan file is missing: {scan_file_path}"
        logger.error(message)
        _finalize_job(scan_job_id, ScanStatus.failed, message=message)
        return {"status": "error", "message": message}
    except Exception as exc:
        db.rollback()
        logger.error(
            "Scan processing failed (attempt %d/%d): %s",
            self.request.retries + 1,
            self.max_retries,
            exc,
            exc_info=True,
        )
        if self.request.retries >= self.max_retries:
            _finalize_job(scan_job_id, ScanStatus.failed, message=str(exc))
            _discard(scan_file_path)
            return {"status": "error", "message": str(exc)}
        raise
    finally:
        db.close()


def _mark_running(db, scan_job_id) -> None:
    if scan_job_id is None:
        return
    job = db.get(ScanJob, scan_job_id)
    if job is not None:
        job.status = ScanStatus.running
        db.commit()


def _apply_result(db, scan_job_id, result) -> None:
    if scan_job_id is None:
        return
    job = db.get(ScanJob, scan_job_id)
    if job is None:
        return
    job.status = ScanStatus.success
    job.processed_records = result.processed_records
    job.new_assets = result.new_assets
    job.new_vulnerabilities = result.new_vulnerabilities
    job.new_associations = result.new_associations
    job.reopened = result.reopened
    job.message = result.message or None
    job.finished_at = datetime.now(timezone.utc)
    db.commit()


def _finalize_job(scan_job_id, status: ScanStatus, message: str | None = None) -> None:
    """Record a terminal state on a session of its own.

    The caller's session may already have been rolled back by the failure that
    brought us here, so the status update does not reuse it.
    """
    if scan_job_id is None:
        return
    db = SessionLocal()
    try:
        job = db.get(ScanJob, scan_job_id)
        if job is None:
            return
        job.status = status
        job.message = message
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Could not record terminal state for scan job %s", scan_job_id)
    finally:
        db.close()


def _discard(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass
