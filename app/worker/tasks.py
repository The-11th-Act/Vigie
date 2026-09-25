import logging
import os
from datetime import UTC, datetime

from app.core.logging import set_request_id
from app.core.metrics import observe_ingestion
from app.db.database import SessionLocal
from app.models.scan import ScanJob, ScanStatus
from app.parsers.nessus import parse_nessus_scan
from app.parsers.openvas import parse_openvas_scan
from app.services.ingestion import ingest_findings
from app.services.rescoring import rescore_open_findings
from app.worker.celery_app import celery_app

logger = logging.getLogger(__name__)

# Each parser returns a ParsedScan: the findings and the hosts the file covered,
# which bounds the automatic closure to what was actually scanned.
PARSERS = {
    "nessus": parse_nessus_scan,
    "openvas": parse_openvas_scan,
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
    _adopt_request_id(self)

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

        scan = parser(raw)
        result = ingest_findings(
            db, scan.findings, scan_type, scanned_addresses=scan.scanned_addresses
        )

        observe_ingestion(scan_type, result.processed_records)
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


@celery_app.task(
    name="app.worker.tasks.sync_crowdstrike_task",
    bind=True,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
    max_retries=3,
    soft_time_limit=1800,
    time_limit=2100,
)
def sync_crowdstrike_task(self):
    """Pull open Spotlight findings and run them through the usual ingestion.

    CrowdStrike is a polled source rather than an uploaded file, but its
    findings are normalised into the same shape, so the whole scoring, SLA and
    deduplication pipeline applies unchanged.
    """
    from app.core.config import settings
    from app.parsers.crowdstrike import fetch_vulnerabilities_from_settings

    if not settings.CROWDSTRIKE_SYNC_ENABLED:
        logger.info("CrowdStrike sync is disabled; nothing to do")
        return {"status": "skipped", "message": "CrowdStrike sync is disabled"}

    if not settings.crowdstrike_configured:
        logger.warning("CrowdStrike sync enabled but no credentials are configured")
        return {"status": "skipped", "message": "CrowdStrike credentials are missing"}

    db = SessionLocal()
    try:
        findings = fetch_vulnerabilities_from_settings()
        result = ingest_findings(db, findings, "crowdstrike")
        observe_ingestion("crowdstrike", result.processed_records)
        return {"status": "success", **result.as_dict()}
    except Exception as exc:
        db.rollback()
        logger.error(
            "CrowdStrike sync failed (attempt %d/%d): %s",
            self.request.retries + 1,
            self.max_retries,
            exc,
            exc_info=True,
        )
        if self.request.retries >= self.max_retries:
            return {"status": "error", "message": str(exc)}
        raise
    finally:
        db.close()


@celery_app.task(
    name="app.worker.tasks.rescore_open_findings_task",
    soft_time_limit=1800,
    time_limit=2100,
)
def rescore_open_findings_task():
    """Recompute the risk of the whole open backlog.

    The overdue penalty grows with time, but scores used to move only when a
    scan came in: a finding past its deadline on a host nobody rescans stayed
    frozen at its original rank. Run daily by beat.
    """
    db = SessionLocal()
    try:
        changed = rescore_open_findings(db)
        db.commit()
        logger.info("Daily rescoring updated %d open finding(s)", changed)
        return {"status": "success", "rescored": changed}
    except Exception:
        db.rollback()
        logger.exception("Daily rescoring failed")
        raise
    finally:
        db.close()


def _adopt_request_id(task) -> None:
    """Continue the correlation id of the request that queued this task."""
    try:
        request_id = (task.request.headers or {}).get("request_id")
    except AttributeError:
        request_id = None
    if request_id:
        set_request_id(request_id)


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
    job.auto_remediated = result.auto_remediated
    job.message = result.message or None
    job.finished_at = datetime.now(UTC)
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
        job.finished_at = datetime.now(UTC)
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
