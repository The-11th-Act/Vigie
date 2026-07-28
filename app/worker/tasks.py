import logging

from app.db.database import SessionLocal
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
def process_scan_file_task(self, file_content_str: str, scan_type: str):
    """Parse an uploaded scan report and ingest its findings.

    Transient failures (database blips, lock contention) are retried with
    exponential backoff; a malformed scan type is a permanent error and is
    returned immediately without burning retries.
    """
    scan_type = (scan_type or "").lower()
    parser = PARSERS.get(scan_type)
    if parser is None:
        logger.error("Unsupported scan type: %s", scan_type)
        return {"status": "error", "message": f"Unsupported scan type: {scan_type}"}

    db = SessionLocal()
    try:
        findings = parser(file_content_str.encode("utf-8"))
        result = ingest_findings(db, findings, scan_type)
        return {"status": "success", **result.as_dict()}
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
            return {"status": "error", "message": str(exc)}
        raise
    finally:
        db.close()
