import logging
import os
import uuid
from datetime import UTC, datetime

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_request_id
from app.core.security import decode_token
from app.db.database import get_db
from app.models.scan import ScanJob, ScanStatus
from app.schemas.scan import PaginatedScanJobResponse, ScanJobResponse
from app.worker.celery_app import celery_app
from app.worker.tasks import process_scan_file_task

logger = logging.getLogger(__name__)

router = APIRouter()

VALID_SCAN_TYPES = {"nessus", "openvas"}
ALLOWED_EXTENSIONS = (".xml", ".nessus")

# Read in bounded chunks so an oversized upload is rejected before it is fully
# buffered in memory, rather than after.
CHUNK_SIZE = 1024 * 1024

MAX_LIMIT = 200


@router.post("/upload", status_code=status.HTTP_202_ACCEPTED)
async def upload_scan_file(
    scan_type: str = Form(..., description="Type of scan: nessus or openvas"),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    payload: dict = Depends(decode_token),
):
    """Stage a scan report on disk and queue it for background ingestion.

    Requires authentication: an unauthenticated upload endpoint lets anyone
    inject arbitrary assets and findings into the platform, or exhaust the
    worker pool.
    """
    normalized_type = scan_type.strip().lower()
    if normalized_type not in VALID_SCAN_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan type must be one of: {', '.join(sorted(VALID_SCAN_TYPES))}",
        )

    if not file.filename or not file.filename.lower().endswith(ALLOWED_EXTENSIONS):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be an XML or .nessus file",
        )

    # Written to a shared volume rather than passed through the broker: a 50 MB
    # report would otherwise be JSON-serialised into Redis in full.
    stored_path = _staged_path(file.filename)
    written = await _stream_to_disk(file, stored_path, settings.MAX_SCAN_UPLOAD_BYTES)

    if not written:
        _discard(stored_path)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty",
        )

    scan_job = ScanJob(
        scan_type=normalized_type,
        filename=file.filename,
        uploaded_by=_user_id(payload),
        status=ScanStatus.pending,
    )
    db.add(scan_job)
    db.commit()
    db.refresh(scan_job)

    try:
        # The request id rides along so the worker's log lines about this
        # ingestion can be traced back to this upload.
        task = process_scan_file_task.apply_async(
            args=(stored_path, normalized_type, scan_job.id),
            headers={"request_id": get_request_id()},
        )
    except Exception as exc:
        # Typically the broker being unreachable — surface it as a 503 rather
        # than a generic 500, and never leak the raw exception to the client.
        logger.error("Failed to enqueue scan processing task: %s", exc, exc_info=True)
        scan_job.status = ScanStatus.failed
        scan_job.message = "Could not be queued: the processing queue is unavailable."
        scan_job.finished_at = datetime.now(UTC)
        db.commit()
        _discard(stored_path)
        # `from None`: the broker error is already logged server-side and must
        # not reach the client, which would leak infrastructure details.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan processing queue is unavailable. Please retry shortly.",
        ) from None

    scan_job.task_id = task.id
    db.commit()
    db.refresh(scan_job)

    logger.info(
        "Queued %s scan '%s' (%d bytes) as task %s / job %s by user %s",
        normalized_type,
        file.filename,
        written,
        task.id,
        scan_job.id,
        payload.get("sub"),
    )
    return {
        "message": "Scan file upload accepted. Processing in background.",
        "task_id": task.id,
        "scan_job_id": scan_job.id,
        "scan_type": normalized_type,
    }


@router.get("/", response_model=PaginatedScanJobResponse)
def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=MAX_LIMIT),
    db: Session = Depends(get_db),
    payload: dict = Depends(decode_token),
):
    """Scan history. Analysts see their own uploads; admins see everything."""
    query = db.query(ScanJob)

    if not _is_admin(payload):
        query = query.filter(ScanJob.uploaded_by == _user_id(payload))

    total = query.count()
    items = query.order_by(ScanJob.id.desc()).offset(skip).limit(limit).all()
    return {"total": total, "items": items}


@router.get("/status/{task_id}", response_model=ScanJobResponse)
def get_scan_status(
    task_id: str,
    db: Session = Depends(get_db),
    payload: dict = Depends(decode_token),
):
    """Status of a single scan, restricted to its author (or an admin).

    Reads from the job table rather than Celery so the answer survives result
    expiry, and so one user cannot read another user's scan by task id.
    """
    scan_job = db.query(ScanJob).filter(ScanJob.task_id == task_id).first()

    if scan_job is None or (
        not _is_admin(payload) and scan_job.uploaded_by != _user_id(payload)
    ):
        # 404 rather than 403 for someone else's job: a 403 would confirm the
        # task id exists.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )

    # A job still in flight can be refined with the broker's live state, but the
    # stored record stands on its own: an unreachable Redis degrades the answer
    # rather than failing the request.
    if scan_job.status in (ScanStatus.pending, ScanStatus.running):
        try:
            state = celery_app.AsyncResult(task_id).state
        except Exception as exc:
            logger.warning("Could not read live task state for %s: %s", task_id, exc)
        else:
            if state == "FAILURE":
                scan_job.status = ScanStatus.failed
            elif state == "STARTED":
                scan_job.status = ScanStatus.running

    return scan_job


def _staged_path(filename: str) -> str:
    """Return a collision-free path under the upload directory.

    The client-supplied name is never used on disk — only its extension, from a
    validated allow-list — so a crafted filename cannot escape the directory.
    """
    _, ext = os.path.splitext(filename.lower())
    if ext not in ALLOWED_EXTENSIONS:
        ext = ".xml"
    os.makedirs(settings.SCAN_UPLOAD_DIR, exist_ok=True)
    return os.path.join(settings.SCAN_UPLOAD_DIR, f"{uuid.uuid4().hex}{ext}")


async def _stream_to_disk(file: UploadFile, destination: str, max_bytes: int) -> int:
    """Stream an upload to disk, aborting as soon as it exceeds ``max_bytes``."""
    total = 0
    try:
        with open(destination, "wb") as out:
            while True:
                chunk = await file.read(CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    out.close()
                    _discard(destination)
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=(
                            f"File exceeds the maximum upload size of "
                            f"{max_bytes // (1024 * 1024)} MB"
                        ),
                    )
                out.write(chunk)
    except HTTPException:
        raise
    except OSError as exc:
        logger.error("Could not stage scan upload at %s: %s", destination, exc)
        _discard(destination)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan storage is unavailable. Please retry shortly.",
        ) from exc

    return total


def _discard(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _user_id(payload: dict) -> int | None:
    try:
        return int(payload["sub"])
    except (KeyError, TypeError, ValueError):
        return None


def _is_admin(payload: dict) -> bool:
    return payload.get("role") == "admin"
