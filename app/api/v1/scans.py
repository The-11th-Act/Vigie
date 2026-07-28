import logging

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    UploadFile,
    status,
)

from app.core.config import settings
from app.core.security import decode_token
from app.worker.celery_app import celery_app
from app.worker.tasks import process_scan_file_task

logger = logging.getLogger(__name__)

router = APIRouter()

VALID_SCAN_TYPES = {"nessus", "openvas"}
ALLOWED_EXTENSIONS = (".xml", ".nessus")

# Read in bounded chunks so an oversized upload is rejected before it is fully
# buffered in memory, rather than after.
CHUNK_SIZE = 1024 * 1024


@router.post("/upload", status_code=status.HTTP_202_ACCEPTED)
async def upload_scan_file(
    scan_type: str = Form(..., description="Type of scan: nessus or openvas"),
    file: UploadFile = File(...),
    payload: dict = Depends(decode_token),
):
    """Queue a scan report for background ingestion.

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

    content = await _read_bounded(file, settings.MAX_SCAN_UPLOAD_BYTES)
    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty",
        )

    try:
        task = process_scan_file_task.delay(
            content.decode("utf-8", errors="ignore"), normalized_type
        )
    except Exception as exc:
        # Typically the broker being unreachable — surface it as a 503 rather
        # than a generic 500, and never leak the raw exception to the client.
        logger.error("Failed to enqueue scan processing task: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan processing queue is unavailable. Please retry shortly.",
        )

    logger.info(
        "Queued %s scan '%s' (%d bytes) as task %s by user %s",
        normalized_type,
        file.filename,
        len(content),
        task.id,
        payload.get("sub"),
    )
    return {
        "message": "Scan file upload accepted. Processing in background.",
        "task_id": task.id,
        "scan_type": normalized_type,
    }


@router.get("/status/{task_id}")
def get_scan_status(task_id: str, payload: dict = Depends(decode_token)):
    result = celery_app.AsyncResult(task_id)
    return {
        "task_id": task_id,
        "state": result.state,
        "result": result.result if result.successful() else None,
    }


async def _read_bounded(file: UploadFile, max_bytes: int) -> bytes:
    """Read an upload, aborting as soon as it exceeds ``max_bytes``."""
    chunks = []
    total = 0

    while True:
        chunk = await file.read(CHUNK_SIZE)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=(
                    f"File exceeds the maximum upload size of "
                    f"{max_bytes // (1024 * 1024)} MB"
                ),
            )
        chunks.append(chunk)

    return b"".join(chunks)
