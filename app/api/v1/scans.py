from fastapi import APIRouter, UploadFile, File, Form, HTTPException, status
from app.worker.tasks import process_scan_file_task
from app.worker.celery_app import celery_app

router = APIRouter()

VALID_SCAN_TYPES = {"nessus", "openvas"}


@router.post("/upload")
async def upload_scan_file(
    scan_type: str = Form(..., description="Type of scan: nessus or openvas"),
    file: UploadFile = File(...),
):
    if scan_type.lower() not in VALID_SCAN_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan type must be one of: {', '.join(VALID_SCAN_TYPES)}",
        )

    if not file.filename or not file.filename.endswith((".xml", ".nessus")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be an XML or .nessus file",
        )

    try:
        content = await file.read()
        file_content_str = content.decode("utf-8", errors="ignore")
        task = process_scan_file_task.delay(file_content_str, scan_type.lower())
        return {
            "message": "Scan file upload accepted. Processing in background.",
            "task_id": task.id,
            "scan_type": scan_type.lower(),
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process upload: {str(e)}",
        )


@router.get("/status/{task_id}")
def get_scan_status(task_id: str):
    result = celery_app.AsyncResult(task_id)
    return {
        "task_id": task_id,
        "state": result.state,
        "result": result.result if result.ready() else None,
    }