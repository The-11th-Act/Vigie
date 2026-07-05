from fastapi import APIRouter, UploadFile, File, Form, HTTPException, status
from app.worker.tasks import process_scan_file_task

router = APIRouter()

@router.post("/upload")
async def upload_scan_file(
    scan_type: str = Form(..., description="Type of scan: nessus or openvas"),
    file: UploadFile = File(...)
):
    if scan_type.lower() not in ["nessus", "openvas"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan type must be either 'nessus' or 'openvas'"
        )
        
    try:
        content = await file.read()
        file_content_str = content.decode("utf-8", errors="ignore")
        task = process_scan_file_task.delay(file_content_str, scan_type)
        return {
            "message": "Scan file upload accepted. Processing in background.",
            "task_id": task.id
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process upload: {str(e)}"
        )
