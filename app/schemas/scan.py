from datetime import datetime

from pydantic import BaseModel

from app.models.scan import ScanStatus


class ScanJobResponse(BaseModel):
    id: int
    task_id: str | None = None
    scan_type: str
    filename: str
    uploaded_by: int | None = None
    status: ScanStatus
    processed_records: int = 0
    new_assets: int = 0
    new_vulnerabilities: int = 0
    new_associations: int = 0
    reopened: int = 0
    message: str | None = None
    created_at: datetime
    finished_at: datetime | None = None

    model_config = {"from_attributes": True}


class PaginatedScanJobResponse(BaseModel):
    total: int
    items: list[ScanJobResponse]
