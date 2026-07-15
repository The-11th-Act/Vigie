from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Optional
from app.db.database import get_db
from app.models.vulnerability import Vulnerability, AssetVulnerability
from app.schemas.vulnerability import (
    VulnerabilityCreate,
    VulnerabilityResponse,
    AssetVulnerabilityResponse,
    PaginatedVulnerabilityResponse,
    PaginatedAssetVulnerabilityResponse,
)

router = APIRouter()

MAX_LIMIT = 500


@router.get("/", response_model=PaginatedVulnerabilityResponse)
def get_vulnerabilities(
    skip: int = 0,
    limit: int = 100,
    search: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
):
    limit = min(limit, MAX_LIMIT)
    query = db.query(Vulnerability)

    if search:
        query = query.filter(
            (Vulnerability.cve_id.ilike(f"%{search}%"))
            | (Vulnerability.title.ilike(f"%{search}%"))
        )
    if severity:
        query = query.filter(Vulnerability.severity == severity.capitalize())

    total = query.count()
    items = query.order_by(Vulnerability.id.desc()).offset(skip).limit(limit).all()

    return {"total": total, "items": items}


@router.post("/", response_model=VulnerabilityResponse, status_code=status.HTTP_201_CREATED)
def create_vulnerability(vuln_in: VulnerabilityCreate, db: Session = Depends(get_db)):
    existing = db.query(Vulnerability).filter(Vulnerability.cve_id == vuln_in.cve_id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Vulnerability with this CVE ID already exists")
    db_vuln = Vulnerability(**vuln_in.model_dump())
    db.add(db_vuln)
    db.commit()
    db.refresh(db_vuln)
    return db_vuln


@router.get("/assets/{asset_id}", response_model=PaginatedAssetVulnerabilityResponse)
def get_asset_vulnerabilities(
    asset_id: int,
    skip: int = 0,
    limit: int = 100,
    status_filter: Optional[str] = None,
    db: Session = Depends(get_db),
):
    limit = min(limit, MAX_LIMIT)
    query = db.query(AssetVulnerability).filter(AssetVulnerability.asset_id == asset_id)

    if status_filter:
        query = query.filter(AssetVulnerability.status == status_filter)

    total = query.count()
    items = query.order_by(AssetVulnerability.id.desc()).offset(skip).limit(limit).all()

    return {"total": total, "items": items}