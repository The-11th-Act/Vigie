from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import get_or_404
from app.core.security import decode_token, require_admin
from app.db.database import get_db
from app.models.asset import Asset, Criticality
from app.models.vulnerability import AssetVulnerability, Status
from app.schemas.asset import (
    AssetCreate,
    AssetResponse,
    AssetUpdate,
    PaginatedAssetResponse,
)
from app.services.risk_scoring import calculate_risk_score

router = APIRouter()

MAX_LIMIT = 500


@router.get("/", response_model=PaginatedAssetResponse)
def get_assets(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=MAX_LIMIT),
    search: str | None = None,
    criticality: Criticality | None = None,
    db: Session = Depends(get_db),
    payload: dict = Depends(decode_token),
):
    query = db.query(Asset)

    if search:
        pattern = f"%{search}%"
        query = query.filter(
            or_(Asset.ip_address.ilike(pattern), Asset.hostname.ilike(pattern))
        )
    if criticality:
        query = query.filter(Asset.business_criticality == criticality)

    total = query.count()
    items = query.order_by(Asset.id.desc()).offset(skip).limit(limit).all()

    return {"total": total, "items": items}


@router.post("/", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
def create_asset(
    asset_in: AssetCreate,
    db: Session = Depends(get_db),
    payload: dict = Depends(decode_token),
):
    existing = db.query(Asset).filter(Asset.ip_address == asset_in.ip_address).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Asset with this IP address already exists",
        )

    db_asset = Asset(**asset_in.model_dump())
    db.add(db_asset)
    db.commit()
    db.refresh(db_asset)
    return db_asset


@router.get("/{asset_id}", response_model=AssetResponse)
def get_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    payload: dict = Depends(decode_token),
):
    return get_or_404(db, Asset, asset_id)


@router.put("/{asset_id}", response_model=AssetResponse)
def update_asset(
    asset_id: int,
    asset_in: AssetUpdate,
    db: Session = Depends(get_db),
    payload: dict = Depends(decode_token),
):
    asset = get_or_404(db, Asset, asset_id)
    changes = asset_in.model_dump(exclude_unset=True)

    for key, val in changes.items():
        setattr(asset, key, val)

    # Risk is a function of business criticality, so a change here invalidates
    # every score already computed for this asset's open findings.
    if "business_criticality" in changes:
        _rescore_open_findings(db, asset)

    db.commit()
    db.refresh(asset)
    return asset


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    asset = get_or_404(db, Asset, asset_id)
    db.delete(asset)
    db.commit()


def _rescore_open_findings(db: Session, asset: Asset) -> None:
    findings = (
        db.query(AssetVulnerability)
        .filter(
            AssetVulnerability.asset_id == asset.id,
            AssetVulnerability.status == Status.open,
        )
        .all()
    )
    for finding in findings:
        if finding.vulnerability is None:
            continue
        finding.risk_score = calculate_risk_score(
            finding.vulnerability.cvss_score,
            asset.business_criticality,
            finding.remediation_deadline,
        )
