from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import get_or_404
from app.core.security import decode_token, require_admin
from app.db.database import get_db
from app.models.asset import Asset, Criticality
from app.models.vulnerability import AssetVulnerability
from app.schemas.asset import (
    AssetCreate,
    AssetResponse,
    AssetUpdate,
    PaginatedAssetResponse,
)
from app.services.rescoring import rescore_open_findings

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

    # Risk is a function of business criticality and exposure, so a change to
    # either invalidates every score already computed for this asset's findings.
    if changes.keys() & {"business_criticality", "internet_facing"}:
        rescore_open_findings(db, AssetVulnerability.asset_id == asset.id)

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
