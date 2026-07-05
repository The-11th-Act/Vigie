from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from app.db.database import get_db
from app.models.asset import Asset
from app.schemas.asset import AssetCreate, AssetResponse, AssetUpdate, PaginatedAssetResponse

router = APIRouter()

@router.get("/", response_model=PaginatedAssetResponse)
def get_assets(
    skip: int = 0, 
    limit: int = 100, 
    search: Optional[str] = None,
    criticality: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Asset)
    
    if search:
        query = query.filter(
            (Asset.ip_address.ilike(f"%{search}%")) |
            (Asset.hostname.ilike(f"%{search}%"))
        )
    if criticality:
        query = query.filter(Asset.business_criticality == criticality)
        
    total = query.count()
    items = query.order_by(Asset.id.desc()).offset(skip).limit(limit).all()
    
    return {"total": total, "items": items}

@router.post("/", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
def create_asset(asset_in: AssetCreate, db: Session = Depends(get_db)):
    existing = db.query(Asset).filter(Asset.ip_address == asset_in.ip_address).first()
    if existing:
        raise HTTPException(status_code=400, detail="Asset with this IP address already exists")
    db_asset = Asset(**asset_in.dict())
    db.add(db_asset)
    db.commit()
    db.refresh(db_asset)
    return db_asset

@router.get("/{asset_id}", response_model=AssetResponse)
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset

@router.put("/{asset_id}", response_model=AssetResponse)
def update_asset(asset_id: int, asset_in: AssetUpdate, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    for key, val in asset_in.dict(exclude_unset=True).items():
        setattr(asset, key, val)
    db.commit()
    db.refresh(asset)
    return asset

@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.delete(asset)
    db.commit()
