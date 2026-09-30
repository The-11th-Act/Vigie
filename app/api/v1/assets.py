from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import get_in_scope_or_404, get_or_404
from app.core.modules import require_risk_decision
from app.core.scope import Scope, current_scope
from app.core.security import require_admin
from app.db.database import get_db
from app.models.asset import Asset, Criticality
from app.models.vulnerability import AssetVulnerability
from app.schemas.asset import (
    AssetCreate,
    AssetResponse,
    AssetUpdate,
    PaginatedAssetResponse,
)
from app.services.asset_policy import environment_for, owner_team_for
from app.services.categorization import asset_type_for
from app.services.rescoring import rescore_open_findings
from app.services.tickets import sync_tickets

router = APIRouter()

MAX_LIMIT = 500


@router.get("/", response_model=PaginatedAssetResponse)
def get_assets(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=MAX_LIMIT),
    search: str | None = None,
    criticality: Criticality | None = None,
    owner_team: str | None = Query(None, max_length=128),
    asset_type: str | None = Query(None, max_length=16),
    environment: str | None = Query(None, max_length=32),
    db: Session = Depends(get_db),
    scope: Scope = Depends(current_scope),
):
    query = scope.filter(db.query(Asset))

    if search:
        pattern = f"%{search}%"
        query = query.filter(
            or_(Asset.ip_address.ilike(pattern), Asset.hostname.ilike(pattern))
        )
    if criticality:
        query = query.filter(Asset.business_criticality == criticality)
    if owner_team:
        query = query.filter(Asset.owner_team == owner_team)
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    if environment:
        query = query.filter(Asset.environment == environment)

    total = query.count()
    items = query.order_by(Asset.id.desc()).offset(skip).limit(limit).all()

    return {"total": total, "items": items}


# Criticality and exposure weigh on every score: risk decisions.
@router.post(
    "/",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_risk_decision)],
)
def create_asset(
    asset_in: AssetCreate,
    db: Session = Depends(get_db),
    scope: Scope = Depends(current_scope),
):
    existing = db.query(Asset).filter(Asset.ip_address == asset_in.ip_address).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Asset with this IP address already exists",
        )

    db_asset = Asset(**asset_in.model_dump())
    if db_asset.owner_team is None:
        db_asset.owner_team = owner_team_for(db_asset.ip_address)
    if db_asset.asset_type is None:
        db_asset.asset_type = asset_type_for(db_asset.operating_system)
    if db_asset.environment is None:
        db_asset.environment = environment_for(db_asset.ip_address)
    _require_team_in_scope(scope, db_asset.owner_team)
    db.add(db_asset)
    db.commit()
    db.refresh(db_asset)
    return db_asset


@router.get("/{asset_id}", response_model=AssetResponse)
def get_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    scope: Scope = Depends(current_scope),
):
    return get_in_scope_or_404(db, Asset, asset_id, scope, _team)


@router.put(
    "/{asset_id}",
    response_model=AssetResponse,
    dependencies=[Depends(require_risk_decision)],
)
def update_asset(
    asset_id: int,
    asset_in: AssetUpdate,
    db: Session = Depends(get_db),
    scope: Scope = Depends(current_scope),
):
    asset = get_in_scope_or_404(db, Asset, asset_id, scope, _team)
    changes = asset_in.model_dump(exclude_unset=True)
    if "owner_team" in changes:
        _require_team_in_scope(scope, changes["owner_team"])

    for key, val in changes.items():
        setattr(asset, key, val)

    # Risk is a function of business criticality and exposure, so a change to
    # either invalidates every score already computed for this asset's findings.
    if changes.keys() & {"business_criticality", "internet_facing"}:
        rescore_open_findings(db, AssetVulnerability.asset_id == asset.id)
    # The host's open findings follow it to its new team's ticket now, not at
    # the next daily pass.
    if "owner_team" in changes:
        sync_tickets(db)

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


def _team(asset: Asset) -> str | None:
    return asset.owner_team


def _require_team_in_scope(scope: Scope, team: str | None) -> None:
    """A scoped user may not create a host for, or hand one to, another team."""
    if not scope.allows(team):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This team is outside your scope",
        )
