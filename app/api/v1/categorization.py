"""Categorization: open findings crossed by kind of software and kind of host."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import case, distinct, func
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.asset import Asset, Criticality
from app.models.vulnerability import (
    RISK_ORDER,
    AssetVulnerability,
    Status,
    Vulnerability,
)
from app.schemas.vulnerability import PaginatedAssetVulnerabilityResponse
from app.services.categorization import ASSET_TYPES, UNCATEGORIZED, VULN_CATEGORIES
from app.services.findings import NOT_SET, FindingFilters, findings_query

router = APIRouter()

# What the columns of the matrix can be: a property of the host.
DIMENSIONS = {
    "asset_type": ("Asset type", Asset.asset_type),
    "environment": ("Environment", Asset.environment),
    "business_criticality": ("Business criticality", Asset.business_criticality),
    "owner_team": ("Owner team", Asset.owner_team),
    "internet_facing": ("Internet exposure", Asset.internet_facing),
}
CRITICALITY_ORDER = [
    c.value
    for c in (Criticality.critical, Criticality.high, Criticality.medium, Criticality.low)
]
NOT_SET_LABELS = {
    "asset_type": "Unknown type",
    "environment": "No environment",
    "owner_team": "Unassigned",
}


def _column_key(dimension: str, value) -> str:
    if value is None:
        return NOT_SET
    if dimension == "internet_facing":
        return "true" if value else "false"
    return getattr(value, "value", value)


def _column_label(dimension: str, key: str) -> str:
    if key == NOT_SET:
        return NOT_SET_LABELS.get(dimension, "Not set")
    if dimension == "asset_type":
        return ASSET_TYPES.get(key, key)
    if dimension == "internet_facing":
        return "Internet-facing" if key == "true" else "Internal"
    return key


def _dimension(name: str):
    if name not in DIMENSIONS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"columns must be one of {', '.join(DIMENSIONS)}",
        )
    return DIMENSIONS[name]


@router.get("/matrix")
def matrix(
    columns: str = "asset_type",
    kev_only: bool = False,
    min_risk: float | None = Query(None, ge=0, le=10),
    owner_team: str | None = Query(None, max_length=128),
    db: Session = Depends(get_db),
):
    """Open findings per kind of software (rows) and property of host (columns).

    Each cell counts findings, hosts, KEV and overdue findings, and sums the
    risk, so the heaviest crossing (say, browsers on exposed workstations)
    stands out at once.
    """
    label, column = _dimension(columns)
    category = func.coalesce(AssetVulnerability.category, UNCATEGORIZED)
    now = datetime.now(UTC)
    query = (
        db.query(
            category.label("row"),
            column.label("col"),
            func.count(AssetVulnerability.id).label("findings"),
            func.count(distinct(AssetVulnerability.asset_id)).label("assets"),
            func.coalesce(func.sum(AssetVulnerability.risk_score), 0.0).label(
                "total_risk"
            ),
            func.max(AssetVulnerability.risk_score).label("max_risk"),
            func.sum(case((Vulnerability.in_kev.is_(True), 1), else_=0)).label("kev"),
            func.sum(
                case((AssetVulnerability.remediation_deadline < now, 1), else_=0)
            ).label("overdue"),
        )
        .join(Asset, Asset.id == AssetVulnerability.asset_id)
        .join(Vulnerability, Vulnerability.id == AssetVulnerability.vulnerability_id)
        .filter(AssetVulnerability.status == Status.open)
    )
    if kev_only:
        query = query.filter(Vulnerability.in_kev.is_(True))
    if min_risk is not None:
        query = query.filter(AssetVulnerability.risk_score >= min_risk)
    if owner_team:
        query = query.filter(
            Asset.owner_team.is_(None)
            if owner_team == NOT_SET
            else Asset.owner_team == owner_team
        )
    groups = query.group_by(category, column).all()

    cells = []
    row_risk: dict[str, float] = {}
    col_risk: dict[str, float] = {}
    for group in groups:
        col = _column_key(columns, group.col)
        risk = round(float(group.total_risk or 0.0), 2)
        cells.append(
            {
                "row": group.row,
                "col": col,
                "findings": group.findings,
                "assets": group.assets,
                "total_risk": risk,
                "max_risk": float(group.max_risk or 0.0),
                "kev": group.kev or 0,
                "overdue": group.overdue or 0,
            }
        )
        row_risk[group.row] = row_risk.get(group.row, 0.0) + risk
        col_risk[col] = col_risk.get(col, 0.0) + risk

    # Rows in taxonomy order; columns in their natural order when they have
    # one, else the heaviest first. "Not set" always last.
    rows = [key for key in VULN_CATEGORIES if key in row_risk]
    rows += sorted(key for key in row_risk if key not in VULN_CATEGORIES)
    if columns == "asset_type":
        cols = [key for key in ASSET_TYPES if key in col_risk]
    elif columns == "business_criticality":
        cols = [key for key in CRITICALITY_ORDER if key in col_risk]
    elif columns == "internet_facing":
        cols = [key for key in ("true", "false") if key in col_risk]
    else:
        cols = sorted(
            (key for key in col_risk if key != NOT_SET), key=lambda k: -col_risk[k]
        )
    cols += [key for key in col_risk if key not in cols and key != NOT_SET]
    if NOT_SET in col_risk:
        cols.append(NOT_SET)

    return {
        "dimension": {"key": columns, "label": label},
        "dimensions": [
            {"key": key, "label": value[0]} for key, value in DIMENSIONS.items()
        ],
        "rows": [{"key": key, "label": VULN_CATEGORIES.get(key, key)} for key in rows],
        "columns": [{"key": key, "label": _column_label(columns, key)} for key in cols],
        "cells": cells,
    }


@router.get("/findings", response_model=PaginatedAssetVulnerabilityResponse)
def cell_findings(
    category: str = Query(max_length=32),
    columns: str = "asset_type",
    value: str = Query(max_length=128),
    kev_only: bool = False,
    min_risk: float | None = Query(None, ge=0, le=10),
    owner_team: str | None = Query(None, max_length=128),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """The open findings of one cell, worst first: what the matrix counted."""
    _dimension(columns)
    filters = FindingFilters(
        status_filter=Status.open,
        category=category,
        kev_only=kev_only,
        min_risk=min_risk,
        owner_team=owner_team,
    )
    if columns == "internet_facing":
        filters.internet_facing = value == "true"
    elif columns == "business_criticality":
        try:
            filters.business_criticality = Criticality(value)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Unknown criticality",
            ) from None
    elif columns == "owner_team" and owner_team:
        # The row filter and the cell both name a team: they must agree.
        if value != owner_team:
            return {"total": 0, "items": []}
    else:
        setattr(filters, columns, value)
    query = findings_query(db, filters)
    total = query.count()
    items = query.order_by(*RISK_ORDER).offset(skip).limit(limit).all()
    return {"total": total, "items": items}
