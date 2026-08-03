from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status as http_status
from sqlalchemy import or_
from sqlalchemy.orm import Session, joinedload

from app.api.deps import get_or_404
from app.core.security import decode_token
from app.db.database import get_db
from app.models.vulnerability import (
    CLOSED_STATUSES,
    AssetVulnerability,
    FindingAuditLog,
    Severity,
    Status,
    Vulnerability,
)
from app.schemas.vulnerability import (
    AssetVulnerabilityResponse,
    AssetVulnerabilityUpdate,
    FindingAuditLogResponse,
    PaginatedAssetVulnerabilityResponse,
    PaginatedVulnerabilityResponse,
    VulnerabilityCreate,
    VulnerabilityResponse,
)

router = APIRouter()

MAX_LIMIT = 500

# Statuses whose selection must be justified for audit purposes.
STATUSES_REQUIRING_NOTE = {Status.false_positive, Status.risk_accepted}


@router.get("/", response_model=PaginatedVulnerabilityResponse)
def get_vulnerabilities(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=MAX_LIMIT),
    search: Optional[str] = None,
    severity: Optional[Severity] = None,
    min_cvss: Optional[float] = Query(None, ge=0, le=10),
    db: Session = Depends(get_db),
    payload: dict = Depends(decode_token),
):
    query = db.query(Vulnerability)

    if search:
        pattern = f"%{search}%"
        query = query.filter(
            or_(
                Vulnerability.cve_id.ilike(pattern),
                Vulnerability.title.ilike(pattern),
            )
        )
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    if min_cvss is not None:
        query = query.filter(Vulnerability.cvss_score >= min_cvss)

    total = query.count()
    items = (
        query.order_by(Vulnerability.cvss_score.desc(), Vulnerability.id.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return {"total": total, "items": items}


@router.post(
    "/", response_model=VulnerabilityResponse, status_code=http_status.HTTP_201_CREATED
)
def create_vulnerability(
    vuln_in: VulnerabilityCreate,
    db: Session = Depends(get_db),
    payload: dict = Depends(decode_token),
):
    existing = (
        db.query(Vulnerability).filter(Vulnerability.cve_id == vuln_in.cve_id).first()
    )
    if existing:
        raise HTTPException(
            status_code=http_status.HTTP_409_CONFLICT,
            detail="Vulnerability with this CVE ID already exists",
        )

    db_vuln = Vulnerability(**vuln_in.model_dump())
    db.add(db_vuln)
    db.commit()
    db.refresh(db_vuln)
    return db_vuln


@router.get("/findings", response_model=PaginatedAssetVulnerabilityResponse)
def get_findings(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=MAX_LIMIT),
    status_filter: Optional[Status] = None,
    min_risk: Optional[float] = Query(None, ge=0, le=10),
    overdue_only: bool = False,
    db: Session = Depends(get_db),
    payload: dict = Depends(decode_token),
):
    """The risk-ranked remediation backlog across every asset.

    Defaults to worst-risk-first, which is the view an analyst actually works
    from. Without this endpoint the platform stored a risk score nobody could
    order by.
    """
    query = db.query(AssetVulnerability).options(
        joinedload(AssetVulnerability.vulnerability),
        joinedload(AssetVulnerability.asset),
    )

    if status_filter:
        query = query.filter(AssetVulnerability.status == status_filter)
    if min_risk is not None:
        query = query.filter(AssetVulnerability.risk_score >= min_risk)
    if overdue_only:
        query = query.filter(
            AssetVulnerability.status == Status.open,
            AssetVulnerability.remediation_deadline.isnot(None),
            AssetVulnerability.remediation_deadline < datetime.now(timezone.utc),
        )

    total = query.count()
    items = (
        query.order_by(
            AssetVulnerability.risk_score.desc(), AssetVulnerability.id.desc()
        )
        .offset(skip)
        .limit(limit)
        .all()
    )
    return {"total": total, "items": items}


@router.get("/assets/{asset_id}", response_model=PaginatedAssetVulnerabilityResponse)
def get_asset_vulnerabilities(
    asset_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=MAX_LIMIT),
    status_filter: Optional[Status] = None,
    db: Session = Depends(get_db),
    payload: dict = Depends(decode_token),
):
    # joinedload avoids one extra SELECT per row for the nested vulnerability.
    query = (
        db.query(AssetVulnerability)
        .options(joinedload(AssetVulnerability.vulnerability))
        .filter(AssetVulnerability.asset_id == asset_id)
    )

    if status_filter:
        query = query.filter(AssetVulnerability.status == status_filter)

    total = query.count()
    items = (
        query.order_by(
            AssetVulnerability.risk_score.desc(), AssetVulnerability.id.desc()
        )
        .offset(skip)
        .limit(limit)
        .all()
    )
    return {"total": total, "items": items}


@router.patch("/findings/{finding_id}", response_model=AssetVulnerabilityResponse)
def update_finding_status(
    finding_id: int,
    update_in: AssetVulnerabilityUpdate,
    db: Session = Depends(get_db),
    payload: dict = Depends(decode_token),
):
    """Triage a finding: remediate it, accept the risk, or dismiss it."""
    finding = get_or_404(db, AssetVulnerability, finding_id)

    if update_in.status in STATUSES_REQUIRING_NOTE and not update_in.status_note:
        raise HTTPException(
            status_code=http_status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"A status_note is required to set status to "
                f"'{update_in.status.value}'"
            ),
        )

    previous_status = _status_value(finding.status)

    finding.status = update_in.status
    if update_in.status_note is not None:
        finding.status_note = update_in.status_note

    if update_in.status in CLOSED_STATUSES:
        finding.fixed_at = finding.fixed_at or datetime.now(timezone.utc)
    else:
        # Reopening clears the closure timestamp so SLA tracking resumes.
        finding.fixed_at = None

    # Written before the commit so the decision and its trail land together:
    # an audit entry that can be lost independently is worth little.
    db.add(
        FindingAuditLog(
            finding_id=finding.id,
            user_id=_user_id(payload),
            username=payload.get("username"),
            old_status=previous_status,
            new_status=_status_value(update_in.status),
            status_note=update_in.status_note,
        )
    )

    db.commit()
    db.refresh(finding)
    return finding


@router.get(
    "/findings/{finding_id}/history", response_model=List[FindingAuditLogResponse]
)
def get_finding_history(
    finding_id: int,
    db: Session = Depends(get_db),
    payload: dict = Depends(decode_token),
):
    """Who changed this finding's status, when, and with what justification."""
    get_or_404(db, AssetVulnerability, finding_id)

    return (
        db.query(FindingAuditLog)
        .filter(FindingAuditLog.finding_id == finding_id)
        .order_by(FindingAuditLog.id.desc())
        .all()
    )


def _status_value(status) -> str:
    return getattr(status, "value", status)


def _user_id(payload: dict) -> Optional[int]:
    try:
        return int(payload["sub"])
    except (KeyError, TypeError, ValueError):
        return None
