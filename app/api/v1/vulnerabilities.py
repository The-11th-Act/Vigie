from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi import status as http_status
from sqlalchemy import or_
from sqlalchemy.orm import Session, contains_eager, joinedload

from app.api.deps import get_or_404
from app.core.config import settings
from app.core.security import decode_token, require_admin
from app.db.database import get_db
from app.models.asset import Asset
from app.models.vulnerability import (
    CLOSED_STATUSES,
    RISK_ORDER,
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
    VulnerabilityUpdate,
)
from app.services.rescoring import rescore_open_findings

router = APIRouter()

MAX_LIMIT = 500

# Statuses whose selection must be justified for audit purposes.
STATUSES_REQUIRING_NOTE = {Status.false_positive, Status.risk_accepted}


@router.get("/", response_model=PaginatedVulnerabilityResponse)
def get_vulnerabilities(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=MAX_LIMIT),
    search: str | None = None,
    severity: Severity | None = None,
    min_cvss: float | None = Query(None, ge=0, le=10),
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


@router.put("/{vulnerability_id}", response_model=VulnerabilityResponse)
def update_vulnerability(
    vulnerability_id: int,
    vuln_in: VulnerabilityUpdate,
    db: Session = Depends(get_db),
    payload: dict = Depends(decode_token),
):
    """Correct a vulnerability's metadata (a wrong score, a truncated title).

    Changing the CVSS score re-scores every open finding for this CVE: risk is
    derived from it, so leaving the old scores would silently misrank the
    backlog.
    """
    vuln = get_or_404(db, Vulnerability, vulnerability_id)
    changes = vuln_in.model_dump(exclude_unset=True)

    for key, value in changes.items():
        setattr(vuln, key, value)

    if "cvss_score" in changes:
        rescore_open_findings(db, AssetVulnerability.vulnerability_id == vuln.id)

    db.commit()
    db.refresh(vuln)
    return vuln


@router.delete("/{vulnerability_id}", status_code=http_status.HTTP_204_NO_CONTENT)
def delete_vulnerability(
    vulnerability_id: int,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Remove a vulnerability and, by cascade, every finding referencing it.

    Admin-only, mirroring asset deletion: this discards triage history across
    potentially many assets at once.
    """
    vuln = get_or_404(db, Vulnerability, vulnerability_id)
    db.delete(vuln)
    db.commit()


@router.get("/findings", response_model=PaginatedAssetVulnerabilityResponse)
def get_findings(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=MAX_LIMIT),
    status_filter: Status | None = None,
    min_risk: float | None = Query(None, ge=0, le=10),
    overdue_only: bool = False,
    kev_only: bool = False,
    min_epss: float | None = Query(None, ge=0, le=1),
    internet_facing_only: bool = False,
    db: Session = Depends(get_db),
    payload: dict = Depends(decode_token),
):
    """The risk-ranked remediation backlog across every asset.

    Defaults to worst-risk-first, which is the view an analyst actually works
    from. Without this endpoint the platform stored a risk score nobody could
    order by.
    """
    # Explicit joins rather than joinedload: the filters and the ranking read
    # the vulnerability and the asset, which a joinedload alias cannot offer.
    query = (
        db.query(AssetVulnerability)
        .join(AssetVulnerability.vulnerability)
        .join(AssetVulnerability.asset)
        .options(
            contains_eager(AssetVulnerability.vulnerability),
            contains_eager(AssetVulnerability.asset),
        )
    )

    if status_filter:
        query = query.filter(AssetVulnerability.status == status_filter)
    if min_risk is not None:
        query = query.filter(AssetVulnerability.risk_score >= min_risk)
    if overdue_only:
        query = query.filter(
            AssetVulnerability.status == Status.open,
            AssetVulnerability.remediation_deadline.isnot(None),
            AssetVulnerability.remediation_deadline < datetime.now(UTC),
        )
    if kev_only:
        query = query.filter(Vulnerability.in_kev.is_(True))
    if min_epss is not None:
        query = query.filter(Vulnerability.epss_score >= min_epss)
    if internet_facing_only:
        query = query.filter(Asset.internet_facing.is_(True))

    total = query.count()
    items = query.order_by(*RISK_ORDER).offset(skip).limit(limit).all()
    return {"total": total, "items": items}


@router.get("/assets/{asset_id}", response_model=PaginatedAssetVulnerabilityResponse)
def get_asset_vulnerabilities(
    asset_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=MAX_LIMIT),
    status_filter: Status | None = None,
    db: Session = Depends(get_db),
    payload: dict = Depends(decode_token),
):
    # Eager loads avoid one extra SELECT per row for the nested vulnerability
    # and asset, both read by the response (risk_factors included).
    query = (
        db.query(AssetVulnerability)
        .join(AssetVulnerability.vulnerability)
        .options(
            contains_eager(AssetVulnerability.vulnerability),
            joinedload(AssetVulnerability.asset),
        )
        .filter(AssetVulnerability.asset_id == asset_id)
    )

    if status_filter:
        query = query.filter(AssetVulnerability.status == status_filter)

    total = query.count()
    items = query.order_by(*RISK_ORDER).offset(skip).limit(limit).all()
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
            status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f"A status_note is required to set status to "
                f"'{update_in.status.value}'"
            ),
        )

    accepted_until = _acceptance_end(update_in)

    previous_status = _status_value(finding.status)

    finding.status = update_in.status
    finding.accepted_until = accepted_until
    if update_in.status_note is not None:
        finding.status_note = update_in.status_note

    if update_in.status in CLOSED_STATUSES:
        finding.fixed_at = finding.fixed_at or datetime.now(UTC)
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
            accepted_until=accepted_until,
        )
    )

    db.commit()
    db.refresh(finding)
    return finding


@router.get(
    "/findings/{finding_id}/history", response_model=list[FindingAuditLogResponse]
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


def _acceptance_end(update_in: AssetVulnerabilityUpdate) -> datetime | None:
    """When a risk acceptance ends: requested, or the default; never unbounded.

    An acceptance without an end date was a way to make a finding vanish from
    the backlog for good. It now lasts RISK_ACCEPTANCE_DEFAULT_DAYS unless the
    analyst says otherwise, and at most RISK_ACCEPTANCE_MAX_DAYS.
    """
    requested = update_in.accepted_until
    if update_in.status != Status.risk_accepted:
        if requested is not None:
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="accepted_until only applies to 'Risk Accepted'",
            )
        return None

    now = datetime.now(UTC)
    if requested is None:
        return now + timedelta(days=settings.RISK_ACCEPTANCE_DEFAULT_DAYS)

    if requested.tzinfo is None:
        requested = requested.replace(tzinfo=UTC)
    if requested <= now:
        raise HTTPException(
            status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="accepted_until must be in the future",
        )
    # A minute of slack, so "exactly the maximum" picked in a form is accepted.
    latest = now + timedelta(days=settings.RISK_ACCEPTANCE_MAX_DAYS, minutes=1)
    if requested > latest:
        raise HTTPException(
            status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                "A risk acceptance lasts at most "
                f"{settings.RISK_ACCEPTANCE_MAX_DAYS} days"
            ),
        )
    return requested


def _status_value(status) -> str:
    return getattr(status, "value", status)


def _user_id(payload: dict) -> int | None:
    try:
        return int(payload["sub"])
    except (KeyError, TypeError, ValueError):
        return None
