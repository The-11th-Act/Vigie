from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from app.core.security import decode_token
from app.db.database import get_db
from app.models.asset import Asset
from app.models.vulnerability import AssetVulnerability, Severity, Status, Vulnerability
from app.services.risk_scoring import risk_level

router = APIRouter()


@router.get("/stats")
def get_dashboard_stats(
    db: Session = Depends(get_db), payload: dict = Depends(decode_token)
):
    now = datetime.now(timezone.utc)

    total_assets = db.query(func.count(Asset.id)).scalar() or 0

    severity_counts = (
        db.query(Vulnerability.severity, func.count(AssetVulnerability.id))
        .join(AssetVulnerability, AssetVulnerability.vulnerability_id == Vulnerability.id)
        .filter(AssetVulnerability.status == Status.open)
        .group_by(Vulnerability.severity)
        .all()
    )
    severity_dict = {s.value: 0 for s in (
        Severity.critical, Severity.high, Severity.medium, Severity.low
    )}
    for severity, count in severity_counts:
        severity_dict[_value_of(severity)] = count

    total_open_vulns = sum(severity_dict.values())

    status_counts = (
        db.query(AssetVulnerability.status, func.count(AssetVulnerability.id))
        .group_by(AssetVulnerability.status)
        .all()
    )
    status_dict = {s.value: 0 for s in Status}
    for finding_status, count in status_counts:
        status_dict[_value_of(finding_status)] = count

    overdue_count = (
        db.query(func.count(AssetVulnerability.id))
        .filter(
            AssetVulnerability.status == Status.open,
            AssetVulnerability.remediation_deadline.isnot(None),
            AssetVulnerability.remediation_deadline < now,
        )
        .scalar()
    ) or 0

    open_aggregates = (
        db.query(
            func.avg(Vulnerability.cvss_score),
            func.avg(AssetVulnerability.risk_score),
            func.max(AssetVulnerability.risk_score),
        )
        .join(AssetVulnerability, AssetVulnerability.vulnerability_id == Vulnerability.id)
        .filter(AssetVulnerability.status == Status.open)
        .one()
    )
    avg_cvss, avg_risk, max_risk = open_aggregates

    # Remediation rate: how much of everything ever detected is now closed out
    # as actually fixed. This is the number leadership asks for.
    total_findings = db.query(func.count(AssetVulnerability.id)).scalar() or 0
    remediated = status_dict.get(Status.remediated.value, 0)
    remediation_rate = (
        round(remediated / total_findings * 100, 1) if total_findings else 0.0
    )

    return {
        "total_assets": total_assets,
        "total_open_vulnerabilities": total_open_vulns,
        "severity_breakdown": severity_dict,
        "status_breakdown": status_dict,
        "overdue_count": overdue_count,
        "average_cvss": round(avg_cvss or 0, 2),
        "average_risk_score": round(avg_risk or 0, 2),
        "max_risk_score": round(max_risk or 0, 2),
        "remediation_rate_percent": remediation_rate,
    }


@router.get("/top-risks")
def get_top_risks(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    payload: dict = Depends(decode_token),
):
    """The highest-risk open findings — what to fix first."""
    findings = (
        db.query(AssetVulnerability)
        .options(
            joinedload(AssetVulnerability.vulnerability),
            joinedload(AssetVulnerability.asset),
        )
        .filter(AssetVulnerability.status == Status.open)
        .order_by(AssetVulnerability.risk_score.desc(), AssetVulnerability.id.desc())
        .limit(limit)
        .all()
    )

    now = datetime.now(timezone.utc)
    return [
        {
            "finding_id": f.id,
            "asset_id": f.asset_id,
            "hostname": f.asset.hostname if f.asset else None,
            "ip_address": f.asset.ip_address if f.asset else None,
            "business_criticality": _value_of(
                f.asset.business_criticality if f.asset else None
            ),
            "cve_id": f.vulnerability.cve_id if f.vulnerability else None,
            "title": f.vulnerability.title if f.vulnerability else None,
            "cvss_score": f.vulnerability.cvss_score if f.vulnerability else None,
            "severity": _value_of(f.vulnerability.severity if f.vulnerability else None),
            "risk_score": f.risk_score,
            "risk_level": risk_level(f.risk_score or 0.0),
            "remediation_deadline": f.remediation_deadline,
            "is_overdue": _is_past(f.remediation_deadline, now),
        }
        for f in findings
    ]


def _value_of(value):
    """Unwrap an enum member into its string value, passing through None."""
    return getattr(value, "value", value)


def _is_past(deadline, now) -> bool:
    if deadline is None:
        return False
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    return deadline < now
