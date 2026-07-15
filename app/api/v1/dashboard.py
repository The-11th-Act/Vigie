from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.db.database import get_db
from app.models.asset import Asset
from app.models.vulnerability import AssetVulnerability, Vulnerability

router = APIRouter()


@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    total_assets = db.query(Asset).count()

    severity_counts = (
        db.query(Vulnerability.severity, func.count(AssetVulnerability.id))
        .join(AssetVulnerability)
        .filter(AssetVulnerability.status == "Open")
        .group_by(Vulnerability.severity)
        .all()
    )

    severity_dict = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for severity, count in severity_counts:
        if severity in severity_dict:
            severity_dict[severity] = count

    total_open_vulns = sum(severity_dict.values())

    status_counts = (
        db.query(AssetVulnerability.status, func.count(AssetVulnerability.id))
        .group_by(AssetVulnerability.status)
        .all()
    )
    status_dict = {status: count for status, count in status_counts}

    overdue_count = (
        db.query(AssetVulnerability)
        .filter(
            AssetVulnerability.status == "Open",
            AssetVulnerability.remediation_deadline < func.now(),
        )
        .count()
    )

    avg_cvss = (
        db.query(func.avg(Vulnerability.cvss_score))
        .join(AssetVulnerability)
        .filter(AssetVulnerability.status == "Open")
        .scalar()
    )

    return {
        "total_assets": total_assets,
        "total_open_vulnerabilities": total_open_vulns,
        "severity_breakdown": severity_dict,
        "status_breakdown": status_dict,
        "overdue_count": overdue_count,
        "average_cvss": round(avg_cvss or 0, 2),
    }