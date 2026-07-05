from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.db.database import get_db
from app.models.asset import Asset
from app.models.vulnerability import AssetVulnerability, Vulnerability

router = APIRouter()

@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    # Total Assets
    total_assets = db.query(Asset).count()
    
    # Vulnerabilities by Severity (Open)
    severity_counts = db.query(
        Vulnerability.severity, 
        func.count(AssetVulnerability.id)
    ).join(AssetVulnerability).filter(
        AssetVulnerability.status == "Open"
    ).group_by(Vulnerability.severity).all()
    
    severity_dict = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }
    for severity, count in severity_counts:
        if severity in severity_dict:
            severity_dict[severity] = count
            
    # Total Open Vulnerabilities
    total_open_vulns = sum(severity_dict.values())
    
    # Status Breakdown
    status_counts = db.query(
        AssetVulnerability.status,
        func.count(AssetVulnerability.id)
    ).group_by(AssetVulnerability.status).all()
    
    status_dict = {status: count for status, count in status_counts}
    
    return {
        "total_assets": total_assets,
        "total_open_vulnerabilities": total_open_vulns,
        "severity_breakdown": severity_dict,
        "status_breakdown": status_dict
    }
