from app.worker.celery_app import celery_app
from app.db.database import SessionLocal
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability, AssetVulnerability
from app.services.remediation import calculate_remediation_deadline
from app.parsers.nessus import parse_nessus_report
from app.parsers.openvas import parse_openvas_report
import datetime

@celery_app.task(name="app.worker.tasks.process_scan_file_task")
def process_scan_file_task(file_content_str: str, scan_type: str):
    db = SessionLocal()
    try:
        content_bytes = file_content_str.encode('utf-8')
        if scan_type.lower() == "nessus":
            findings = parse_nessus_report(content_bytes)
        elif scan_type.lower() == "openvas":
            findings = parse_openvas_report(content_bytes)
        else:
            return {"status": "error", "message": f"Unsupported scan type: {scan_type}"}

        # 1. Cache existing Assets
        existing_assets = db.query(Asset).all()
        asset_cache = {a.ip_address: a for a in existing_assets}
        new_assets = {}

        # 2. Cache existing Vulnerabilities
        existing_vulns = db.query(Vulnerability).all()
        vuln_cache = {v.cve_id: v for v in existing_vulns}
        new_vulns = {}

        # First Pass: Identify all new Assets and Vulnerabilities
        for f in findings:
            if f["ip_address"] not in asset_cache and f["ip_address"] not in new_assets:
                new_assets[f["ip_address"]] = Asset(
                    ip_address=f["ip_address"],
                    hostname=f["hostname"],
                    operating_system=f["operating_system"],
                    business_criticality="Medium"
                )
            
            if f["cve_id"] not in vuln_cache and f["cve_id"] not in new_vulns:
                new_vulns[f["cve_id"]] = Vulnerability(
                    cve_id=f["cve_id"],
                    title=f["title"],
                    description=f["description"],
                    cvss_score=f["cvss_score"],
                    severity=f["severity"]
                )

        # Bulk insert new assets and vulnerabilities
        if new_assets:
            db.add_all(new_assets.values())
        if new_vulns:
            db.add_all(new_vulns.values())
        db.commit()

        # Refresh caches with newly inserted objects to get their IDs
        for a in new_assets.values():
            asset_cache[a.ip_address] = a
        for v in new_vulns.values():
            vuln_cache[v.cve_id] = v

        # 3. Handle AssetVulnerability relationships
        existing_assocs = db.query(AssetVulnerability).all()
        assoc_cache = {(a.asset_id, a.vulnerability_id) for a in existing_assocs}
        
        new_assocs = []
        for f in findings:
            asset = asset_cache[f["ip_address"]]
            vuln = vuln_cache[f["cve_id"]]
            
            if (asset.id, vuln.id) not in assoc_cache:
                deadline = calculate_remediation_deadline(f["severity"])
                new_assocs.append(AssetVulnerability(
                    asset_id=asset.id,
                    vulnerability_id=vuln.id,
                    status="Open",
                    scan_source=scan_type,
                    remediation_deadline=deadline
                ))
                assoc_cache.add((asset.id, vuln.id))
        
        # Bulk insert new associations
        if new_assocs:
            # Insert in chunks of 5000 to avoid large transactions
            chunk_size = 5000
            for i in range(0, len(new_assocs), chunk_size):
                db.add_all(new_assocs[i:i + chunk_size])
                db.commit()
                
        count = len(findings)
        return {"status": "success", "processed_records": count}
    except Exception as e:
        db.rollback()
        return {"status": "error", "message": str(e)}
    finally:
        db.close()
