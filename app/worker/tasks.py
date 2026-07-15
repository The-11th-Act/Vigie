import logging
from app.worker.celery_app import celery_app
from app.db.database import SessionLocal
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability, AssetVulnerability
from app.services.remediation import calculate_remediation_deadline
from app.parsers.nessus import parse_nessus_report
from app.parsers.openvas import parse_openvas_report

logger = logging.getLogger(__name__)


@celery_app.task(name="app.worker.tasks.process_scan_file_task")
def process_scan_file_task(file_content_str: str, scan_type: str):
    db = SessionLocal()
    try:
        content_bytes = file_content_str.encode("utf-8")
        if scan_type.lower() == "nessus":
            findings = parse_nessus_report(content_bytes)
        elif scan_type.lower() == "openvas":
            findings = parse_openvas_report(content_bytes)
        else:
            return {"status": "error", "message": f"Unsupported scan type: {scan_type}"}

        if not findings:
            return {"status": "success", "processed_records": 0, "message": "No findings in scan file"}

        unique_ips = {f["ip_address"] for f in findings}
        unique_cves = {f["cve_id"] for f in findings}

        existing_assets = db.query(Asset).filter(Asset.ip_address.in_(list(unique_ips))).all()
        asset_cache = {a.ip_address: a for a in existing_assets}
        new_assets = {}

        existing_vulns = db.query(Vulnerability).filter(Vulnerability.cve_id.in_(list(unique_cves))).all()
        vuln_cache = {v.cve_id: v for v in existing_vulns}
        new_vulns = {}

        for f in findings:
            ip = f["ip_address"]
            if ip not in asset_cache and ip not in new_assets:
                new_assets[ip] = Asset(
                    ip_address=ip,
                    hostname=f["hostname"],
                    operating_system=f["operating_system"],
                    business_criticality="Medium",
                )

            cve = f["cve_id"]
            if cve not in vuln_cache and cve not in new_vulns:
                new_vulns[cve] = Vulnerability(
                    cve_id=cve,
                    title=f["title"],
                    description=f["description"],
                    cvss_score=f["cvss_score"],
                    severity=f["severity"],
                )

        if new_assets:
            db.add_all(new_assets.values())
        if new_vulns:
            db.add_all(new_vulns.values())
        db.commit()

        for a in new_assets.values():
            asset_cache[a.ip_address] = a
        for v in new_vulns.values():
            vuln_cache[v.cve_id] = v

        asset_ids = {a.id for a in asset_cache.values()}
        vuln_ids = {v.id for v in vuln_cache.values()}
        existing_assocs = db.query(AssetVulnerability).filter(
            AssetVulnerability.asset_id.in_(list(asset_ids)),
            AssetVulnerability.vulnerability_id.in_(list(vuln_ids)),
        ).all()
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
                    remediation_deadline=deadline,
                ))
                assoc_cache.add((asset.id, vuln.id))

        if new_assocs:
            chunk_size = 5000
            for i in range(0, len(new_assocs), chunk_size):
                db.add_all(new_assocs[i:i + chunk_size])
                db.commit()

        logger.info("Processed %d findings: %d new assets, %d new vulns, %d new assocs",
                     len(findings), len(new_assets), len(new_vulns), len(new_assocs))
        return {
            "status": "success",
            "processed_records": len(findings),
            "new_assets": len(new_assets),
            "new_vulnerabilities": len(new_vulns),
            "new_associations": len(new_assocs),
        }
    except Exception as e:
        db.rollback()
        logger.error("Scan processing failed: %s", e, exc_info=True)
        return {"status": "error", "message": str(e)}
    finally:
        db.close()