"""Scan ingestion.

Kept deliberately free of Celery imports so it can be unit-tested against a
plain SQLAlchemy session; the worker task is a thin wrapper around it.
"""

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.asset import Asset, Criticality
from app.models.vulnerability import AssetVulnerability, Status, Vulnerability
from app.services.remediation import calculate_remediation_deadline
from app.services.risk_scoring import calculate_risk_score

logger = logging.getLogger(__name__)

CHUNK_SIZE = 5_000


@dataclass
class IngestionResult:
    processed_records: int = 0
    new_assets: int = 0
    new_vulnerabilities: int = 0
    new_associations: int = 0
    reopened: int = 0
    message: str = ""

    def as_dict(self) -> dict[str, Any]:
        data = {
            "processed_records": self.processed_records,
            "new_assets": self.new_assets,
            "new_vulnerabilities": self.new_vulnerabilities,
            "new_associations": self.new_associations,
            "reopened": self.reopened,
        }
        if self.message:
            data["message"] = self.message
        return data


def ingest_findings(
    db: Session, findings: Iterable[dict[str, Any]], scan_source: str
) -> IngestionResult:
    """Upsert assets, vulnerabilities and their associations from findings.

    Re-detections refresh ``last_seen_at`` and recompute the risk score rather
    than being silently dropped, so a finding that reappears after being marked
    remediated is reopened instead of hiding from the backlog.
    """
    findings = list(findings)
    if not findings:
        return IngestionResult(message="No findings in scan file")

    now = datetime.now(UTC)

    asset_cache, new_assets = _upsert_assets(db, findings)
    vuln_cache, new_vulns = _upsert_vulnerabilities(db, findings)
    # Flush so freshly created rows get their primary keys before we link them.
    db.flush()

    new_links, reopened = _upsert_associations(
        db, findings, asset_cache, vuln_cache, scan_source, now
    )
    db.commit()

    result = IngestionResult(
        processed_records=len(findings),
        new_assets=new_assets,
        new_vulnerabilities=new_vulns,
        new_associations=new_links,
        reopened=reopened,
    )
    logger.info(
        "Ingested %d findings from %s: %d new assets, %d new vulns, %d new links, %d reopened",
        result.processed_records,
        scan_source,
        result.new_assets,
        result.new_vulnerabilities,
        result.new_associations,
        result.reopened,
    )
    return result


def _upsert_assets(
    db: Session, findings: list[dict[str, Any]]
) -> tuple[dict[str, Asset], int]:
    unique_ips = {f["ip_address"] for f in findings}
    existing = db.query(Asset).filter(Asset.ip_address.in_(unique_ips)).all()
    cache: dict[str, Asset] = {a.ip_address: a for a in existing}
    created = 0

    for finding in findings:
        ip = finding["ip_address"]
        asset = cache.get(ip)

        if asset is None:
            asset = Asset(
                ip_address=ip,
                hostname=finding["hostname"],
                operating_system=finding["operating_system"],
                business_criticality=Criticality.medium,
            )
            db.add(asset)
            cache[ip] = asset
            created += 1
            continue

        # Enrich an existing asset when the scan knows something we do not.
        # Never overwrite a value an operator may have curated by hand.
        if not asset.hostname and finding["hostname"]:
            asset.hostname = finding["hostname"]
        if not asset.operating_system and finding["operating_system"]:
            asset.operating_system = finding["operating_system"]

    return cache, created


def _upsert_vulnerabilities(
    db: Session, findings: list[dict[str, Any]]
) -> tuple[dict[str, Vulnerability], int]:
    unique_cves = {f["cve_id"] for f in findings}
    existing = db.query(Vulnerability).filter(Vulnerability.cve_id.in_(unique_cves)).all()
    cache: dict[str, Vulnerability] = {v.cve_id: v for v in existing}
    created = 0

    for finding in findings:
        cve = finding["cve_id"]
        if cve in cache:
            continue
        vuln = Vulnerability(
            cve_id=cve,
            title=finding["title"],
            description=finding["description"],
            cvss_score=finding["cvss_score"],
            severity=finding["severity"],
        )
        db.add(vuln)
        cache[cve] = vuln
        created += 1

    return cache, created


def _upsert_associations(
    db: Session,
    findings: list[dict[str, Any]],
    asset_cache: dict[str, Asset],
    vuln_cache: dict[str, Vulnerability],
    scan_source: str,
    now: datetime,
) -> tuple[int, int]:
    asset_ids = {a.id for a in asset_cache.values()}
    vuln_ids = {v.id for v in vuln_cache.values()}

    existing = (
        db.query(AssetVulnerability)
        .filter(
            AssetVulnerability.asset_id.in_(asset_ids),
            AssetVulnerability.vulnerability_id.in_(vuln_ids),
        )
        .all()
    )
    assoc_cache: dict[tuple[int, int], AssetVulnerability] = {
        (a.asset_id, a.vulnerability_id): a for a in existing
    }

    new_assocs: list[AssetVulnerability] = []
    reopened = 0

    for finding in findings:
        asset = asset_cache[finding["ip_address"]]
        vuln = vuln_cache[finding["cve_id"]]
        key = (asset.id, vuln.id)

        deadline = calculate_remediation_deadline(finding["severity"], now)
        assoc = assoc_cache.get(key)

        if assoc is None:
            assoc = AssetVulnerability(
                asset_id=asset.id,
                vulnerability_id=vuln.id,
                status=Status.open,
                scan_source=scan_source,
                remediation_deadline=deadline,
                risk_score=calculate_risk_score(
                    finding["cvss_score"], asset.business_criticality, deadline, now
                ),
                last_seen_at=now,
            )
            new_assocs.append(assoc)
            assoc_cache[key] = assoc
            continue

        # Already known: refresh recency and recompute the score.
        assoc.last_seen_at = now
        assoc.scan_source = scan_source

        # Still detected after having been closed as fixed — reopen it.
        if assoc.status == Status.remediated:
            assoc.status = Status.open
            assoc.fixed_at = None
            assoc.remediation_deadline = deadline
            reopened += 1

        assoc.risk_score = calculate_risk_score(
            finding["cvss_score"],
            asset.business_criticality,
            assoc.remediation_deadline or deadline,
            now,
        )

    for i in range(0, len(new_assocs), CHUNK_SIZE):
        db.add_all(new_assocs[i : i + CHUNK_SIZE])
        db.flush()

    return len(new_assocs), reopened
