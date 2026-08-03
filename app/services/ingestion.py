"""Scan ingestion.

Kept deliberately free of Celery imports so it can be unit-tested against a
plain SQLAlchemy session; the worker task is a thin wrapper around it.
"""
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Tuple

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.asset import Asset
from app.models.vulnerability import AssetVulnerability, Status, Vulnerability
from app.services.asset_policy import criticality_for
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
    auto_remediated: int = 0
    message: str = ""

    def as_dict(self) -> Dict[str, Any]:
        data = {
            "processed_records": self.processed_records,
            "new_assets": self.new_assets,
            "new_vulnerabilities": self.new_vulnerabilities,
            "new_associations": self.new_associations,
            "reopened": self.reopened,
            "auto_remediated": self.auto_remediated,
        }
        if self.message:
            data["message"] = self.message
        return data


def ingest_findings(
    db: Session, findings: Iterable[Dict[str, Any]], scan_source: str
) -> IngestionResult:
    """Upsert assets, vulnerabilities and their associations from findings.

    Re-detections refresh ``last_seen_at`` and recompute the risk score rather
    than being silently dropped, so a finding that reappears after being marked
    remediated is reopened instead of hiding from the backlog.
    """
    findings = list(findings)
    if not findings:
        return IngestionResult(message="No findings in scan file")

    now = datetime.now(timezone.utc)

    trusted_hostnames = _unambiguous_hostnames(findings)

    asset_cache, new_assets = _upsert_assets(db, findings, trusted_hostnames)
    vuln_cache, new_vulns = _upsert_vulnerabilities(db, findings)
    # Flush so freshly created rows get their primary keys before we link them.
    db.flush()

    new_links, reopened, seen_ids = _upsert_associations(
        db, findings, asset_cache, vuln_cache, scan_source, now, trusted_hostnames
    )
    auto_remediated = _close_unseen_findings(db, scan_source, seen_ids, now)
    db.commit()

    result = IngestionResult(
        processed_records=len(findings),
        new_assets=new_assets,
        new_vulnerabilities=new_vulns,
        new_associations=new_links,
        reopened=reopened,
        auto_remediated=auto_remediated,
    )
    logger.info(
        "Ingested %d findings from %s: %d new assets, %d new vulns, %d new links, "
        "%d reopened, %d auto-remediated",
        result.processed_records,
        scan_source,
        result.new_assets,
        result.new_vulnerabilities,
        result.new_associations,
        result.reopened,
        result.auto_remediated,
    )
    return result


def _close_unseen_findings(
    db: Session, scan_source: str, seen_ids: set, now: datetime
) -> int:
    """Close findings this source has stopped reporting.

    A patched host used to leave its findings open forever, so the backlog
    drifted away from reality. Closure waits for several consecutive misses
    rather than one: a partial or failed scan would otherwise wrongly close
    everything it did not cover.
    """
    threshold = settings.AUTO_REMEDIATE_AFTER_MISSES
    if threshold <= 0:
        return 0

    stale = (
        db.query(AssetVulnerability)
        .filter(
            AssetVulnerability.scan_source == scan_source,
            AssetVulnerability.status == Status.open,
            AssetVulnerability.id.notin_(seen_ids) if seen_ids else True,
        )
        .all()
    )

    closed = 0
    for finding in stale:
        finding.missed_scans = (finding.missed_scans or 0) + 1
        if finding.missed_scans >= threshold:
            finding.status = Status.remediated
            finding.fixed_at = now
            closed += 1

    if closed:
        logger.info(
            "Closed %d finding(s) absent from the last %d %s scans",
            closed,
            threshold,
            scan_source,
        )
    return closed


def _asset_key(finding: Dict[str, Any], trusted_hostnames: set) -> str:
    """Stable lookup key for the asset a finding belongs to.

    Prefers the hostname, which survives a DHCP lease change, and falls back to
    the address when the source reports no name — or when the name turned out
    to be ambiguous within this scan.
    """
    hostname = _normalized_hostname(finding.get("hostname"))
    if hostname and hostname in trusted_hostnames:
        return f"h:{hostname}"
    return f"i:{finding['ip_address']}"


def _normalized_hostname(hostname: Any) -> str:
    return str(hostname).strip().lower() if hostname else ""


def _unambiguous_hostnames(findings: List[Dict[str, Any]]) -> set:
    """Hostnames safe to match on, i.e. seen at exactly one address here.

    A single scan reporting the same name at several addresses proves the name
    is not unique — default names like "localhost" or "ubuntu" are common — and
    matching on it would merge genuinely distinct hosts into one asset, taking
    their findings with them. Those fall back to address matching. The DHCP case
    this is meant to serve looks different: the same name at a new address in a
    *later* scan.
    """
    addresses_by_hostname: Dict[str, set] = {}
    for finding in findings:
        hostname = _normalized_hostname(finding.get("hostname"))
        if hostname:
            addresses_by_hostname.setdefault(hostname, set()).add(
                finding["ip_address"]
            )

    return {
        hostname
        for hostname, addresses in addresses_by_hostname.items()
        if len(addresses) == 1
    }


def _upsert_assets(
    db: Session, findings: List[Dict[str, Any]], trusted_hostnames: set
) -> Tuple[Dict[str, Asset], int]:
    """Resolve each finding to an asset, creating one only when truly new.

    Matching on the address alone meant a DHCP host produced a fresh asset —
    and a fresh copy of its whole backlog — every time its lease changed. The
    hostname is checked first when the scan provides one, and an asset already
    known by address is enriched rather than duplicated.
    """
    unique_ips = {f["ip_address"] for f in findings}

    query = db.query(Asset).filter(Asset.ip_address.in_(unique_ips))
    if trusted_hostnames:
        query = db.query(Asset).filter(
            or_(
                Asset.ip_address.in_(unique_ips),
                func.lower(Asset.hostname).in_(trusted_hostnames),
            )
        )
    existing = query.all()

    by_hostname: Dict[str, Asset] = {
        _normalized_hostname(a.hostname): a for a in existing if a.hostname
    }
    by_ip: Dict[str, Asset] = {a.ip_address: a for a in existing}

    cache: Dict[str, Asset] = {}
    created = 0

    for finding in findings:
        ip = finding["ip_address"]
        hostname = _normalized_hostname(finding.get("hostname"))
        if hostname not in trusted_hostnames:
            hostname = ""

        asset = by_hostname.get(hostname) if hostname else None
        if asset is None:
            asset = by_ip.get(ip)

        if asset is None:
            asset = Asset(
                ip_address=ip,
                hostname=finding["hostname"],
                operating_system=finding["operating_system"],
                business_criticality=criticality_for(ip),
            )
            db.add(asset)
            created += 1
        else:
            # Enrich an existing asset when the scan knows something we do not.
            # Never overwrite a value an operator may have curated by hand.
            if not asset.hostname and finding["hostname"]:
                asset.hostname = finding["hostname"]
            if not asset.operating_system and finding["operating_system"]:
                asset.operating_system = finding["operating_system"]
            # Matched by name on a new address: the host moved, so follow it.
            if hostname and asset.ip_address != ip:
                logger.info(
                    "Asset '%s' moved from %s to %s", hostname, asset.ip_address, ip
                )
                asset.ip_address = ip

        if hostname:
            by_hostname[hostname] = asset
        by_ip[ip] = asset
        cache[_asset_key(finding, trusted_hostnames)] = asset

    return cache, created


def _upsert_vulnerabilities(
    db: Session, findings: List[Dict[str, Any]]
) -> Tuple[Dict[str, Vulnerability], int]:
    unique_cves = {f["cve_id"] for f in findings}
    existing = db.query(Vulnerability).filter(Vulnerability.cve_id.in_(unique_cves)).all()
    cache: Dict[str, Vulnerability] = {v.cve_id: v for v in existing}
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
    findings: List[Dict[str, Any]],
    asset_cache: Dict[str, Asset],
    vuln_cache: Dict[str, Vulnerability],
    scan_source: str,
    now: datetime,
    trusted_hostnames: set,
) -> Tuple[int, int, set]:
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
    assoc_cache: Dict[Tuple[int, int], AssetVulnerability] = {
        (a.asset_id, a.vulnerability_id): a for a in existing
    }

    new_assocs: List[AssetVulnerability] = []
    reopened = 0

    for finding in findings:
        asset = asset_cache[_asset_key(finding, trusted_hostnames)]
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
        # Seen again, so any run of misses is broken.
        assoc.missed_scans = 0

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

    # Flushed above, so the new rows now have ids and can be excluded from the
    # stale sweep along with the ones that were already known.
    seen_ids = {assoc.id for assoc in assoc_cache.values() if assoc.id is not None}

    return len(new_assocs), reopened, seen_ids
