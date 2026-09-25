"""Recompute stored risk scores.

``risk_score`` is persisted so the backlog can be sorted in SQL, which means
every input it depends on — CVSS, asset criticality, and time through the
overdue penalty — must trigger a recomputation when it changes. This is the
single place that does it.
"""

from datetime import datetime

from sqlalchemy.orm import Session, joinedload

from app.models.vulnerability import AssetVulnerability, Status
from app.services.risk_scoring import calculate_risk_score

BATCH_SIZE = 1_000


def rescore_open_findings(db: Session, *criteria, now: datetime | None = None) -> int:
    """Rescore the open findings matching ``criteria``; return how many changed.

    Without criteria, the whole open backlog is rescored — that is the daily
    job. The caller commits.
    """
    query = (
        db.query(AssetVulnerability)
        .options(
            joinedload(AssetVulnerability.asset),
            joinedload(AssetVulnerability.vulnerability),
        )
        .filter(AssetVulnerability.status == Status.open, *criteria)
        .order_by(AssetVulnerability.id)
    )

    changed = 0
    for finding in query.yield_per(BATCH_SIZE):
        if finding.asset is None or finding.vulnerability is None:
            continue
        score = calculate_risk_score(
            finding.vulnerability.cvss_score,
            finding.asset.business_criticality,
            finding.remediation_deadline,
            now,
        )
        if score != finding.risk_score:
            finding.risk_score = score
            changed += 1
    return changed
