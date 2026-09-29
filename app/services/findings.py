"""The filtered backlog query, shared by the screen, its export and extracts.

One definition, so a CSV export or an API extract holds exactly what the
backlog screen shows for the same filters.
"""

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.orm import Session, contains_eager, selectinload

from app.models.asset import Asset
from app.models.remediation import FindingRemediation
from app.models.vulnerability import AssetVulnerability, Status, Vulnerability


@dataclass
class FindingFilters:
    status_filter: Status | None = None
    min_risk: float | None = None
    overdue_only: bool = False
    kev_only: bool = False
    min_epss: float | None = None
    internet_facing_only: bool = False
    owner_team: str | None = None


def findings_query(db: Session, filters: FindingFilters):
    # Explicit joins rather than joinedload: the filters and the ranking read
    # the vulnerability and the asset, which a joinedload alias cannot offer.
    query = (
        db.query(AssetVulnerability)
        .join(AssetVulnerability.vulnerability)
        .join(AssetVulnerability.asset)
        .options(
            contains_eager(AssetVulnerability.vulnerability),
            contains_eager(AssetVulnerability.asset),
            selectinload(AssetVulnerability.detections),
            selectinload(AssetVulnerability.remediations).joinedload(
                FindingRemediation.action
            ),
        )
    )

    if filters.status_filter:
        query = query.filter(AssetVulnerability.status == filters.status_filter)
    if filters.min_risk is not None:
        query = query.filter(AssetVulnerability.risk_score >= filters.min_risk)
    if filters.overdue_only:
        query = query.filter(
            AssetVulnerability.status == Status.open,
            AssetVulnerability.remediation_deadline.isnot(None),
            AssetVulnerability.remediation_deadline < datetime.now(UTC),
        )
    if filters.kev_only:
        query = query.filter(Vulnerability.in_kev.is_(True))
    if filters.min_epss is not None:
        query = query.filter(Vulnerability.epss_score >= filters.min_epss)
    if filters.internet_facing_only:
        query = query.filter(Asset.internet_facing.is_(True))
    if filters.owner_team:
        query = query.filter(Asset.owner_team == filters.owner_team)
    return query
