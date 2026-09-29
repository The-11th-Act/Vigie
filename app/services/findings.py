"""The filtered backlog query, shared by the screen, its export and extracts.

One definition, so a CSV export or an API extract holds exactly what the
backlog screen shows for the same filters.
"""

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import or_
from sqlalchemy.orm import Session, contains_eager, selectinload

from app.models.asset import Asset, Criticality
from app.models.remediation import FindingRemediation
from app.models.vulnerability import AssetVulnerability, Status, Vulnerability
from app.services.categorization import UNCATEGORIZED

# Filter value for "not set" (no team, no environment, unknown type).
NOT_SET = "__none__"


@dataclass
class FindingFilters:
    status_filter: Status | None = None
    min_risk: float | None = None
    overdue_only: bool = False
    kev_only: bool = False
    min_epss: float | None = None
    internet_facing_only: bool = False
    owner_team: str | None = None
    category: str | None = None
    asset_type: str | None = None
    environment: str | None = None
    business_criticality: Criticality | None = None
    # Exact match, unlike internet_facing_only: False selects internal hosts.
    internet_facing: bool | None = None


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
        query = query.filter(_matches(Asset.owner_team, filters.owner_team))
    if filters.asset_type:
        query = query.filter(_matches(Asset.asset_type, filters.asset_type))
    if filters.environment:
        query = query.filter(_matches(Asset.environment, filters.environment))
    if filters.business_criticality:
        query = query.filter(Asset.business_criticality == filters.business_criticality)
    if filters.internet_facing is not None:
        query = query.filter(Asset.internet_facing.is_(filters.internet_facing))
    if filters.category:
        if filters.category in (UNCATEGORIZED, NOT_SET):
            query = query.filter(
                or_(
                    AssetVulnerability.category.is_(None),
                    AssetVulnerability.category == UNCATEGORIZED,
                )
            )
        else:
            query = query.filter(AssetVulnerability.category == filters.category)
    return query


def _matches(column, value: str):
    return column.is_(None) if value == NOT_SET else column == value
