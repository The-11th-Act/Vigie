"""The backlog seen from the remediation side: what to deploy, and where.

A finding is asset × CVE; a remediation team works per fix. These queries fold
the open backlog onto remediation actions, so a Windows rollup closing forty
CVEs on a hundred servers is one line, weighed by all the risk it removes.
"""

import csv
import io
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import case, distinct, func, or_, select
from sqlalchemy.orm import Session

from app.core.scope import Scope
from app.models.asset import Asset
from app.models.remediation import FindingRemediation, RemediationAction
from app.models.vulnerability import AssetVulnerability, Status, Vulnerability
from app.services.export import neutralize
from app.services.remediation import is_overdue


@dataclass
class ActionFilters:
    kind: str | None = None
    search: str | None = None
    kev_only: bool = False


@dataclass
class HostEntry:
    asset_id: int
    hostname: str | None
    ip_address: str
    operating_system: str | None
    business_criticality: str
    internet_facing: bool
    installed_versions: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    max_risk: float = 0.0
    next_deadline: datetime | None = None
    in_kev: bool = False
    overdue: bool = False


def _open_links():
    """Each (action, finding) pair once: two sources prescribing the same KB
    for a finding must not count its risk twice."""
    return (
        select(FindingRemediation.action_id, FindingRemediation.finding_id)
        .distinct()
        .subquery()
    )


def action_summaries(
    db: Session, filters: ActionFilters, skip: int, limit: int, scope: Scope
) -> tuple[int, list[dict]]:
    """Open remediation actions, the one removing the most risk first, counted
    on the hosts ``scope`` covers only."""
    now = datetime.now(UTC)
    links = _open_links()
    findings = func.count(AssetVulnerability.id)
    total_risk = func.coalesce(func.sum(AssetVulnerability.risk_score), 0.0)

    query = (
        db.query(
            RemediationAction,
            findings.label("findings"),
            func.count(distinct(AssetVulnerability.asset_id)).label("assets"),
            func.count(distinct(AssetVulnerability.vulnerability_id)).label("cves"),
            func.sum(case((Vulnerability.in_kev.is_(True), 1), else_=0)).label("kev"),
            func.sum(
                case((AssetVulnerability.remediation_deadline < now, 1), else_=0)
            ).label("overdue"),
            total_risk.label("total_risk"),
            func.max(AssetVulnerability.risk_score).label("max_risk"),
            func.min(AssetVulnerability.remediation_deadline).label("next_deadline"),
        )
        .join(links, links.c.action_id == RemediationAction.id)
        .join(AssetVulnerability, AssetVulnerability.id == links.c.finding_id)
        .join(Vulnerability, Vulnerability.id == AssetVulnerability.vulnerability_id)
        .join(Asset, Asset.id == AssetVulnerability.asset_id)
        .filter(AssetVulnerability.status == Status.open)
    )
    query = scope.filter(query)
    if filters.kind:
        query = query.filter(RemediationAction.kind == filters.kind)
    if filters.search:
        pattern = f"%{filters.search.strip()}%"
        query = query.filter(
            or_(
                RemediationAction.reference.ilike(pattern),
                RemediationAction.title.ilike(pattern),
            )
        )
    if filters.kev_only:
        query = query.filter(Vulnerability.in_kev.is_(True))
    # Grouping by the primary key is enough for PostgreSQL to accept the
    # action's other columns in the select list.
    query = query.group_by(RemediationAction.id)

    total = query.order_by(None).count()
    rows = (
        query.order_by(total_risk.desc(), findings.desc(), RemediationAction.id)
        .offset(skip)
        .limit(limit)
        .all()
    )
    return total, [
        {
            "action": row.RemediationAction,
            "findings": row.findings,
            "assets": row.assets,
            "cves": row.cves,
            "kev": row.kev or 0,
            "overdue": row.overdue or 0,
            "total_risk": round(float(row.total_risk or 0.0), 2),
            "max_risk": float(row.max_risk or 0.0),
            "next_deadline": row.next_deadline,
        }
        for row in rows
    ]


def unremediated_summary(db: Session, scope: Scope) -> dict:
    """Open findings no scanner gave a fix for: work nobody can plan yet."""
    linked = select(FindingRemediation.finding_id)
    query = (
        db.query(
            func.count(AssetVulnerability.id).label("findings"),
            func.count(distinct(AssetVulnerability.asset_id)).label("assets"),
            func.coalesce(func.sum(AssetVulnerability.risk_score), 0.0).label(
                "total_risk"
            ),
        )
        .join(Asset, Asset.id == AssetVulnerability.asset_id)
        .filter(
            AssetVulnerability.status == Status.open,
            AssetVulnerability.id.notin_(linked),
        )
    )
    row = scope.filter(query).one()
    return {
        "findings": row.findings,
        "assets": row.assets,
        "total_risk": round(float(row.total_risk or 0.0), 2),
    }


def action_hosts(
    db: Session, action_id: int, scope: Scope, finding_ids: list[int] | None = None
) -> list[HostEntry]:
    """Every host in ``scope`` where the action still has open findings to
    close; only among ``finding_ids`` when given (the findings of one ticket)."""
    now = datetime.now(UTC)
    query = (
        db.query(AssetVulnerability, Asset, Vulnerability, FindingRemediation)
        .join(FindingRemediation, FindingRemediation.finding_id == AssetVulnerability.id)
        .join(Asset, Asset.id == AssetVulnerability.asset_id)
        .join(Vulnerability, Vulnerability.id == AssetVulnerability.vulnerability_id)
        .filter(
            FindingRemediation.action_id == action_id,
            AssetVulnerability.status == Status.open,
        )
        .order_by(AssetVulnerability.risk_score.desc(), Asset.id)
    )
    query = scope.filter(query)
    if finding_ids is not None:
        query = query.filter(AssetVulnerability.id.in_(finding_ids))
    rows = query.all()

    hosts: dict[int, HostEntry] = {}
    for finding, asset, vuln, link in rows:
        host = hosts.get(asset.id)
        if host is None:
            host = hosts[asset.id] = HostEntry(
                asset_id=asset.id,
                hostname=asset.hostname,
                ip_address=asset.ip_address,
                operating_system=asset.operating_system,
                business_criticality=getattr(
                    asset.business_criticality, "value", asset.business_criticality
                ),
                internet_facing=bool(asset.internet_facing),
            )
        _add_unique(host.installed_versions, link.installed_version)
        _add_unique(host.fixed_versions, link.fixed_version)
        _add_unique(host.cves, vuln.cve_id)
        host.max_risk = max(host.max_risk, finding.risk_score or 0.0)
        host.in_kev = host.in_kev or bool(vuln.in_kev)
        deadline = finding.remediation_deadline
        if deadline is not None and (
            host.next_deadline is None or _aware(deadline) < _aware(host.next_deadline)
        ):
            host.next_deadline = deadline
        host.overdue = host.overdue or is_overdue(deadline, now)

    # Worst host first, as the rows came.
    return list(hosts.values())


HOST_COLUMNS = (
    "hostname",
    "ip_address",
    "operating_system",
    "business_criticality",
    "internet_facing",
    "installed_version",
    "fixed_version",
    "cves",
    "max_risk",
    "next_deadline",
    "overdue",
)


def hosts_csv(hosts: list[HostEntry]) -> str:
    """The host list a deployment tool (SCCM, WSUS, Ansible) is fed from."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(HOST_COLUMNS)
    for host in hosts:
        row = [
            host.hostname,
            host.ip_address,
            host.operating_system,
            host.business_criticality,
            "yes" if host.internet_facing else "no",
            "; ".join(host.installed_versions),
            "; ".join(host.fixed_versions),
            " ".join(host.cves),
            host.max_risk,
            host.next_deadline.isoformat() if host.next_deadline else "",
            "yes" if host.overdue else "no",
        ]
        writer.writerow([neutralize(cell) for cell in row])
    # utf-8-sig for Excel, as the backlog export.
    return "﻿" + buffer.getvalue()


def _add_unique(values: list[str], value: str | None) -> None:
    if value and value not in values:
        values.append(value)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)
