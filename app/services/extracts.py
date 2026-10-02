"""Extracts: the platform's data as CSV or JSON, for scripts and reporting.

Each dataset declares its module, columns and typed filters, and yields its
rows from a streamed query. The same definitions drive the extract builder
screen (``describe``), the one-off download and the saved extracts, so what a
reporting tool pulls is exactly what the builder previewed.
"""

import csv
import json
import tempfile
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from app.core.scope import Scope
from app.models.asset import Asset, Criticality
from app.models.remediation import RemediationKind
from app.models.ticket import ACTIVE_TICKET_STATUSES, RemediationTicket, TicketStatus
from app.models.vulnerability import (
    RISK_ORDER,
    AssetVulnerability,
    Status,
    Vulnerability,
)
from app.services.categorization import ASSET_TYPES, VULN_CATEGORIES
from app.services.export import (
    BATCH_SIZE,
    SPOOL_IN_MEMORY_BYTES,
    _chunks,
    _iso,
    _joined,
    _remediation,
    neutralize,
)
from app.services.findings import FindingFilters, findings_query
from app.services.remediation import is_overdue
from app.services.remediation_plan import ActionFilters, action_summaries
from app.services.risk_scoring import risk_level
from app.services.tickets import ticket_metrics
from app.services.xlsx import write_xlsx

FORMATS = ("csv", "json", "xlsx")
# Enough for a whole backlog; a preview asks for far fewer.
MAX_ROWS = 1_000_000


@dataclass(frozen=True)
class Column:
    key: str
    label: str
    get: Callable[[Any], Any]


@dataclass(frozen=True)
class Filter:
    key: str
    label: str
    type: str  # bool | float | enum | str
    options: tuple[str, ...] = ()
    minimum: float | None = None
    maximum: float | None = None


@dataclass(frozen=True)
class Dataset:
    key: str
    label: str
    module: str
    columns: tuple[Column, ...]
    filters: tuple[Filter, ...]
    # (db, filters, limit, scope): the rows the caller's scope may see.
    rows: Callable[[Session, dict, int | None, Scope], Iterator[Any]]
    column_keys: tuple[str, ...] = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "column_keys", tuple(c.key for c in self.columns))


# --- findings ---------------------------------------------------------------


def _finding_rows(db: Session, filters: dict, limit: int | None, scope: Scope):
    status = filters.get("status")
    query = findings_query(
        db,
        FindingFilters(
            status_filter=Status(status) if status else None,
            min_risk=filters.get("min_risk"),
            overdue_only=filters.get("overdue_only", False),
            kev_only=filters.get("kev_only", False),
            min_epss=filters.get("min_epss"),
            internet_facing_only=filters.get("internet_facing_only", False),
            owner_team=filters.get("owner_team"),
            category=filters.get("category"),
            asset_type=filters.get("asset_type"),
            environment=filters.get("environment"),
            business_criticality=filters.get("business_criticality"),
        ),
        scope,
    ).order_by(*RISK_ORDER)
    if limit is not None:
        query = query.limit(limit)
    yield from query.yield_per(BATCH_SIZE)


def _deadline_passed(finding) -> bool:
    return finding.status == Status.open and is_overdue(finding.remediation_deadline)


FINDINGS = Dataset(
    key="findings",
    label="Findings (risk backlog)",
    module="backlog",
    columns=(
        Column("finding_id", "Finding id", lambda f: f.id),
        Column("asset", "Asset", lambda f: f.asset.hostname),
        Column("ip_address", "IP address", lambda f: f.asset.ip_address),
        Column("owner_team", "Owner team", lambda f: f.asset.owner_team),
        Column("asset_type", "Asset type", lambda f: f.asset.asset_type),
        Column("environment", "Environment", lambda f: f.asset.environment),
        Column(
            "business_criticality",
            "Business criticality",
            lambda f: f.asset.business_criticality,
        ),
        Column("internet_facing", "Internet-facing", lambda f: f.asset.internet_facing),
        Column("cve_id", "CVE", lambda f: f.vulnerability.cve_id),
        Column("title", "Title", lambda f: f.vulnerability.title),
        Column("category", "Category", lambda f: f.category),
        Column("remediation", "Fix", _remediation),
        Column(
            "fixed_version",
            "Fixed version",
            lambda f: _joined(link.fixed_version for link in f.remediations),
        ),
        Column("cvss", "CVSS", lambda f: f.vulnerability.cvss_score),
        Column("epss", "EPSS", lambda f: f.vulnerability.epss_score),
        Column("in_kev", "In CISA KEV", lambda f: f.vulnerability.in_kev),
        Column("risk_score", "Risk score", lambda f: f.risk_score),
        Column("risk_level", "Risk level", lambda f: risk_level(f.risk_score or 0.0)),
        Column("status", "Status", lambda f: f.status),
        Column("remediation_deadline", "Deadline", lambda f: f.remediation_deadline),
        Column("overdue", "Overdue", _deadline_passed),
        Column("accepted_until", "Accepted until", lambda f: f.accepted_until),
        Column("detected_at", "Detected", lambda f: f.detected_at),
        Column("last_seen_at", "Last seen", lambda f: f.last_seen_at),
        Column("sources", "Sources", lambda f: _joined(d.source for d in f.detections)),
    ),
    filters=(
        Filter("status", "Status", "enum", tuple(s.value for s in Status)),
        Filter("min_risk", "Minimum risk", "float", minimum=0, maximum=10),
        Filter("overdue_only", "Overdue only", "bool"),
        Filter("kev_only", "Known exploited (KEV) only", "bool"),
        Filter("min_epss", "Minimum EPSS", "float", minimum=0, maximum=1),
        Filter("internet_facing_only", "Internet-facing only", "bool"),
        Filter("owner_team", "Owner team", "str"),
        Filter("category", "Category", "enum", tuple(VULN_CATEGORIES)),
        Filter("asset_type", "Asset type", "enum", tuple(ASSET_TYPES)),
        Filter("environment", "Environment", "str"),
        Filter(
            "business_criticality",
            "Business criticality",
            "enum",
            tuple(c.value for c in Criticality),
        ),
    ),
    rows=_finding_rows,
)


# --- assets -----------------------------------------------------------------


def _asset_rows(db: Session, filters: dict, limit: int | None, scope: Scope):
    open_findings = (
        db.query(
            AssetVulnerability.asset_id.label("asset_id"),
            func.count(AssetVulnerability.id).label("open_findings"),
            func.max(AssetVulnerability.risk_score).label("max_risk"),
        )
        .filter(AssetVulnerability.status == Status.open)
        .group_by(AssetVulnerability.asset_id)
        .subquery()
    )
    query = db.query(
        Asset,
        func.coalesce(open_findings.c.open_findings, 0),
        func.coalesce(open_findings.c.max_risk, 0.0),
    ).outerjoin(open_findings, open_findings.c.asset_id == Asset.id)
    query = scope.filter(query)
    if filters.get("criticality"):
        query = query.filter(Asset.business_criticality == filters["criticality"])
    if filters.get("owner_team"):
        query = query.filter(Asset.owner_team == filters["owner_team"])
    if filters.get("internet_facing_only"):
        query = query.filter(Asset.internet_facing.is_(True))
    if filters.get("asset_type"):
        query = query.filter(Asset.asset_type == filters["asset_type"])
    if filters.get("environment"):
        query = query.filter(Asset.environment == filters["environment"])
    query = query.order_by(Asset.id)
    if limit is not None:
        query = query.limit(limit)
    yield from query.yield_per(BATCH_SIZE)


ASSETS = Dataset(
    key="assets",
    label="Assets",
    module="assets",
    columns=(
        Column("id", "Asset id", lambda r: r[0].id),
        Column("hostname", "Hostname", lambda r: r[0].hostname),
        Column("ip_address", "IP address", lambda r: r[0].ip_address),
        Column("operating_system", "Operating system", lambda r: r[0].operating_system),
        Column(
            "business_criticality",
            "Business criticality",
            lambda r: r[0].business_criticality,
        ),
        Column("internet_facing", "Internet-facing", lambda r: r[0].internet_facing),
        Column("owner_team", "Owner team", lambda r: r[0].owner_team),
        Column("asset_type", "Asset type", lambda r: r[0].asset_type),
        Column("environment", "Environment", lambda r: r[0].environment),
        Column("open_findings", "Open findings", lambda r: r[1]),
        Column("max_risk", "Highest open risk", lambda r: r[2]),
        Column("created_at", "Created", lambda r: r[0].created_at),
    ),
    filters=(
        Filter("criticality", "Criticality", "enum", tuple(c.value for c in Criticality)),
        Filter("owner_team", "Owner team", "str"),
        Filter("internet_facing_only", "Internet-facing only", "bool"),
        Filter("asset_type", "Asset type", "enum", tuple(ASSET_TYPES)),
        Filter("environment", "Environment", "str"),
    ),
    rows=_asset_rows,
)


# --- vulnerabilities --------------------------------------------------------


def _vulnerability_rows(db: Session, filters: dict, limit: int | None, scope: Scope):
    open_findings = scope.filter(
        db.query(
            AssetVulnerability.vulnerability_id.label("vulnerability_id"),
            func.count(AssetVulnerability.id).label("open_findings"),
        )
        .join(Asset, Asset.id == AssetVulnerability.asset_id)
        .filter(AssetVulnerability.status == Status.open)
    )
    open_findings = open_findings.group_by(AssetVulnerability.vulnerability_id).subquery()
    query = db.query(
        Vulnerability, func.coalesce(open_findings.c.open_findings, 0)
    ).outerjoin(open_findings, open_findings.c.vulnerability_id == Vulnerability.id)
    query = scope.filter_vulnerabilities(db, query)
    if filters.get("kev_only"):
        query = query.filter(Vulnerability.in_kev.is_(True))
    if filters.get("min_cvss") is not None:
        query = query.filter(Vulnerability.cvss_score >= filters["min_cvss"])
    query = query.order_by(Vulnerability.cvss_score.desc(), Vulnerability.id)
    if limit is not None:
        query = query.limit(limit)
    yield from query.yield_per(BATCH_SIZE)


VULNERABILITIES = Dataset(
    key="vulnerabilities",
    label="Vulnerabilities (CVE catalogue)",
    module="vulnerabilities",
    columns=(
        Column("cve_id", "CVE", lambda r: r[0].cve_id),
        Column("title", "Title", lambda r: r[0].title),
        Column("cvss", "CVSS", lambda r: r[0].cvss_score),
        Column("severity", "Severity", lambda r: r[0].severity),
        Column("in_kev", "In CISA KEV", lambda r: r[0].in_kev),
        Column("kev_date_added", "Added to KEV", lambda r: r[0].kev_date_added),
        Column("epss", "EPSS", lambda r: r[0].epss_score),
        Column("epss_percentile", "EPSS percentile", lambda r: r[0].epss_percentile),
        Column("open_findings", "Open findings", lambda r: r[1]),
    ),
    filters=(
        Filter("kev_only", "Known exploited (KEV) only", "bool"),
        Filter("min_cvss", "Minimum CVSS", "float", minimum=0, maximum=10),
    ),
    rows=_vulnerability_rows,
)


# --- remediation actions ----------------------------------------------------


def _action_rows(db: Session, filters: dict, limit: int | None, scope: Scope):
    _, items = action_summaries(
        db,
        ActionFilters(
            kind=filters.get("kind"),
            search=filters.get("search"),
            kev_only=filters.get("kev_only", False),
        ),
        0,
        limit if limit is not None else MAX_ROWS,
        scope,
    )
    yield from items


FIXES = Dataset(
    key="remediation_actions",
    label="Fixes to deploy (per KB or fix)",
    module="remediation",
    columns=(
        Column("reference", "Reference", lambda i: i["action"].reference),
        Column("kind", "Kind", lambda i: i["action"].kind),
        Column("title", "Title", lambda i: i["action"].title),
        Column("hosts", "Hosts", lambda i: i["assets"]),
        Column("findings", "Open findings", lambda i: i["findings"]),
        Column("cves", "CVEs", lambda i: i["cves"]),
        Column("kev", "KEV findings", lambda i: i["kev"]),
        Column("overdue", "Overdue findings", lambda i: i["overdue"]),
        Column("total_risk", "Risk removed", lambda i: i["total_risk"]),
        Column("max_risk", "Highest risk", lambda i: i["max_risk"]),
        Column("next_deadline", "Next deadline", lambda i: i["next_deadline"]),
        Column("url", "Vendor advisory", lambda i: i["action"].url),
    ),
    filters=(
        Filter("kind", "Kind", "enum", tuple(k.value for k in RemediationKind)),
        Filter("kev_only", "Fixing KEV only", "bool"),
        Filter("search", "Search", "str"),
    ),
    rows=_action_rows,
)


# --- tickets ----------------------------------------------------------------


def _ticket_rows(db: Session, filters: dict, limit: int | None, scope: Scope):
    query = db.query(RemediationTicket).options(joinedload(RemediationTicket.action))
    query = scope.filter(query, RemediationTicket.owner_team)
    status = filters.get("status") or "active"
    if status == "active":
        query = query.filter(RemediationTicket.status.in_(ACTIVE_TICKET_STATUSES))
    elif status != "all":
        query = query.filter(RemediationTicket.status == status)
    if filters.get("owner_team"):
        query = query.filter(RemediationTicket.owner_team == filters["owner_team"])
    query = query.order_by(RemediationTicket.id)
    if limit is not None:
        query = query.limit(limit)

    batch: list[RemediationTicket] = []
    for ticket in query.yield_per(BATCH_SIZE):
        batch.append(ticket)
        if len(batch) == BATCH_SIZE:
            yield from _with_metrics(db, batch)
            batch = []
    yield from _with_metrics(db, batch)


def _with_metrics(db: Session, tickets: list[RemediationTicket]):
    metrics = ticket_metrics(db, [ticket.id for ticket in tickets])
    for ticket in tickets:
        yield ticket, metrics.get(ticket.id, {})


TICKETS = Dataset(
    key="tickets",
    label="Remediation tickets",
    module="remediation",
    columns=(
        Column("id", "Ticket id", lambda r: r[0].id),
        Column("title", "Title", lambda r: r[0].title),
        Column("owner_team", "Team", lambda r: r[0].owner_team),
        Column("status", "Status", lambda r: r[0].status),
        Column("fix", "Fix", lambda r: r[0].action.reference),
        Column("findings_open", "Open findings", lambda r: r[1].get("findings_open", 0)),
        Column("findings_total", "All findings", lambda r: r[1].get("findings_total", 0)),
        Column("hosts_open", "Hosts left", lambda r: r[1].get("hosts_open", 0)),
        Column("open_risk", "Open risk", lambda r: r[1].get("open_risk", 0.0)),
        Column("next_deadline", "Next deadline", lambda r: r[1].get("next_deadline")),
        Column("overdue", "Overdue findings", lambda r: r[1].get("overdue", 0)),
        Column("external_ref", "External reference", lambda r: r[0].external_ref),
        Column("external_url", "External link", lambda r: r[0].external_url),
        Column("created_at", "Created", lambda r: r[0].created_at),
        Column("resolved_at", "Resolved", lambda r: r[0].resolved_at),
    ),
    filters=(
        Filter(
            "status",
            "Status",
            "enum",
            ("active", "all", *(s.value for s in TicketStatus)),
        ),
        Filter("owner_team", "Team", "str"),
    ),
    rows=_ticket_rows,
)


DATASETS = {
    dataset.key: dataset
    for dataset in (FINDINGS, FIXES, TICKETS, ASSETS, VULNERABILITIES)
}


# --- parameters -------------------------------------------------------------

TRUE = {"true", "1", "yes", "on"}
FALSE = {"false", "0", "no", "off"}


def parse_filters(dataset: Dataset, raw: Mapping[str, Any]) -> dict:
    """Typed filter values from query parameters or a saved extract.

    Unknown names are refused rather than ignored: a mistyped filter would
    otherwise silently export everything.
    """
    specs = {spec.key: spec for spec in dataset.filters}
    unknown = sorted(set(raw) - set(specs))
    if unknown:
        raise ValueError(f"unknown filter(s) for {dataset.key}: {', '.join(unknown)}")

    parsed: dict[str, Any] = {}
    for key, value in raw.items():
        if value is None or value == "":
            continue
        spec = specs[key]
        text = str(value).strip()
        if spec.type == "bool":
            if isinstance(value, bool):
                parsed[key] = value
            elif text.lower() in TRUE | FALSE:
                parsed[key] = text.lower() in TRUE
            else:
                raise ValueError(f"{key} must be true or false")
        elif spec.type == "float":
            try:
                number = float(text)
            except ValueError:
                raise ValueError(f"{key} must be a number") from None
            if (spec.minimum is not None and number < spec.minimum) or (
                spec.maximum is not None and number > spec.maximum
            ):
                raise ValueError(
                    f"{key} must be between {spec.minimum} and {spec.maximum}"
                )
            parsed[key] = number
        elif spec.type == "enum":
            if text not in spec.options:
                raise ValueError(f"{key} must be one of {', '.join(spec.options)}")
            parsed[key] = text
        else:
            if len(text) > 128:
                raise ValueError(f"{key} is too long")
            parsed[key] = text
    return parsed


def parse_columns(dataset: Dataset, raw: str | list | None) -> list[str]:
    if not raw:
        return list(dataset.column_keys)
    keys = [k.strip() for k in raw.split(",")] if isinstance(raw, str) else list(raw)
    keys = [k for k in keys if k]
    unknown = [k for k in keys if k not in dataset.column_keys]
    if unknown:
        raise ValueError(f"unknown column(s) for {dataset.key}: {', '.join(unknown)}")
    if not keys:
        raise ValueError("choose at least one column")
    return list(dict.fromkeys(keys))


def describe(dataset: Dataset) -> dict:
    return {
        "key": dataset.key,
        "label": dataset.label,
        "columns": [{"key": c.key, "label": c.label} for c in dataset.columns],
        "filters": [
            {
                "key": f.key,
                "label": f.label,
                "type": f.type,
                "options": list(f.options),
                "minimum": f.minimum,
                "maximum": f.maximum,
            }
            for f in dataset.filters
        ],
    }


# --- output -----------------------------------------------------------------


def _plain(value):
    """A JSON-ready value: enums by value, moments in ISO 8601."""
    value = getattr(value, "value", value)
    if isinstance(value, datetime):
        return _iso(value)
    if hasattr(value, "isoformat"):  # a date
        return value.isoformat()
    return value


def _cell(value) -> str:
    value = _plain(value)
    if isinstance(value, bool):
        return "yes" if value else "no"
    return neutralize(value)


def run(
    db: Session,
    dataset: Dataset,
    columns: list[str],
    filters: dict,
    fmt: str,
    scope: Scope,
    limit: int | None = None,
) -> Iterator[bytes]:
    """Write the extract to a spooled file, then return a chunk iterator.

    Like the backlog export: the query is consumed before the response starts,
    so the download depends neither on memory nor on an open session.
    """
    by_key = {column.key: column for column in dataset.columns}
    chosen = [by_key[key] for key in columns]
    spool = tempfile.SpooledTemporaryFile(  # noqa: SIM115 - closed by _chunks
        max_size=SPOOL_IN_MEMORY_BYTES, mode="w+b"
    )
    rows = dataset.rows(db, filters, limit, scope)

    if fmt == "csv":
        # utf-8-sig: the BOM lets Excel open accented values correctly.
        text = _Utf8(spool, bom=True)
        writer = csv.writer(text)
        writer.writerow(columns)
        for row in rows:
            writer.writerow([_cell(column.get(row)) for column in chosen])
    elif fmt == "xlsx":
        # Typed cells: numbers stay numbers, moments ISO 8601 as in JSON.
        write_xlsx(
            spool,
            columns,
            ([_plain(column.get(row)) for column in chosen] for row in rows),
            name=dataset.label,
        )
    else:
        text = _Utf8(spool, bom=False)
        text.write("[")
        for index, row in enumerate(rows):
            record = {column.key: _plain(column.get(row)) for column in chosen}
            text.write(
                ("," if index else "") + "\n" + json.dumps(record, ensure_ascii=False)
            )
        text.write("\n]\n")

    spool.seek(0)
    return _chunks(spool)


class _Utf8:
    def __init__(self, spool, bom: bool) -> None:
        self._spool = spool
        if bom:
            self._spool.write("﻿".encode())

    def write(self, text: str) -> int:
        return self._spool.write(text.encode("utf-8"))


def filename(dataset: Dataset, fmt: str) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    return f"vigie-{dataset.key}-{stamp}.{fmt}"
