"""Prometheus instrumentation.

Labels use the *route template* (``/api/v1/assets/{asset_id}``) rather than the
resolved path: labelling by raw path would mint a new time series per asset id
and blow up cardinality.
"""
import logging

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram
from sqlalchemy import func
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# A registry of our own rather than the global default: it keeps the exposition
# limited to what this app declares, and lets tests build a clean one.
REGISTRY = CollectorRegistry()

REQUEST_COUNT = Counter(
    "vigie_http_requests_total",
    "HTTP requests handled, by route and outcome.",
    ["method", "route", "status"],
    registry=REGISTRY,
)

REQUEST_LATENCY = Histogram(
    "vigie_http_request_duration_seconds",
    "Time spent handling a request, by route.",
    ["method", "route"],
    registry=REGISTRY,
)

FINDINGS_INGESTED = Counter(
    "vigie_findings_ingested_total",
    "Findings processed by the ingestion pipeline, by scan source.",
    ["source"],
    registry=REGISTRY,
)

OPEN_FINDINGS = Gauge(
    "vigie_open_findings",
    "Findings currently open — the size of the remediation backlog.",
    registry=REGISTRY,
)

OVERDUE_FINDINGS = Gauge(
    "vigie_overdue_findings",
    "Open findings past their remediation deadline.",
    registry=REGISTRY,
)


def observe_request(method: str, route: str, status: int, duration: float) -> None:
    REQUEST_COUNT.labels(method=method, route=route, status=str(status)).inc()
    REQUEST_LATENCY.labels(method=method, route=route).observe(duration)


def observe_ingestion(source: str, processed: int) -> None:
    if processed:
        FINDINGS_INGESTED.labels(source=source or "unknown").inc(processed)


def refresh_backlog_gauges(db: Session) -> None:
    """Recompute the backlog gauges at scrape time.

    Cheaper and simpler than keeping counters in sync with every status change,
    and it cannot drift from the database.
    """
    from datetime import datetime, timezone

    from app.models.vulnerability import AssetVulnerability, Status

    try:
        open_count = (
            db.query(func.count(AssetVulnerability.id))
            .filter(AssetVulnerability.status == Status.open)
            .scalar()
        ) or 0
        overdue_count = (
            db.query(func.count(AssetVulnerability.id))
            .filter(
                AssetVulnerability.status == Status.open,
                AssetVulnerability.remediation_deadline.isnot(None),
                AssetVulnerability.remediation_deadline < datetime.now(timezone.utc),
            )
            .scalar()
        ) or 0
    except Exception as exc:
        # A scrape must never take the application down.
        logger.warning("Could not refresh backlog gauges: %s", exc)
        return

    OPEN_FINDINGS.set(open_count)
    OVERDUE_FINDINGS.set(overdue_count)
