"""Prometheus instrumentation.

Labels use the *route template* (``/api/v1/assets/{asset_id}``) rather than the
resolved path: labelling by raw path would mint a new time series per asset id
and blow up cardinality.

In production the API runs several uvicorn processes, and a scrape reaches only
one of them. Each would report its own counters, which Prometheus reads as a
counter reset at every scrape. With PROMETHEUS_MULTIPROC_DIR set, every process
writes its values to that directory and /metrics sums them all.
"""

import glob
import logging
import os
from datetime import UTC

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    multiprocess,
)
from prometheus_client.core import CounterMetricFamily
from sqlalchemy import event, func
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Read by prometheus_client itself, not a setting of the application. On a
# tmpfs: it starts empty with the container, as the counters must.
MULTIPROCESS_DIR = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
if MULTIPROCESS_DIR:
    # Metrics without labels write their file as soon as they are declared.
    os.makedirs(MULTIPROCESS_DIR, exist_ok=True)

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


class _IngestedFindings:
    """``vigie_findings_ingested_total``, read from the scan history.

    Ingestion runs in the Celery worker, which serves no /metrics: a counter
    incremented there never reached Prometheus and stayed at 0. The successful
    scan jobs hold the same count, uploads and CrowdStrike syncs alike, and it
    only grows, since the history is never pruned. Refreshed at scrape time.
    """

    def __init__(self) -> None:
        self.by_source: dict[str, int] = {}

    def collect(self):
        family = CounterMetricFamily(
            "vigie_findings_ingested",
            "Findings processed by the ingestion pipeline, by scan source.",
            labels=["source"],
        )
        for source, total in sorted(self.by_source.items()):
            family.add_metric([source], total)
        yield family


INGESTED_FINDINGS = _IngestedFindings()
REGISTRY.register(INGESTED_FINDINGS)

OPEN_FINDINGS = Gauge(
    "vigie_open_findings",
    "Findings currently open — the size of the remediation backlog.",
    registry=REGISTRY,
    multiprocess_mode="mostrecent",
)

OVERDUE_FINDINGS = Gauge(
    "vigie_overdue_findings",
    "Open findings past their remediation deadline.",
    registry=REGISTRY,
    multiprocess_mode="mostrecent",
)


OPEN_KEV_FINDINGS = Gauge(
    "vigie_open_kev_findings",
    "Open findings on a CVE listed in CISA KEV (exploited in the wild).",
    registry=REGISTRY,
    multiprocess_mode="mostrecent",
)

OVERDUE_KEV_FINDINGS = Gauge(
    "vigie_overdue_kev_findings",
    "Open KEV findings past their remediation deadline.",
    registry=REGISTRY,
    multiprocess_mode="mostrecent",
)

# Read from the database at scrape time: the worker that refreshes the feeds
# exposes no /metrics of its own. 0 until a feed was first applied, so an alert
# on "time() - value > 2d" also fires for a feed that never worked.
THREAT_FEED_LAST_SUCCESS = Gauge(
    "vigie_threat_feed_last_success_timestamp_seconds",
    "Unix time of the last successful application of a threat feed.",
    ["feed"],
    registry=REGISTRY,
    multiprocess_mode="mostrecent",
)


# Saturation of the API (docs/EXPLOITATION.md, "Dimensionnement"), summed over
# the live processes. Requests in progress beyond the thread capacity are
# waiting for a thread; connections in use near their maximum mean requests
# will soon wait for the pool.
REQUESTS_IN_PROGRESS = Gauge(
    "vigie_http_requests_in_progress",
    "Requests being handled or waiting for a thread.",
    registry=REGISTRY,
    multiprocess_mode="livesum",
)
API_THREADS = Gauge(
    "vigie_api_threads",
    "Requests the API can run at once (API_THREADS x processes).",
    registry=REGISTRY,
    multiprocess_mode="livesum",
)
DB_CONNECTIONS_IN_USE = Gauge(
    "vigie_db_connections_in_use",
    "Database connections checked out of the API's pools.",
    registry=REGISTRY,
    multiprocess_mode="livesum",
)
DB_CONNECTIONS_MAX = Gauge(
    "vigie_db_connections_max",
    "Connections the API's pools may open (DB_POOL_SIZE + DB_MAX_OVERFLOW, per process).",
    registry=REGISTRY,
    multiprocess_mode="livesum",
)


def record_capacity(threads: int, connections: int) -> None:
    API_THREADS.set(threads)
    DB_CONNECTIONS_MAX.set(connections)


def instrument_pool(engine) -> None:
    """Count the connections checked out of ``engine``'s pool."""
    event.listen(engine, "checkout", lambda *_: DB_CONNECTIONS_IN_USE.inc())
    event.listen(engine, "checkin", lambda *_: DB_CONNECTIONS_IN_USE.dec())


def exposition() -> bytes:
    """The metrics of this process, or of all of them in multiprocess mode."""
    if not MULTIPROCESS_DIR:
        return generate_latest(REGISTRY)
    _forget_dead_processes(MULTIPROCESS_DIR)
    registry = CollectorRegistry()
    multiprocess.MultiProcessCollector(registry, path=MULTIPROCESS_DIR)
    # Not a multiprocess metric: this process has just read it from the base.
    registry.register(INGESTED_FINDINGS)
    return generate_latest(registry)


def _forget_dead_processes(directory: str) -> None:
    """Drop the live gauges of processes that are gone.

    uvicorn replaces a worker that dies; its in-progress requests and
    connections would otherwise be counted forever. Counters and histograms
    keep their files: what a dead process counted still happened. Liveness is
    read from /proc, as in the Linux containers this mode is meant for.
    """
    if not os.path.isdir("/proc"):
        return
    pids = {
        int(os.path.basename(path).rsplit("_", 1)[1].removesuffix(".db"))
        for path in glob.glob(os.path.join(directory, "gauge_live*_*.db"))
    }
    for pid in pids:
        if not os.path.exists(f"/proc/{pid}"):
            multiprocess.mark_process_dead(pid, directory)


def observe_request(method: str, route: str, status: int, duration: float) -> None:
    REQUEST_COUNT.labels(method=method, route=route, status=str(status)).inc()
    REQUEST_LATENCY.labels(method=method, route=route).observe(duration)


def refresh_backlog_gauges(db: Session) -> None:
    """Recompute the backlog gauges at scrape time.

    Cheaper and simpler than keeping counters in sync with every status change,
    and it cannot drift from the database.
    """
    from datetime import datetime

    from app.models.scan import ScanJob, ScanStatus
    from app.models.threat_intel import FEEDS, ThreatFeedStatus
    from app.models.vulnerability import AssetVulnerability, Status, Vulnerability

    try:
        now = datetime.now(UTC)
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
                AssetVulnerability.remediation_deadline < now,
            )
            .scalar()
        ) or 0
        open_kev = (
            db.query(func.count(AssetVulnerability.id))
            .join(AssetVulnerability.vulnerability)
            .filter(
                AssetVulnerability.status == Status.open, Vulnerability.in_kev.is_(True)
            )
        )
        open_kev_count = open_kev.scalar() or 0
        overdue_kev_count = (
            open_kev.filter(
                AssetVulnerability.remediation_deadline.isnot(None),
                AssetVulnerability.remediation_deadline < now,
            ).scalar()
        ) or 0
        last_success = {
            row.feed: row.last_success_at
            for row in db.query(ThreatFeedStatus.feed, ThreatFeedStatus.last_success_at)
        }
        ingested = {
            source: int(total or 0)
            for source, total in db.query(
                ScanJob.scan_type, func.sum(ScanJob.processed_records)
            )
            .filter(ScanJob.status == ScanStatus.success)
            .group_by(ScanJob.scan_type)
        }
    except Exception as exc:
        # A scrape must never take the application down.
        logger.warning("Could not refresh backlog gauges: %s", exc)
        return

    OPEN_FINDINGS.set(open_count)
    OVERDUE_FINDINGS.set(overdue_count)
    OPEN_KEV_FINDINGS.set(open_kev_count)
    OVERDUE_KEV_FINDINGS.set(overdue_kev_count)
    INGESTED_FINDINGS.by_source = ingested
    for feed in FEEDS:
        moment = last_success.get(feed)
        if moment is not None and moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        THREAT_FEED_LAST_SUCCESS.labels(feed=feed).set(
            moment.timestamp() if moment else 0
        )
