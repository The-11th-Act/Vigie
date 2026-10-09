"""Apply the KEV and EPSS feeds to the vulnerabilities we track.

Kept free of Celery imports, like ingestion: the worker task, the offline
import script and the admin upload all call into this module.

The rule is "never break, never erase". A feed that cannot be fetched or parsed
changes nothing and is recorded as a failure in ``threat_feed_status``. A
snapshot older than the one already applied, or a KEV catalogue that shrank
sharply (a truncated download looks exactly like that), is refused unless
forced. A CVE missing from an otherwise valid EPSS file keeps its last score.

Only the findings whose score can actually change are rescored: CVEs that
entered or left KEV, and CVEs whose EPSS value crossed a band.
"""

import logging
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import delete, func, insert
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.threat_intel import (
    FEED_EPSS,
    FEED_KEV,
    FEED_MSRC,
    FEEDS,
    EpssScoreEntry,
    KbSupersedence,
    KevCatalogEntry,
    MsrcDocument,
    ThreatFeedStatus,
)
from app.models.vulnerability import AssetVulnerability, Status, Vulnerability
from app.parsers.msrc import MsrcDocument as ParsedMsrcDocument
from app.parsers.msrc import (
    MsrcDocumentRef,
    parse_msrc_document,
    parse_msrc_index,
)
from app.parsers.threat_feeds import (
    EpssSnapshot,
    KevCatalog,
    KevEntry,
    ThreatFeedClient,
    ThreatFeedError,
    parse_epss,
    parse_kev,
)
from app.services.kb_supersedence import apply_supersedence, store_documents
from app.services.remediation import apply_kev_sla
from app.services.rescoring import rescore_open_findings
from app.services.risk_acceptance import reopen_for_kev
from app.services.risk_scoring import epss_band
from app.services.tickets import sync_tickets
from app.services.webhooks import emit

logger = logging.getLogger(__name__)

# Well under SQLite's bound-parameter limit, and a sane IN () list for PostgreSQL.
CHUNK_SIZE = 500
# Rows per INSERT when storing a whole snapshot (~380 000 for EPSS).
SNAPSHOT_BATCH_SIZE = 5_000

# A catalogue with fewer entries than this share of the last one is refused:
# CISA removes entries rarely and one at a time, a truncated file removes many.
MIN_KEV_RETENTION = 0.9

SOURCE_NETWORK = "network"
SOURCE_IMPORT = "import"

# MSRC documents are asked for as JSON: the API answers XML otherwise.
MSRC_HEADERS = {"Accept": "application/json"}
# MSRC revises a dozen recent documents a day, mostly to add CVEs. A revision
# is fetched again only for documents of the last two months, where an
# out-of-band update can still change what supersedes what; older ones are
# fetched once.
MSRC_REFETCH_WINDOW = timedelta(days=62)
# One document a month (Patch Tuesday): an installation importing them by
# hand is not stale three days after an import.
MSRC_STALE_AFTER = timedelta(days=35)

# CVEs named in one threat.kev_listed webhook event.
KEV_EVENT_MAX_CVES = 100


class FeedRejected(ThreatFeedError):
    """A well-formed snapshot that is refused, rather than applied."""


@dataclass
class FeedResult:
    feed: str
    status: str  # "applied" or "failed"
    records: int = 0
    changed: int = 0
    rescored: int = 0
    error: str | None = None


@dataclass
class RefreshResult:
    feeds: list[FeedResult]

    @property
    def ok(self) -> bool:
        return all(feed.status == "applied" for feed in self.feeds)

    def as_dict(self) -> dict:
        return {feed.feed: asdict(feed) for feed in self.feeds}


def refresh_threat_intel(
    db: Session, *, client: ThreatFeedClient | None = None, now: datetime | None = None
) -> RefreshResult:
    """Fetch both feeds and apply them; each feed succeeds or fails on its own."""
    now = now or datetime.now(UTC)
    client = client or ThreatFeedClient(
        timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS,
        max_bytes=settings.THREAT_INTEL_MAX_FEED_BYTES,
    )
    max_bytes = settings.THREAT_INTEL_MAX_FEED_BYTES

    # KEV first: the smaller file, and the stronger signal.
    kev = _refresh_one(
        db,
        FEED_KEV,
        lambda: apply_kev(
            db,
            parse_kev(client.get(settings.THREAT_INTEL_KEV_URL), max_bytes),
            source=SOURCE_NETWORK,
            now=now,
        ),
        now,
    )
    epss = _refresh_one(
        db,
        FEED_EPSS,
        lambda: apply_epss(
            db,
            parse_epss(client.get(settings.THREAT_INTEL_EPSS_URL), None, max_bytes),
            source=SOURCE_NETWORK,
            now=now,
        ),
        now,
    )
    msrc = _refresh_one(db, FEED_MSRC, lambda: refresh_msrc(db, client, now), now)
    return RefreshResult(feeds=[kev, epss, msrc])


def import_feed(
    db: Session,
    feed: str,
    raw: bytes,
    *,
    force: bool = False,
    now: datetime | None = None,
) -> FeedResult:
    """Apply a feed file obtained out of band — the offline path.

    Raises ``ThreatFeedError`` on a malformed or refused file, which the caller
    reports as it sees fit (exit code, HTTP 400).
    """
    now = now or datetime.now(UTC)
    max_bytes = settings.THREAT_INTEL_MAX_FEED_BYTES
    if feed == FEED_KEV:
        catalog = parse_kev(raw, max_bytes)
        return apply_kev(db, catalog, source=SOURCE_IMPORT, now=now, force=force)
    if feed == FEED_EPSS:
        snapshot = parse_epss(raw, None, max_bytes)
        return apply_epss(db, snapshot, source=SOURCE_IMPORT, now=now, force=force)
    if feed == FEED_MSRC:
        document = parse_msrc_document(raw, max_bytes)
        return apply_msrc(db, [document], source=SOURCE_IMPORT, now=now, force=force)
    raise ThreatFeedError(f"Unknown feed {feed!r}")


def refresh_msrc(db: Session, client: ThreatFeedClient, now: datetime) -> FeedResult:
    """Fetch the MSRC documents that are new or newly revised, and apply them.

    Every document is fetched and parsed before anything is written: one that
    fails leaves the stored supersedences as they were, like the other feeds.
    """
    base = settings.THREAT_INTEL_MSRC_URL
    max_bytes = settings.THREAT_INTEL_MAX_FEED_BYTES
    index = parse_msrc_index(
        client.get(base + "updates", headers=MSRC_HEADERS), max_bytes
    )
    stored = {row.id: row for row in db.query(MsrcDocument)}
    oldest = now - timedelta(days=31 * settings.THREAT_INTEL_MSRC_MONTHS)

    wanted = sorted(
        (
            ref
            for ref in index
            if ref.initial_release is not None
            and ref.initial_release >= oldest
            and _msrc_outdated(ref, stored.get(ref.id), now)
        ),
        key=lambda ref: ref.initial_release or now,
    )
    documents = []
    for ref in wanted:
        document = parse_msrc_document(
            client.get(f"{base}cvrf/{ref.id}", headers=MSRC_HEADERS), max_bytes
        )
        if document.id != ref.id:
            raise ThreatFeedError(f"MSRC answered {document.id} when asked for {ref.id}")
        documents.append(document)
    return apply_msrc(db, documents, source=SOURCE_NETWORK, now=now, lenient=True)


def _msrc_outdated(ref: MsrcDocumentRef, row: MsrcDocument | None, now: datetime) -> bool:
    if row is None:
        return True
    if ref.current_release is None or row.current_release is None:
        return False
    revised = _aware(row.current_release) != ref.current_release
    recent = ref.initial_release is not None and ref.initial_release >= (
        now - MSRC_REFETCH_WINDOW
    )
    return revised and recent


def apply_msrc(
    db: Session,
    documents: list[ParsedMsrcDocument],
    *,
    source: str,
    now: datetime,
    force: bool = False,
    lenient: bool = False,
) -> FeedResult:
    """Store the supersedences of ``documents``, then move the links they affect.

    A document older than the revision already applied, or one that would
    erase all the supersedences its stored revision has (a format change looks
    like that), is refused: the whole import fails unless forced. The network
    refresh is ``lenient``: it skips such a document and applies the others,
    rather than letting one odd document block every later month.
    """
    status = _feed_status(db, FEED_MSRC)
    accepted = []
    for document in documents:
        reason = (
            None if force else _msrc_refusal(db.get(MsrcDocument, document.id), document)
        )
        if reason is None:
            accepted.append(document)
        elif lenient:
            logger.warning("MSRC document %s skipped: %s", document.id, reason)
        else:
            raise FeedRejected(f"{reason}; use force to apply it anyway")

    changed_documents = store_documents(db, accepted, now)
    # Only a changed supersedence can move a link; ingestion handles new ones.
    moved = apply_supersedence(db) if changed_documents else 0
    if moved:
        # Tickets follow their findings to the later KB (tickets.sync_tickets).
        sync_tickets(db, now)

    newest = (
        db.query(MsrcDocument)
        .order_by(MsrcDocument.initial_release.desc(), MsrcDocument.id.desc())
        .first()
    )
    records = db.query(KbSupersedence).count()
    _record_success(
        status,
        source,
        newest.id if newest else None,
        (
            _aware(newest.initial_release).date()
            if newest and newest.initial_release
            else None
        ),
        records,
        moved,
        now,
    )
    db.commit()
    logger.info(
        "MSRC applied from %s: %d document(s) fetched, %d changed, %d supersedences "
        "stored, %d remediation link(s) moved",
        source,
        len(documents),
        changed_documents,
        records,
        moved,
    )
    return FeedResult(FEED_MSRC, "applied", records, moved)


def _msrc_refusal(row: MsrcDocument | None, document: ParsedMsrcDocument) -> str | None:
    if row is None:
        return None
    if (
        row.current_release is not None
        and document.current_release is not None
        and document.current_release < _aware(row.current_release)
    ):
        return (
            f"MSRC document {document.id} of {document.current_release:%Y-%m-%d} is "
            f"older than the revision already applied ({_aware(row.current_release):%Y-%m-%d})"
        )
    if row.supersedences and not document.supersedences:
        return (
            f"MSRC document {document.id} names no superseded KB, where the "
            f"applied revision named {row.supersedences}"
        )
    return None


def apply_kev(
    db: Session,
    catalog: KevCatalog,
    *,
    source: str,
    now: datetime,
    force: bool = False,
) -> FeedResult:
    """Flag the tracked CVEs listed in KEV, and unflag those no longer listed."""
    status = _feed_status(db, FEED_KEV)
    if not force:
        _refuse_older(status, catalog.released, FEED_KEV)
        if status.records and len(catalog.entries) < status.records * MIN_KEV_RETENTION:
            raise FeedRejected(
                f"KEV catalogue shrank from {status.records} to "
                f"{len(catalog.entries)} entries; use force to apply it anyway"
            )

    listed = _vulnerabilities_by_cve(db, catalog.entries)
    flagged = db.query(Vulnerability).filter(Vulnerability.in_kev.is_(True)).all()
    candidates = {vuln.id: vuln for vuln in [*listed, *flagged]}

    changed = 0
    newly_listed: list[int] = []
    newly_ransomware: list[int] = []
    delisted: list[str] = []
    for vuln in candidates.values():
        entry = catalog.entries.get(vuln.cve_id)
        was_listed = bool(vuln.in_kev)
        was_ransomware = bool(vuln.kev_ransomware)
        wanted = {
            "in_kev": entry is not None,
            "kev_date_added": entry.date_added if entry else None,
            "kev_due_date": entry.due_date if entry else None,
            "kev_ransomware": entry.ransomware if entry else False,
            "kev_ransomware_since": _ransomware_since(vuln, entry, was_listed, now),
        }
        if not _assign(vuln, wanted, now):
            continue
        changed += 1
        if entry is not None and not was_listed:
            newly_listed.append(vuln.id)
        elif entry is not None and entry.ransomware and not was_ransomware:
            newly_ransomware.append(vuln.id)
        elif entry is None and was_listed:
            delisted.append(vuln.cve_id)

    if delisted:
        logger.warning(
            "CVEs removed from the KEV catalogue: %s", ", ".join(sorted(delisted))
        )

    db.flush()
    # A risk accepted as theoretical is no longer theoretical: reopened first,
    # so the new KEV deadline and score apply to it too.
    reopened = reopen_for_kev(
        db, newly_listed, {v.id: v.kev_date_added for v in listed if v.id in newly_listed}
    )
    if reopened:
        logger.warning("%d accepted finding(s) reopened: their CVE entered KEV", reopened)
    _tighten_deadlines(db, [*newly_listed, *newly_ransomware])
    rescored = _rescore(
        db,
        [
            *newly_listed,
            *newly_ransomware,
            *(v.id for v in flagged if not v.in_kev),
        ],
        now,
    )
    _announce_kev(db, newly_listed, newly_ransomware, now)

    _replace_table(
        db,
        KevCatalogEntry,
        (
            {
                "cve_id": entry.cve_id,
                "date_added": entry.date_added,
                "due_date": entry.due_date,
                "ransomware": entry.ransomware,
            }
            for entry in catalog.entries.values()
        ),
    )
    _record_success(
        status,
        source,
        catalog.version,
        catalog.released,
        len(catalog.entries),
        changed,
        now,
    )
    db.commit()
    logger.info(
        "KEV %s applied from %s: %d entries, %d CVEs changed, %d findings rescored",
        catalog.version,
        source,
        len(catalog.entries),
        changed,
        rescored,
    )
    return FeedResult(FEED_KEV, "applied", len(catalog.entries), changed, rescored)


def apply_epss(
    db: Session,
    snapshot: EpssSnapshot,
    *,
    source: str,
    now: datetime,
    force: bool = False,
) -> FeedResult:
    """Store the EPSS score of every tracked CVE the snapshot covers."""
    status = _feed_status(db, FEED_EPSS)
    if not force:
        _refuse_older(status, snapshot.score_date, FEED_EPSS)

    changed = 0
    band_moved: list[int] = []
    # The file covers every published CVE; only the tracked ones are looked up.
    covered = tracked_cves(db) & snapshot.scores.keys()
    for vuln in _vulnerabilities_by_cve(db, covered):
        score = snapshot.scores[vuln.cve_id]
        old_band = epss_band(vuln.epss_score)
        wanted = {
            "epss_score": score.score,
            "epss_percentile": score.percentile,
            "epss_date": snapshot.score_date,
        }
        if not _assign(vuln, wanted, now):
            continue
        changed += 1
        # A KEV entry ignores EPSS, so its findings cannot move.
        if not vuln.in_kev and epss_band(score.score) != old_band:
            band_moved.append(vuln.id)

    db.flush()
    rescored = _rescore(db, band_moved, now)

    _replace_table(
        db,
        EpssScoreEntry,
        (
            {
                "cve_id": cve_id,
                "score": score.score,
                "percentile": score.percentile,
                "score_date": snapshot.score_date,
            }
            for cve_id, score in snapshot.scores.items()
        ),
    )
    _record_success(
        status,
        source,
        snapshot.model_version,
        snapshot.score_date,
        snapshot.total_rows,
        changed,
        now,
    )
    db.commit()
    logger.info(
        "EPSS %s applied from %s: %d CVEs changed, %d findings rescored",
        snapshot.score_date,
        source,
        changed,
        rescored,
    )
    return FeedResult(FEED_EPSS, "applied", snapshot.total_rows, changed, rescored)


def _replace_table(db: Session, model, rows) -> None:
    """Swap the stored snapshot for a new one, inside the caller's transaction.

    Called only once a snapshot passed every guard, and committed together with
    the rest of its application: a refused or failed feed leaves the previous
    snapshot in place.
    """
    db.execute(delete(model))
    batch: list[dict] = []
    for row in rows:
        batch.append(row)
        if len(batch) >= SNAPSHOT_BATCH_SIZE:
            db.execute(insert(model), batch)
            batch = []
    if batch:
        db.execute(insert(model), batch)


def enrich_new_vulnerabilities(db: Session, vulnerabilities, now: datetime) -> None:
    """Give CVEs seen for the first time the intel of the last snapshots.

    Without this a new CVE waited for the next daily refresh — up to a day
    without its KEV deadline or its EPSS weight. The caller flushes.
    """
    by_cve = {vuln.cve_id: vuln for vuln in vulnerabilities}
    ids = list(by_cve)
    for i in range(0, len(ids), CHUNK_SIZE):
        chunk = ids[i : i + CHUNK_SIZE]
        for entry in db.query(KevCatalogEntry).filter(KevCatalogEntry.cve_id.in_(chunk)):
            _assign(
                by_cve[entry.cve_id],
                {
                    "in_kev": True,
                    "kev_date_added": entry.date_added,
                    "kev_due_date": entry.due_date,
                    "kev_ransomware": entry.ransomware,
                    # Flagged before this CVE was seen here: the window counts
                    # from its detection, which comes later anyway.
                    "kev_ransomware_since": (
                        entry.date_added if entry.ransomware else None
                    ),
                },
                now,
            )
        for score in db.query(EpssScoreEntry).filter(EpssScoreEntry.cve_id.in_(chunk)):
            _assign(
                by_cve[score.cve_id],
                {
                    "epss_score": score.score,
                    "epss_percentile": score.percentile,
                    "epss_date": score.score_date,
                },
                now,
            )


def tracked_cves(db: Session) -> set[str]:
    """Every CVE in the database — all the EPSS file is filtered down to."""
    return {cve for (cve,) in db.query(Vulnerability.cve_id)}


def _refresh_one(
    db: Session, feed: str, apply: Callable[[], FeedResult], now: datetime
) -> FeedResult:
    # Fetching, parsing and the refusal guards all run before the first write,
    # so a ThreatFeedError leaves nothing to roll back: only the failure itself
    # is recorded.
    try:
        return apply()
    except ThreatFeedError as exc:
        logger.error("Threat feed %s not applied: %s", feed, exc)
        status = _feed_status(db, feed)
        status.last_attempt_at = now
        status.last_error = str(exc)[:2000]
        db.commit()
        return FeedResult(feed, "failed", error=str(exc))


def _vulnerabilities_by_cve(db: Session, cve_ids: Iterable[str]) -> list[Vulnerability]:
    ids = list(cve_ids)
    rows: list[Vulnerability] = []
    for i in range(0, len(ids), CHUNK_SIZE):
        chunk = ids[i : i + CHUNK_SIZE]
        rows.extend(db.query(Vulnerability).filter(Vulnerability.cve_id.in_(chunk)).all())
    return rows


def _assign(vuln: Vulnerability, values: dict, now: datetime) -> bool:
    """Write only what differs, so an unchanged row is not rewritten daily."""
    changed = False
    for field, value in values.items():
        if getattr(vuln, field) != value:
            setattr(vuln, field, value)
            changed = True
    if changed:
        vuln.threat_intel_updated_at = now
    return changed


def _announce_kev(
    db: Session, newly_listed: list[int], newly_ransomware: list[int], now: datetime
) -> None:
    """One webhook event per refresh: the CVEs that became urgent on open
    findings. CVEs nothing is exposed to are left out."""
    ids = [*newly_listed, *newly_ransomware]
    open_counts: dict[int, int] = {}
    for i in range(0, len(ids), CHUNK_SIZE):
        chunk = ids[i : i + CHUNK_SIZE]
        open_counts.update(
            db.query(
                AssetVulnerability.vulnerability_id, func.count(AssetVulnerability.id)
            )
            .filter(
                AssetVulnerability.vulnerability_id.in_(chunk),
                AssetVulnerability.status == Status.open,
            )
            .group_by(AssetVulnerability.vulnerability_id)
            .all()
        )
    if not open_counts:
        return

    listed = set(newly_listed)
    cves: list[dict] = []
    open_counts_by_cve: dict[str, int] = {}
    vulnerability_ids = list(open_counts)
    for i in range(0, len(vulnerability_ids), CHUNK_SIZE):
        chunk = vulnerability_ids[i : i + CHUNK_SIZE]
        for vuln in db.query(Vulnerability).filter(Vulnerability.id.in_(chunk)):
            open_counts_by_cve[vuln.cve_id] = open_counts[vuln.id]
            cves.append(
                {
                    "cve_id": vuln.cve_id,
                    "title": vuln.title,
                    "cvss_score": vuln.cvss_score,
                    "reason": "listed" if vuln.id in listed else "ransomware",
                    "kev_date_added": vuln.kev_date_added,
                    "ransomware": vuln.kev_ransomware,
                    "open_findings": open_counts[vuln.id],
                }
            )
    cves.sort(key=lambda cve: (-open_counts_by_cve[cve["cve_id"]], cve["cve_id"]))
    # A first catalogue lists every tracked CVE at once: the event names the
    # most widespread and counts the rest.
    emit(
        db,
        "threat.kev_listed",
        {
            "total": len(cves),
            "truncated": len(cves) > KEV_EVENT_MAX_CVES,
            "cves": cves[:KEV_EVENT_MAX_CVES],
        },
        now,
    )


def _ransomware_since(
    vuln: Vulnerability, entry: KevEntry | None, was_listed: bool, now: datetime
) -> date | None:
    """The day ransomware use became known, kept from one refresh to the next.

    A CVE listed here for the first time with the flag gets the listing date,
    like its KEV window. A CVE already listed gets the flag today: dating it from
    the listing would put its findings past the ransomware deadline at once.
    """
    if entry is None or not entry.ransomware:
        return None
    if vuln.kev_ransomware and vuln.kev_ransomware_since is not None:
        return vuln.kev_ransomware_since
    if was_listed:
        return now.date()
    return entry.date_added


def _tighten_deadlines(db: Session, vulnerability_ids: list[int]) -> None:
    """Give the open findings of newly listed CVEs the KEV window."""
    for i in range(0, len(vulnerability_ids), CHUNK_SIZE):
        chunk = vulnerability_ids[i : i + CHUNK_SIZE]
        findings = (
            db.query(AssetVulnerability)
            .filter(
                AssetVulnerability.vulnerability_id.in_(chunk),
                AssetVulnerability.status == Status.open,
            )
            .all()
        )
        for finding in findings:
            finding.remediation_deadline = apply_kev_sla(
                finding.remediation_deadline,
                finding.detected_at,
                finding.vulnerability.kev_date_added,
                ransomware_since=finding.vulnerability.kev_ransomware_since,
            )


def _rescore(db: Session, vulnerability_ids: list[int], now: datetime) -> int:
    rescored = 0
    for i in range(0, len(vulnerability_ids), CHUNK_SIZE):
        chunk = vulnerability_ids[i : i + CHUNK_SIZE]
        rescored += rescore_open_findings(
            db, AssetVulnerability.vulnerability_id.in_(chunk), now=now
        )
    return rescored


def _feed_status(db: Session, feed: str) -> ThreatFeedStatus:
    status = db.get(ThreatFeedStatus, feed)
    if status is None:
        status = ThreatFeedStatus(feed=feed, records=0, changed=0)
        db.add(status)
    return status


def _refuse_older(status: ThreatFeedStatus, snapshot_date, feed: str) -> None:
    if status.source_date and snapshot_date and snapshot_date < status.source_date:
        raise FeedRejected(
            f"{feed.upper()} snapshot of {snapshot_date} is older than the one "
            f"already applied ({status.source_date}); use force to apply it anyway"
        )


def _record_success(
    status: ThreatFeedStatus,
    source: str,
    version: str | None,
    snapshot_date,
    records: int,
    changed: int,
    now: datetime,
) -> None:
    status.last_attempt_at = now
    status.last_success_at = now
    status.last_error = None
    status.source = source
    status.source_version = version
    status.source_date = snapshot_date
    status.records = records
    status.changed = changed


def feed_freshness(db: Session, now: datetime | None = None) -> list[dict]:
    """State of each feed, for the API, the dashboard and the metrics.

    A feed never applied, or not applied for ``THREAT_INTEL_STALE_AFTER_HOURS``,
    is stale: its values still count in the score, but they may be outdated.
    MSRC publishes monthly and gets ``MSRC_STALE_AFTER`` at least.
    """
    now = now or datetime.now(UTC)
    daily = timedelta(hours=settings.THREAT_INTEL_STALE_AFTER_HOURS)
    rows = {row.feed: row for row in db.query(ThreatFeedStatus).all()}

    feeds = []
    for feed in FEEDS:
        max_age = max(daily, MSRC_STALE_AFTER) if feed == FEED_MSRC else daily
        row = rows.get(feed)
        last_success = (
            _aware(row.last_success_at) if row and row.last_success_at else None
        )
        feeds.append(
            {
                "feed": feed,
                "last_attempt_at": row.last_attempt_at if row else None,
                "last_success_at": last_success,
                "last_error": row.last_error if row else None,
                "source": row.source if row else None,
                "source_version": row.source_version if row else None,
                "source_date": row.source_date if row else None,
                "records": row.records if row else 0,
                "stale": last_success is None or now - last_success > max_age,
                "stale_after_hours": int(max_age.total_seconds() // 3600),
            }
        )
    return feeds


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)
