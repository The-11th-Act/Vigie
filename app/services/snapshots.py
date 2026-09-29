"""Daily snapshots of the backlog, and the history rebuilt before them.

A day's snapshot is the backlog as it stood at the end of that day (UTC): a
finding counts as open then if it was detected before, and not closed before.
The same rule rebuilds the past from the detection and fix dates already
stored, so trends exist from the first day instead of after three months;
such days are marked estimated, since a finding reopened since then, or a
score that moved, cannot be seen from today.
"""

import logging
from datetime import UTC, date, datetime, time, timedelta

from sqlalchemy import and_, case, func, or_
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.snapshot import BacklogSnapshot
from app.models.vulnerability import AssetVulnerability, Status, Vulnerability

logger = logging.getLogger(__name__)

HISTORY_DAYS = 90
HIGH_RISK = 7.0  # "High" and above, as risk_level() buckets it


def _bounds(day: date) -> tuple[datetime, datetime]:
    start = datetime.combine(day, time.min, tzinfo=UTC)
    return start, start + timedelta(days=1)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def compute_day(db: Session, day: date) -> dict[str, dict]:
    """Metrics of each team at the end of ``day``, keyed by team ("" = none)."""
    start, end = _bounds(day)
    av = AssetVulnerability
    team = func.coalesce(Asset.owner_team, "")
    open_at = and_(av.detected_at < end, or_(av.fixed_at.is_(None), av.fixed_at >= end))

    def count(condition):
        return func.sum(case((condition, 1), else_=0))

    rows = (
        db.query(
            team.label("team"),
            count(open_at).label("open_findings"),
            count(and_(open_at, av.risk_score >= HIGH_RISK)).label("open_high"),
            count(and_(open_at, Vulnerability.in_kev.is_(True))).label("open_kev"),
            count(
                and_(
                    open_at,
                    av.remediation_deadline.isnot(None),
                    av.remediation_deadline < end,
                )
            ).label("overdue"),
            func.sum(case((open_at, av.risk_score), else_=0.0)).label("open_risk"),
            count(and_(av.detected_at >= start, av.detected_at < end)).label(
                "new_findings"
            ),
        )
        .join(Asset, Asset.id == av.asset_id)
        .join(Vulnerability, Vulnerability.id == av.vulnerability_id)
        .filter(av.detected_at < end)
        .group_by(team)
    )
    metrics: dict[str, dict] = {}
    for row in rows:
        metrics[row.team] = {
            "open_findings": row.open_findings or 0,
            "open_high": row.open_high or 0,
            "open_kev": row.open_kev or 0,
            "overdue": row.overdue or 0,
            "open_risk": round(float(row.open_risk or 0.0), 2),
            "new_findings": row.new_findings or 0,
            "fixed": 0,
            "fixed_on_time": 0,
            "fixed_days_total": 0.0,
            "fixed_risk": 0.0,
        }

    # Fixes are few per day: their durations are computed here, which spares a
    # date arithmetic that SQLite and PostgreSQL spell differently.
    fixes = (
        db.query(
            team.label("team"),
            av.detected_at,
            av.fixed_at,
            av.remediation_deadline,
            av.risk_score,
        )
        .join(Asset, Asset.id == av.asset_id)
        .filter(av.status == Status.remediated, av.fixed_at >= start, av.fixed_at < end)
    )
    for row in fixes:
        entry = metrics.setdefault(row.team, _empty())
        fixed_at = _aware(row.fixed_at)
        entry["fixed"] += 1
        if row.remediation_deadline is None or fixed_at <= _aware(
            row.remediation_deadline
        ):
            entry["fixed_on_time"] += 1
        if row.detected_at is not None:
            entry["fixed_days_total"] += max(
                0.0, (fixed_at - _aware(row.detected_at)).total_seconds() / 86400
            )
        entry["fixed_risk"] += float(row.risk_score or 0.0)
    return metrics


def _empty() -> dict:
    return {
        "open_findings": 0,
        "open_high": 0,
        "open_kev": 0,
        "overdue": 0,
        "open_risk": 0.0,
        "new_findings": 0,
        "fixed": 0,
        "fixed_on_time": 0,
        "fixed_days_total": 0.0,
        "fixed_risk": 0.0,
    }


def record_day(db: Session, day: date, estimated: bool) -> int:
    """Store (or replace) the snapshot rows of ``day``."""
    db.query(BacklogSnapshot).filter(BacklogSnapshot.day == day).delete(
        synchronize_session=False
    )
    # A day without any finding still gets its (empty) row: otherwise it would
    # look missing, and be rebuilt again by every daily pass.
    metrics = compute_day(db, day) or {"": _empty()}
    for team, values in metrics.items():
        values["fixed_days_total"] = round(values["fixed_days_total"], 3)
        values["fixed_risk"] = round(values["fixed_risk"], 2)
        db.add(BacklogSnapshot(day=day, owner_team=team, estimated=estimated, **values))
    db.flush()
    return len(metrics)


def record_snapshots(db: Session, today: date | None = None) -> dict:
    """The daily pass: yesterday as it ended, and any missing past day rebuilt.

    Yesterday is a complete day, so its snapshot is final. Days of the last
    HISTORY_DAYS that have none (a fresh install, a pass that did not run) are
    rebuilt and marked estimated; a day already stored is never touched again.
    """
    today = today or datetime.now(UTC).date()
    yesterday = today - timedelta(days=1)
    record_day(db, yesterday, estimated=False)

    known = {
        row.day
        for row in db.query(BacklogSnapshot.day)
        .filter(BacklogSnapshot.day >= today - timedelta(days=HISTORY_DAYS))
        .distinct()
    }
    rebuilt = 0
    for offset in range(2, HISTORY_DAYS + 1):
        day = today - timedelta(days=offset)
        if day not in known:
            record_day(db, day, estimated=True)
            rebuilt += 1
    if rebuilt:
        logger.info("Rebuilt %d day(s) of backlog history (estimated)", rebuilt)
    return {"day": yesterday.isoformat(), "rebuilt": rebuilt}
