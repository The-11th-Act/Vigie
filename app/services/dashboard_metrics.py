"""Trends and remediation performance for the dashboards.

Trends read the daily snapshots. Performance is computed from the findings
themselves, since it only looks at a recent window: what was fixed, how fast,
within the deadline or not, and how much risk that removed, per team.
"""

from collections import defaultdict
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import and_, case, func, or_
from sqlalchemy.orm import Session

from app.core.scope import Scope
from app.models.asset import Asset
from app.models.snapshot import BacklogSnapshot
from app.models.ticket import ACTIVE_TICKET_STATUSES, RemediationTicket
from app.models.vulnerability import AssetVulnerability, Status, Vulnerability
from app.services.findings import NOT_SET

UNASSIGNED = "Unassigned"
CRITICALITIES = ("Critical", "High", "Medium", "Low")
SNAPSHOT_FIELDS = (
    "open_findings",
    "open_high",
    "open_kev",
    "overdue",
    "open_risk",
    "new_findings",
    "fixed",
    "fixed_on_time",
    "fixed_days_total",
    "fixed_risk",
)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _team_key(team: str) -> str:
    """The snapshot key of a team filter: "" for hosts without a team."""
    return "" if team == NOT_SET else team


def trends(db: Session, days: int, team: str | None, scope: Scope) -> list[dict]:
    """One point per stored day, the estate or one team: the teams of
    ``scope`` summed, for a scoped user."""
    since = datetime.now(UTC).date() - timedelta(days=days)
    query = db.query(BacklogSnapshot).filter(BacklogSnapshot.day >= since)
    query = scope.filter(query, BacklogSnapshot.owner_team)
    if team:
        query = query.filter(BacklogSnapshot.owner_team == _team_key(team))

    points: dict[date, dict] = {}
    for row in query.order_by(BacklogSnapshot.day):
        point = points.setdefault(
            row.day,
            {"day": row.day, "estimated": False, **dict.fromkeys(SNAPSHOT_FIELDS, 0)},
        )
        point["estimated"] = point["estimated"] or row.estimated
        for field in SNAPSHOT_FIELDS:
            point[field] += getattr(row, field)

    result = []
    for point in points.values():
        fixed = point["fixed"]
        result.append(
            {
                **point,
                "open_risk": round(point["open_risk"], 2),
                "fixed_risk": round(point["fixed_risk"], 2),
                "mttr_days": (
                    round(point["fixed_days_total"] / fixed, 1) if fixed else None
                ),
            }
        )
    return result


def _team_filter(query, team: str | None, scope: Scope):
    query = scope.filter(query)
    if not team:
        return query
    if team == NOT_SET:
        return query.filter(Asset.owner_team.is_(None))
    return query.filter(Asset.owner_team == team)


def _rate(part: float, whole: float) -> float | None:
    return round(part / whole * 100, 1) if whole else None


def _mean(total: float, count: float) -> float | None:
    return round(total / count, 1) if count else None


def performance(db: Session, days: int, team: str | None, scope: Scope) -> dict:
    """Remediation over the last ``days`` days, overall and per team."""
    now = datetime.now(UTC)
    since = now - timedelta(days=days)
    av = AssetVulnerability
    team_col = Asset.owner_team

    # --- what was fixed in the window, one row each (a window stays small) ---
    fixed_rows = _team_filter(
        db.query(
            team_col,
            Asset.business_criticality,
            av.detected_at,
            av.fixed_at,
            av.remediation_deadline,
            av.risk_score,
        )
        .join(Asset, Asset.id == av.asset_id)
        .filter(av.status == Status.remediated, av.fixed_at >= since),
        team,
        scope,
    ).all()

    overall = {"fixed": 0, "on_time": 0, "days": 0.0, "risk": 0.0}
    by_criticality = {c: {"fixed": 0, "days": 0.0} for c in CRITICALITIES}
    by_team: dict[str | None, dict] = defaultdict(
        lambda: {"fixed": 0, "on_time": 0, "days": 0.0}
    )
    for owner, criticality, detected_at, fixed_at, deadline, risk in fixed_rows:
        fixed_at = _aware(fixed_at)
        on_time = deadline is None or fixed_at <= _aware(deadline)
        duration = (
            max(0.0, (fixed_at - _aware(detected_at)).total_seconds() / 86400)
            if detected_at
            else 0.0
        )
        overall["fixed"] += 1
        overall["on_time"] += on_time
        overall["days"] += duration
        overall["risk"] += float(risk or 0.0)
        level = getattr(criticality, "value", criticality)
        if level in by_criticality:
            by_criticality[level]["fixed"] += 1
            by_criticality[level]["days"] += duration
        entry = by_team[owner]
        entry["fixed"] += 1
        entry["on_time"] += on_time
        entry["days"] += duration

    # --- the backlog now, and when the window opened -------------------------
    open_now = av.status == Status.open
    open_then = and_(
        av.detected_at < since, or_(av.fixed_at.is_(None), av.fixed_at >= since)
    )
    totals = _team_filter(
        db.query(
            func.sum(case((open_now, 1), else_=0)),
            func.sum(case((open_now, av.risk_score), else_=0.0)),
            func.sum(case((open_then, 1), else_=0)),
            func.sum(case((open_then, av.risk_score), else_=0.0)),
            func.sum(case((av.detected_at >= since, 1), else_=0)),
        ).join(Asset, Asset.id == av.asset_id),
        team,
        scope,
    ).one()
    open_count, open_risk, open_start, risk_start, new_findings = totals

    # --- per team: backlog now, and tickets -----------------------------------
    teams: dict[str | None, dict] = {}
    for owner, count, overdue, risk, kev in _team_filter(
        db.query(
            team_col,
            func.count(av.id),
            func.sum(case((av.remediation_deadline < now, 1), else_=0)),
            func.coalesce(func.sum(av.risk_score), 0.0),
            func.sum(case((Vulnerability.in_kev.is_(True), 1), else_=0)),
        )
        .join(Asset, Asset.id == av.asset_id)
        .join(Vulnerability, Vulnerability.id == av.vulnerability_id)
        .filter(open_now)
        .group_by(team_col),
        team,
        scope,
    ):
        teams[owner] = {
            "open": count,
            "overdue": overdue or 0,
            "open_risk": round(float(risk or 0.0), 2),
            "kev": kev or 0,
        }

    tickets = db.query(
        RemediationTicket.owner_team,
        func.sum(
            case((RemediationTicket.status.in_(ACTIVE_TICKET_STATUSES), 1), else_=0)
        ),
        func.sum(case((RemediationTicket.resolved_at >= since, 1), else_=0)),
    ).group_by(RemediationTicket.owner_team)
    tickets = scope.filter(tickets, RemediationTicket.owner_team)
    if team == NOT_SET:
        tickets = tickets.filter(RemediationTicket.owner_team.is_(None))
    elif team:
        tickets = tickets.filter(RemediationTicket.owner_team == team)
    ticket_counts = {
        owner: (active or 0, resolved or 0) for owner, active, resolved in tickets
    }

    team_rows = []
    for owner in set(teams) | set(by_team) | set(ticket_counts):
        backlog = teams.get(owner, {"open": 0, "overdue": 0, "open_risk": 0.0, "kev": 0})
        fixes = by_team.get(owner, {"fixed": 0, "on_time": 0, "days": 0.0})
        active, resolved = ticket_counts.get(owner, (0, 0))
        team_rows.append(
            {
                "team": owner or UNASSIGNED,
                "key": owner if owner is not None else NOT_SET,
                **backlog,
                "fixed": fixes["fixed"],
                "sla_percent": _rate(fixes["on_time"], fixes["fixed"]),
                "mttr_days": _mean(fixes["days"], fixes["fixed"]),
                "active_tickets": active,
                "resolved_tickets": resolved,
            }
        )
    team_rows.sort(key=lambda row: -row["open_risk"])

    return {
        "days": days,
        "fixed": overall["fixed"],
        "sla_percent": _rate(overall["on_time"], overall["fixed"]),
        "mttr_days": _mean(overall["days"], overall["fixed"]),
        "mttr_by_criticality": {
            level: _mean(values["days"], values["fixed"])
            for level, values in by_criticality.items()
        },
        "risk_removed": round(overall["risk"], 2),
        "new_findings": new_findings or 0,
        "open_now": open_count or 0,
        "open_at_start": open_start or 0,
        "open_risk_now": round(float(open_risk or 0.0), 2),
        "open_risk_at_start": round(float(risk_start or 0.0), 2),
        "teams": team_rows,
    }


def team_names(db: Session, scope: Scope) -> list[str]:
    rows = (
        db.query(Asset.owner_team)
        .filter(Asset.owner_team.isnot(None))
        .distinct()
        .order_by(Asset.owner_team)
    )
    return scope.visible_teams(row.owner_team for row in rows)
