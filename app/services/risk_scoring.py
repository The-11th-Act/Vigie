"""Risk scoring — the core of the RBVM model.

A raw CVSS score describes a vulnerability in the abstract. Risk is what that
vulnerability means *here*: a 9.8 on an isolated lab box matters less than a 7.5
on the production payment database. The score below contextualises CVSS with
business criticality and finding age so the backlog can be ordered by what
actually needs fixing first.
"""

from datetime import datetime, timezone
from typing import Optional

# How much the business criticality of the host amplifies or dampens CVSS.
CRITICALITY_MULTIPLIERS = {
    "Critical": 1.5,
    "High": 1.2,
    "Medium": 1.0,
    "Low": 0.7,
}

# Additive penalty (in points) once a finding blows past its remediation SLA.
# Capped so an old low-severity issue never outranks a fresh critical one.
MAX_OVERDUE_PENALTY = 1.5
OVERDUE_PENALTY_PER_30_DAYS = 0.5


def calculate_risk_score(
    cvss_score: float,
    business_criticality: str,
    remediation_deadline: Optional[datetime] = None,
    now: Optional[datetime] = None,
) -> float:
    """Return a contextual risk score in the range [0.0, 10.0].

    ``remediation_deadline`` is optional: when supplied, findings past their SLA
    accrue an escalating penalty so they surface at the top of the backlog.
    """
    multiplier = CRITICALITY_MULTIPLIERS.get(_as_str(business_criticality), 1.0)
    score = _as_float(cvss_score) * multiplier
    score += _overdue_penalty(remediation_deadline, now)
    return min(10.0, max(0.0, round(score, 2)))


def risk_level(risk_score: float) -> str:
    """Bucket a risk score into a label for dashboards and filtering."""
    if risk_score >= 9.0:
        return "Critical"
    if risk_score >= 7.0:
        return "High"
    if risk_score >= 4.0:
        return "Medium"
    return "Low"


def _overdue_penalty(
    remediation_deadline: Optional[datetime], now: Optional[datetime]
) -> float:
    if remediation_deadline is None:
        return 0.0

    reference = now or datetime.now(timezone.utc)
    deadline = remediation_deadline
    # Tolerate naive datetimes, which is what SQLite hands back in tests.
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)

    days_overdue = (reference - deadline).days
    if days_overdue <= 0:
        return 0.0

    penalty = (days_overdue / 30.0) * OVERDUE_PENALTY_PER_30_DAYS
    return min(MAX_OVERDUE_PENALTY, penalty)


def _as_str(value) -> str:
    """Accept either a raw string or a Criticality enum member."""
    return getattr(value, "value", value)


def _as_float(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
