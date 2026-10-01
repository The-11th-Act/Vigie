"""Remediation SLA policy."""

from datetime import UTC, date, datetime, time, timedelta

from app.core.config import settings
from app.services.policy import DEFAULT_SLA_DAYS, SLA_DAYS, get_sla_days

__all__ = [
    "DEFAULT_SLA_DAYS",
    "SLA_DAYS",
    "apply_kev_sla",
    "calculate_remediation_deadline",
    "get_sla_days",
]


def calculate_remediation_deadline(
    severity: str, detection_time: datetime | None = None
) -> datetime:
    """Return the timezone-aware deadline by which a finding must be fixed."""
    if detection_time is None:
        detection_time = datetime.now(UTC)
    elif detection_time.tzinfo is None:
        detection_time = detection_time.replace(tzinfo=UTC)

    days = get_sla_days(severity)
    return detection_time + timedelta(days=days)


def apply_kev_sla(
    deadline: datetime | None,
    detected_at: datetime | None,
    kev_date_added: date | None,
    *,
    is_ransomware: bool = False,
) -> datetime | None:
    """Tighten a deadline for a CVE that is exploited in the wild.

    A severity window gives a "Medium" CVE 90 days even when attackers already
    use it. KEV entries get ``KEV_SLA_DAYS`` instead, counted from the later of
    detection and KEV listing: a CVE listed months after detection gets its days
    from the listing, not an instant breach. CISA's own ``dueDate`` is not used,
    since for older entries it is already in the past.

    When ``is_ransomware`` is True, the window tightens further to
    ``RANSOMWARE_SLA_DAYS`` (default 7 days) to reflect the urgency of an active
    ransomware threat.

    The result is never later than ``deadline``: a CVE leaving the catalogue does
    not loosen a commitment already made.
    """
    days = (
        settings.RANSOMWARE_SLA_DAYS
        if is_ransomware and settings.RANSOMWARE_SLA_DAYS > 0
        else settings.KEV_SLA_DAYS
    )
    if days <= 0:
        return deadline

    anchor = _aware(detected_at) if detected_at else datetime.now(UTC)
    if kev_date_added is not None:
        anchor = max(anchor, datetime.combine(kev_date_added, time.min, tzinfo=UTC))
    kev_deadline = anchor + timedelta(days=days)

    if deadline is None:
        return kev_deadline
    return min(_aware(deadline), kev_deadline)


def is_overdue(
    remediation_deadline: datetime | None, now: datetime | None = None
) -> bool:
    """True when a finding has passed its remediation deadline."""
    if remediation_deadline is None:
        return False

    reference = now or datetime.now(UTC)
    deadline = remediation_deadline
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=UTC)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=UTC)

    return deadline < reference


def _aware(value: datetime) -> datetime:
    """Tolerate naive datetimes, which is what SQLite hands back."""
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _as_str(value) -> str:
    """Accept either a raw string or a Severity enum member."""
    return getattr(value, "value", value)
