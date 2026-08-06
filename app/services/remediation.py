"""Remediation SLA policy."""

from datetime import UTC, datetime, timedelta

# Days allowed to remediate, by severity. Loosely aligned with common
# regulatory guidance (e.g. PCI DSS / CISA BOD 22-01 style windows).
SLA_DAYS = {
    "Critical": 14,
    "High": 30,
    "Medium": 90,
    "Low": 180,
}

DEFAULT_SLA_DAYS = 90


def calculate_remediation_deadline(
    severity: str, detection_time: datetime | None = None
) -> datetime:
    """Return the timezone-aware deadline by which a finding must be fixed."""
    if detection_time is None:
        detection_time = datetime.now(UTC)
    elif detection_time.tzinfo is None:
        detection_time = detection_time.replace(tzinfo=UTC)

    days = SLA_DAYS.get(_as_str(severity), DEFAULT_SLA_DAYS)
    return detection_time + timedelta(days=days)


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


def _as_str(value) -> str:
    """Accept either a raw string or a Severity enum member."""
    return getattr(value, "value", value)
