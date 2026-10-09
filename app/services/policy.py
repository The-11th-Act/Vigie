"""Centralized RBVM policy: CVSS severity thresholds, risk scoring parameters, and SLA windows.

Consolidates previously scattered constants across parsers and services so that
business policy can be configured via environment variables and maintained in a
single place without diverging scales.
"""

from __future__ import annotations

from typing import Any

from app.core.config import settings
from app.models.vulnerability import Severity

# CVSS v3 score thresholds used for both vendor finding severity categorization
# and contextual risk level classification. Guaranteed to remain unified.
CVSS_THRESHOLDS = {
    "Critical": 9.0,
    "High": 7.0,
    "Medium": 4.0,
    "Low": 0.0,
}

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

# Exploitation observed in the wild outweighs any prediction, so a KEV entry
# takes this multiplier instead of its EPSS band.
KEV_MULTIPLIER = 1.3
# A known-exploited vulnerability is at least "High" risk, whatever the host:
# this is the lower bound of the "High" level in ``risk_level``.
KEV_RISK_FLOOR = 7.0

# An active ransomware campaign represents an immediate operational threat.
# Stacks on top of KEV to prioritize extortion vectors.
RANSOMWARE_MULTIPLIER = 1.15
RANSOMWARE_RISK_FLOOR = 7.5

# EPSS probability -> multiplier, by band, highest threshold first. Bands rather
# than a continuous factor keep the score explainable, and stable.
EPSS_BANDS = (
    (0.50, 1.30),
    (0.10, 1.15),
    (0.01, 1.00),
    (0.00, 0.90),
)

INTERNET_FACING_MULTIPLIER = 1.2

# Several multipliers stacked on a critical asset would push most of the top of
# the backlog to 10.0, where nothing can be told apart any more.
MAX_CONTEXT_MULTIPLIER = 1.5

# Each severity's SLA window is a setting; the defaults live in Settings only.
SLA_SETTINGS: dict[str, str] = {
    "Critical": "SLA_CRITICAL_DAYS",
    "High": "SLA_HIGH_DAYS",
    "Medium": "SLA_MEDIUM_DAYS",
    "Low": "SLA_LOW_DAYS",
}


def _as_str(value: Any) -> str:
    """Accept either a string or an enum member."""
    return getattr(value, "value", str(value) if value is not None else "")


def get_sla_days(severity: Any) -> int:
    """Return the configured SLA days for a given severity level."""
    name = SLA_SETTINGS.get(_as_str(severity), "SLA_DEFAULT_DAYS")
    return getattr(settings, name)


class _SlaDaysProxy(dict):
    """Dictionary proxy for SLA_DAYS that dynamically reflects application settings."""

    def __getitem__(self, key: str) -> int:
        return get_sla_days(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return get_sla_days(key)
        except KeyError:
            return default

    def __contains__(self, key: Any) -> bool:
        return _as_str(key) in SLA_SETTINGS

    def __iter__(self):
        return iter(SLA_SETTINGS)

    def __len__(self) -> int:
        return len(SLA_SETTINGS)

    def items(self):
        return [(k, get_sla_days(k)) for k in SLA_SETTINGS]

    def values(self):
        return [get_sla_days(k) for k in SLA_SETTINGS]

    def keys(self):
        return SLA_SETTINGS.keys()


SLA_DAYS = _SlaDaysProxy()


def severity_from_cvss(cvss_score: float) -> str:
    """Map a CVSS v3 base score onto a Severity enum value.

    CVSS defines a "None" band for 0.0, but the platform only tracks findings
    that carry actual risk, so 0.0 collapses to ``Low`` rather than producing a
    value that does not exist in the ``Severity`` enum.
    """
    if cvss_score >= CVSS_THRESHOLDS["Critical"]:
        return Severity.critical.value
    if cvss_score >= CVSS_THRESHOLDS["High"]:
        return Severity.high.value
    if cvss_score >= CVSS_THRESHOLDS["Medium"]:
        return Severity.medium.value
    return Severity.low.value


def risk_level(risk_score: float) -> str:
    """Bucket a risk score into a label for dashboards and filtering."""
    if risk_score >= CVSS_THRESHOLDS["Critical"]:
        return "Critical"
    if risk_score >= CVSS_THRESHOLDS["High"]:
        return "High"
    if risk_score >= CVSS_THRESHOLDS["Medium"]:
        return "Medium"
    return "Low"
