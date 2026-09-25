"""Shared helpers for scan report parsers.

Every parser must emit findings in the same normalised shape so the ingestion
task can treat them uniformly:

    {
        "ip_address": str,
        "hostname": str | None,
        "operating_system": str | None,
        "cve_id": str,
        "title": str,
        "description": str | None,
        "cvss_score": float,   # clamped to [0, 10]
        "severity": str,       # always a valid Severity enum value
    }

File-based parsers also report which hosts the scan covered (``ParsedScan``),
including hosts that came back clean: that is what tells ingestion a finding
disappeared because it was fixed, not because its host was out of scope.
"""

import re
from dataclasses import dataclass, field
from typing import Any

from app.models.vulnerability import Severity

# CVE-YYYY-NNNN+ — used to reject junk values such as "NOCVE" or "".
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@dataclass
class ParsedScan:
    """Findings of a scan file plus the addresses it actually scanned."""

    findings: list[dict[str, Any]] = field(default_factory=list)
    scanned_addresses: set[str] = field(default_factory=set)


def safe_float(value: Any, default: float = 0.0) -> float:
    """Parse a CVSS score without ever raising, clamped to the valid range."""
    if value is None:
        return default
    try:
        score = float(str(value).strip())
    except (TypeError, ValueError):
        return default
    if score != score:  # NaN
        return default
    return min(10.0, max(0.0, score))


def severity_from_cvss(cvss_score: float) -> str:
    """Map a CVSS v3 base score onto a Severity enum value.

    CVSS defines a "None" band for 0.0, but the platform only tracks findings
    that carry actual risk, so 0.0 collapses to ``Low`` rather than producing a
    value that does not exist in the ``Severity`` enum.
    """
    if cvss_score >= 9.0:
        return Severity.critical.value
    if cvss_score >= 7.0:
        return Severity.high.value
    if cvss_score >= 4.0:
        return Severity.medium.value
    return Severity.low.value


def normalize_severity(raw: str | None, cvss_score: float) -> str:
    """Coerce a vendor severity label into a valid Severity enum value.

    Falls back to deriving the severity from the CVSS score when the vendor
    label is missing or unknown. This is what prevents values such as ``None``
    or ``Informational`` from reaching the database and failing the insert.
    """
    if raw:
        candidate = str(raw).strip().capitalize()
        if candidate in {s.value for s in Severity}:
            return candidate
    return severity_from_cvss(cvss_score)


def is_valid_cve(cve_id: str | None) -> bool:
    return bool(cve_id and CVE_PATTERN.match(cve_id.strip()))


def clean_text(value: str | None, max_length: int | None = None) -> str | None:
    """Strip whitespace, collapse empties to None, optionally truncate."""
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if max_length is not None and len(cleaned) > max_length:
        cleaned = cleaned[:max_length]
    return cleaned
