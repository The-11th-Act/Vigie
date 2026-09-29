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
        "remediations": list,  # optional, see remediation() below
    }

``remediations`` absent means the source says nothing about how to fix the
finding; an empty list means it reported the finding without any fix.

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


# Microsoft update identifiers, however the scanner spells them: "KB5034441",
# "KB 5034441", or the bare number of a Nessus "MSKB:5034441" cross-reference.
KB_PATTERN = re.compile(r"\bKB\s?(\d{6,8})\b", re.IGNORECASE)
KB_NUMBER = re.compile(r"^(?:MSKB:|KB\s?)?(\d{6,8})$", re.IGNORECASE)

# "Installed version : 2.4.52" / "Fixed version : 2.4.58", as Nessus plugin
# output and OpenVAS result descriptions both print them.
INSTALLED_VERSION = re.compile(
    r"^\s*Installed version\s*:\s*(\S.*?)\s*$", re.IGNORECASE | re.MULTILINE
)
FIXED_VERSION = re.compile(
    r"^\s*Fixed version\s*:\s*(\S.*?)\s*$", re.IGNORECASE | re.MULTILINE
)

MAX_REFERENCE_LENGTH = 128
MAX_TITLE_LENGTH = 512
MAX_SOLUTION_LENGTH = 4_000
MAX_URL_LENGTH = 1_024
MAX_FAMILY_LENGTH = 128
MAX_VERSION_LENGTH = 256


def kb_reference(value: str | None) -> str | None:
    """``KB5034441`` for any spelling of a KB number, None otherwise."""
    if not value:
        return None
    match = KB_NUMBER.match(value.strip())
    return f"KB{match.group(1)}" if match else None


def kb_references_in(text: str | None) -> list[str]:
    """Every KB named in free text, in order of appearance, without repeats."""
    if not text:
        return []
    return list(dict.fromkeys(f"KB{number}" for number in KB_PATTERN.findall(text)))


def versions_in(text: str | None) -> tuple[str | None, str | None]:
    """The installed and fixed versions a scanner printed, when it did."""
    if not text:
        return None, None
    installed = INSTALLED_VERSION.search(text)
    fixed = FIXED_VERSION.search(text)
    return (
        clean_text(installed.group(1) if installed else None, MAX_VERSION_LENGTH),
        clean_text(fixed.group(1) if fixed else None, MAX_VERSION_LENGTH),
    )


def first_url(text: str | None) -> str | None:
    """The first http(s) link of a whitespace-separated list."""
    if not text:
        return None
    for token in text.split():
        if token.lower().startswith(("https://", "http://")):
            return clean_text(token, MAX_URL_LENGTH)
    return None


def remediation(
    kind: str,
    reference: str,
    *,
    title: str | None = None,
    solution: str | None = None,
    url: str | None = None,
    family: str | None = None,
    installed_version: str | None = None,
    fixed_version: str | None = None,
) -> dict[str, Any]:
    """One entry of a finding's ``remediations``, lengths already bounded."""
    # Shown as a link: a scanner-supplied javascript: or data: URL is dropped.
    if url and not url.strip().lower().startswith(("https://", "http://")):
        url = None
    return {
        "kind": kind,
        "reference": reference[:MAX_REFERENCE_LENGTH],
        "title": clean_text(title, MAX_TITLE_LENGTH),
        "solution": clean_text(solution, MAX_SOLUTION_LENGTH),
        "url": clean_text(url, MAX_URL_LENGTH),
        "family": clean_text(family, MAX_FAMILY_LENGTH),
        "installed_version": clean_text(installed_version, MAX_VERSION_LENGTH),
        "fixed_version": clean_text(fixed_version, MAX_VERSION_LENGTH),
    }
