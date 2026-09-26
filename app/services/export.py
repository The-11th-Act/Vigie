"""CSV export of the remediation backlog.

The file leaves the platform: it is opened in a spreadsheet, forwarded, pasted
into tickets. Two consequences shape this module:

- Every cell a scanner or a user controls (hostnames, titles, notes) is guarded
  against formula injection: a value starting with ``= + - @`` or a control
  character would otherwise run as a formula in Excel or LibreOffice.
- Rows are written from a streamed query into a spooled temporary file, so a
  large backlog neither sits in memory nor depends on the database session
  still being open while the response is sent.
"""

import csv
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime

from sqlalchemy.orm import Query

from app.models.vulnerability import Status
from app.services.remediation import is_overdue
from app.services.risk_scoring import RiskInputs, explain_risk, risk_level

COLUMNS = (
    "asset",
    "ip_address",
    "business_criticality",
    "internet_facing",
    "cve_id",
    "title",
    "cvss",
    "epss",
    "in_kev",
    "risk_score",
    "risk_level",
    "status",
    "remediation_deadline",
    "overdue",
    "accepted_until",
    "detected_at",
    "last_seen_at",
    "sources",
    "risk_factors",
)

# Spreadsheets treat a cell starting with one of these as a formula (OWASP
# "CSV injection"). Tab and carriage return are included: some tools strip
# leading whitespace before evaluating.
FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")

SPOOL_IN_MEMORY_BYTES = 5 * 1024 * 1024
CHUNK_BYTES = 64 * 1024
BATCH_SIZE = 1_000


def neutralize(value) -> str:
    """A cell value that no spreadsheet will evaluate."""
    if value is None:
        return ""
    text = str(value)
    if text.startswith(FORMULA_TRIGGERS):
        return "'" + text
    return text


def export_findings_csv(query: Query) -> Iterator[bytes]:
    """Write the findings of ``query`` as CSV and return a chunk iterator.

    The query is fully consumed before this returns; the iterator only reads
    the temporary file back.
    """
    spool = tempfile.SpooledTemporaryFile(  # noqa: SIM115 - closed by _chunks
        max_size=SPOOL_IN_MEMORY_BYTES, mode="w+b"
    )
    # utf-8-sig: the BOM lets Excel open accented hostnames correctly.
    text = _TextSpool(spool)
    writer = csv.writer(text)
    writer.writerow(COLUMNS)
    now = datetime.now(UTC)
    for finding in query.yield_per(BATCH_SIZE):
        writer.writerow([neutralize(cell) for cell in _row(finding, now)])
    spool.seek(0)
    return _chunks(spool)


def _row(finding, now: datetime) -> list:
    asset, vuln = finding.asset, finding.vulnerability
    open_ = finding.status == Status.open
    deadline = finding.remediation_deadline if open_ else None
    factors = (
        explain_risk(RiskInputs.of(asset, vuln, deadline), now) if asset and vuln else []
    )
    return [
        asset.hostname if asset else None,
        asset.ip_address if asset else None,
        _value(asset.business_criticality) if asset else None,
        _yes_no(asset.internet_facing) if asset else None,
        vuln.cve_id if vuln else None,
        vuln.title if vuln else None,
        vuln.cvss_score if vuln else None,
        vuln.epss_score if vuln else None,
        _yes_no(vuln.in_kev) if vuln else None,
        finding.risk_score,
        risk_level(finding.risk_score or 0.0),
        _value(finding.status),
        _iso(finding.remediation_deadline),
        _yes_no(open_ and is_overdue(finding.remediation_deadline, now)),
        _iso(finding.accepted_until),
        _iso(finding.detected_at),
        _iso(finding.last_seen_at),
        ", ".join(detection.source for detection in finding.detections),
        "; ".join(factor["label"] for factor in factors),
    ]


def _chunks(spool) -> Iterator[bytes]:
    try:
        while chunk := spool.read(CHUNK_BYTES):
            yield chunk
    finally:
        spool.close()


class _TextSpool:
    """Text writes, encoded to UTF-8 (with BOM) into a binary spool."""

    def __init__(self, spool) -> None:
        self._spool = spool
        self._spool.write("﻿".encode())

    def write(self, text: str) -> int:
        return self._spool.write(text.encode("utf-8"))


def _value(value):
    return getattr(value, "value", value)


def _yes_no(flag) -> str:
    return "yes" if flag else "no"


def _iso(moment) -> str | None:
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.isoformat()
