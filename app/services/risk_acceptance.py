"""The end of a risk acceptance.

Accepting a risk used to close a finding for good. An acceptance now has an end
date, and two events hand the finding back to the backlog: the date passing, and
the CVE entering the CISA KEV catalogue — a risk accepted as theoretical is no
longer theoretical once it is exploited in the wild.

Both reopenings are recorded in the triage audit log under a "system" actor, so
the trail says why a finding the team had closed came back. The caller commits.
"""

from collections.abc import Iterable
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.models.vulnerability import AssetVulnerability, FindingAuditLog, Status
from app.services.rescoring import rescore_open_findings

SYSTEM_ACTOR = "system"


def expire_risk_acceptances(db: Session, now: datetime | None = None) -> int:
    """Reopen the accepted findings whose acceptance has run out."""
    now = now or datetime.now(UTC)
    expired = (
        db.query(AssetVulnerability)
        .filter(
            AssetVulnerability.status == Status.risk_accepted,
            AssetVulnerability.accepted_until.isnot(None),
            AssetVulnerability.accepted_until < now,
        )
        .all()
    )
    return reopen_accepted(
        db,
        expired,
        lambda finding: (
            "Risk acceptance expired on "
            f"{_date(finding.accepted_until)}; to be reviewed."
        ),
    )


def reopen_for_kev(db: Session, vulnerability_ids: Iterable[int], kev_dates: dict) -> int:
    """Reopen the accepted findings of CVEs that just entered CISA KEV.

    False positives stay closed: a finding that is not there cannot become more
    exploitable.
    """
    ids = list(vulnerability_ids)
    if not ids:
        return 0
    accepted = (
        db.query(AssetVulnerability)
        .filter(
            AssetVulnerability.vulnerability_id.in_(ids),
            AssetVulnerability.status == Status.risk_accepted,
        )
        .all()
    )

    def note(finding) -> str:
        added = kev_dates.get(finding.vulnerability_id)
        when = f" on {added.isoformat()}" if added else ""
        return (
            f"CVE added to the CISA KEV catalogue{when}: exploited in the wild, "
            "risk acceptance to be reviewed."
        )

    return reopen_accepted(db, accepted, note)


def reopen_accepted(db: Session, findings: list[AssetVulnerability], note_for) -> int:
    for finding in findings:
        note = note_for(finding)
        db.add(
            FindingAuditLog(
                finding_id=finding.id,
                user_id=None,
                username=SYSTEM_ACTOR,
                old_status=Status.risk_accepted.value,
                new_status=Status.open.value,
                status_note=note,
            )
        )
        finding.status = Status.open
        finding.status_note = note
        finding.fixed_at = None
        finding.accepted_until = None

    if findings:
        db.flush()
        # Scores of closed findings are frozen; reopened, they must be current.
        rescore_open_findings(db, AssetVulnerability.id.in_([f.id for f in findings]))
    return len(findings)


def _date(value: datetime) -> str:
    return value.date().isoformat() if value else "?"
