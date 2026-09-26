"""Reopening accepted findings: when the acceptance ends, or the CVE enters KEV."""

from datetime import UTC, date, datetime, timedelta

import pytest

from app.models.asset import Asset
from app.models.vulnerability import (
    AssetVulnerability,
    FindingAuditLog,
    Status,
    Vulnerability,
)
from app.parsers.threat_feeds import KevCatalog, KevEntry
from app.services.risk_acceptance import SYSTEM_ACTOR, expire_risk_acceptances
from app.services.threat_intel import apply_kev

NOW = datetime(2026, 9, 26, 2, 0, tzinfo=UTC)


@pytest.fixture
def accepted(db_session):
    counter = iter(range(1, 100))

    def _make(until, status=Status.risk_accepted, cve=None):
        n = next(counter)
        asset = Asset(ip_address=f"10.90.0.{n}")
        vuln = Vulnerability(
            cve_id=cve or f"CVE-2026-{9000 + n}",
            title="Accepted",
            cvss_score=8.0,
            severity="High",
        )
        db_session.add_all([asset, vuln])
        db_session.flush()
        finding = AssetVulnerability(
            asset_id=asset.id,
            vulnerability_id=vuln.id,
            status=status,
            status_note="Compensating control.",
            accepted_until=until,
            fixed_at=NOW - timedelta(days=10),
            risk_score=1.0,
        )
        db_session.add(finding)
        db_session.commit()
        return finding

    return _make


def audit_of(db_session, finding):
    return (
        db_session.query(FindingAuditLog)
        .filter(FindingAuditLog.finding_id == finding.id)
        .order_by(FindingAuditLog.id.desc())
        .first()
    )


class TestExpiry:
    def test_an_expired_acceptance_is_reopened_and_traced(self, db_session, accepted):
        finding = accepted(NOW - timedelta(hours=1))

        assert expire_risk_acceptances(db_session, NOW) == 1

        assert finding.status == Status.open
        assert finding.accepted_until is None
        assert finding.fixed_at is None
        assert finding.risk_score == 8.0  # rescored now that it is open again
        entry = audit_of(db_session, finding)
        assert entry.username == SYSTEM_ACTOR
        assert entry.old_status == "Risk Accepted" and entry.new_status == "Open"
        assert "expired" in entry.status_note

    def test_a_running_acceptance_is_left_alone(self, db_session, accepted):
        finding = accepted(NOW + timedelta(days=3))

        assert expire_risk_acceptances(db_session, NOW) == 0
        assert finding.status == Status.risk_accepted

    def test_other_closed_statuses_do_not_expire(self, db_session, accepted):
        dismissed = accepted(NOW - timedelta(days=1), status=Status.false_positive)

        assert expire_risk_acceptances(db_session, NOW) == 0
        assert dismissed.status == Status.false_positive


def catalog(*cves):
    return KevCatalog(
        version="2026.09.26",
        released=date(2026, 9, 26),
        entries={cve: KevEntry(cve, date_added=date(2026, 9, 25)) for cve in cves},
    )


class TestKevEntry:
    def test_an_accepted_finding_is_reopened_when_its_cve_enters_kev(
        self, db_session, accepted
    ):
        """Accepted as theoretical; now exploited in the wild."""
        finding = accepted(NOW + timedelta(days=60), cve="CVE-2026-1111")

        apply_kev(db_session, catalog("CVE-2026-1111"), source="network", now=NOW)

        assert finding.status == Status.open
        entry = audit_of(db_session, finding)
        assert entry.username == SYSTEM_ACTOR
        assert "KEV" in entry.status_note and "2026-09-25" in entry.status_note

    def test_a_false_positive_stays_closed(self, db_session, accepted):
        dismissed = accepted(None, status=Status.false_positive, cve="CVE-2026-2222")

        apply_kev(db_session, catalog("CVE-2026-2222"), source="network", now=NOW)

        assert dismissed.status == Status.false_positive

    def test_a_cve_already_in_kev_does_not_reopen_again(self, db_session, accepted):
        """Re-accepting a KEV finding is a deliberate decision: the next daily
        pull must not undo it."""
        accepted(NOW + timedelta(days=60), cve="CVE-2026-3333")
        apply_kev(db_session, catalog("CVE-2026-3333"), source="network", now=NOW)
        again = accepted(NOW + timedelta(days=60), cve="CVE-2026-3334")
        again.vulnerability.in_kev = True
        db_session.commit()

        apply_kev(
            db_session,
            catalog("CVE-2026-3333", "CVE-2026-3334"),
            source="network",
            now=NOW,
        )

        assert again.status == Status.risk_accepted
