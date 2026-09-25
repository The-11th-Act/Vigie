"""Stored risk scores must follow every input they depend on.

``risk_score`` is persisted so the backlog sorts in SQL. The trap is time: the
overdue penalty grows every day, so a score computed at ingestion goes stale on
its own even when nothing about the finding changes.
"""

from datetime import UTC, datetime, timedelta

import pytest

from app.models.asset import Asset, Criticality
from app.models.vulnerability import AssetVulnerability, Status, Vulnerability
from app.services.rescoring import rescore_open_findings

NOW = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)


@pytest.fixture
def make_finding(db_session):
    counter = iter(range(1, 1000))

    def _make(
        cvss=6.0,
        criticality=Criticality.medium,
        deadline=None,
        status=Status.open,
        risk_score=0.0,
    ):
        n = next(counter)
        asset = Asset(ip_address=f"10.20.0.{n}", business_criticality=criticality)
        vuln = Vulnerability(
            cve_id=f"CVE-2026-{1000 + n}",
            title="Rescoring",
            cvss_score=cvss,
            severity="Medium",
        )
        db_session.add_all([asset, vuln])
        db_session.flush()
        finding = AssetVulnerability(
            asset_id=asset.id,
            vulnerability_id=vuln.id,
            status=status,
            risk_score=risk_score,
            remediation_deadline=deadline,
        )
        db_session.add(finding)
        db_session.commit()
        return finding

    return _make


class TestRescoreOpenFindings:
    def test_a_passed_deadline_raises_a_frozen_score(self, db_session, make_finding):
        """Regression: nothing recomputed scores between scans, so a late finding
        on a host nobody rescans kept the rank it had at ingestion."""
        finding = make_finding(
            cvss=6.0, deadline=NOW - timedelta(days=60), risk_score=6.0
        )

        changed = rescore_open_findings(db_session, now=NOW)

        assert changed == 1
        assert finding.risk_score == 7.0  # 6.0 + 60 days late -> +1.0

    def test_counts_only_scores_that_moved(self, db_session, make_finding):
        make_finding(cvss=6.0, risk_score=6.0)  # already right
        make_finding(cvss=6.0, risk_score=2.0)  # stale

        assert rescore_open_findings(db_session, now=NOW) == 1

    def test_closed_findings_are_left_alone(self, db_session, make_finding):
        """A remediated or accepted finding keeps the score it was closed with."""
        closed = make_finding(cvss=9.0, status=Status.remediated, risk_score=1.0)

        assert rescore_open_findings(db_session, now=NOW) == 0
        assert closed.risk_score == 1.0

    def test_criteria_narrow_the_rescoring(self, db_session, make_finding):
        target = make_finding(cvss=8.0, risk_score=0.0)
        other = make_finding(cvss=8.0, risk_score=0.0)

        changed = rescore_open_findings(
            db_session, AssetVulnerability.asset_id == target.asset_id, now=NOW
        )

        assert changed == 1
        assert target.risk_score == 8.0
        assert other.risk_score == 0.0

    def test_uses_the_asset_criticality(self, db_session, make_finding):
        finding = make_finding(cvss=6.0, criticality=Criticality.critical)

        rescore_open_findings(db_session, now=NOW)

        assert finding.risk_score == 9.0  # 6.0 * 1.5

    def test_the_caller_commits(self, db_session, make_finding, monkeypatch):
        """The service only stages changes, so a caller can roll them back with
        the rest of its transaction."""
        make_finding(cvss=8.0, risk_score=0.0)
        monkeypatch.setattr(
            db_session, "commit", lambda: pytest.fail("the service committed")
        )

        assert rescore_open_findings(db_session, now=NOW) == 1
