"""Daily backlog snapshots and the history rebuilt before them."""

from datetime import UTC, datetime, time, timedelta

import pytest

from app.models.asset import Asset
from app.models.snapshot import BacklogSnapshot
from app.models.vulnerability import AssetVulnerability, Status, Vulnerability
from app.services.snapshots import HISTORY_DAYS, compute_day, record_snapshots

TODAY = datetime.now(UTC).date()


def at(days_ago: int, hour: int = 12) -> datetime:
    return datetime.combine(TODAY - timedelta(days=days_ago), time(hour), tzinfo=UTC)


@pytest.fixture
def make(db_session):
    counter = iter(range(1, 1000))

    def finding(
        team="Servers",
        detected=10,
        fixed=None,
        status=Status.open,
        deadline=None,
        risk=8.0,
        kev=False,
    ):
        n = next(counter)
        asset = Asset(ip_address=f"10.0.0.{n}", owner_team=team)
        vuln = Vulnerability(
            cve_id=f"CVE-2024-{n:04d}",
            title="t",
            cvss_score=8.0,
            severity="High",
            in_kev=kev,
        )
        db_session.add_all([asset, vuln])
        db_session.flush()
        link = AssetVulnerability(
            asset_id=asset.id,
            vulnerability_id=vuln.id,
            status=status,
            risk_score=risk,
            detected_at=at(detected),
            fixed_at=at(fixed) if fixed is not None else None,
            remediation_deadline=at(deadline) if deadline is not None else None,
        )
        db_session.add(link)
        db_session.commit()
        return link

    return finding


class TestComputeDay:
    def test_open_at_the_end_of_the_day(self, db_session, make):
        make(detected=10)  # open since
        make(detected=0)  # found today: not yet there yesterday
        make(detected=10, fixed=3, status=Status.remediated)  # closed before
        make(detected=10, fixed=0, status=Status.remediated)  # closed today

        yesterday = compute_day(db_session, TODAY - timedelta(days=1))["Servers"]
        four_days_ago = compute_day(db_session, TODAY - timedelta(days=4))["Servers"]

        assert yesterday["open_findings"] == 2
        assert four_days_ago["open_findings"] == 3

    def test_high_kev_overdue_and_risk(self, db_session, make):
        make(risk=9.5, kev=True, deadline=5)
        make(risk=5.0, deadline=-5)

        day = compute_day(db_session, TODAY - timedelta(days=1))["Servers"]

        assert (day["open_high"], day["open_kev"], day["overdue"]) == (1, 1, 1)
        assert day["open_risk"] == pytest.approx(14.5)

    def test_fixes_of_the_day(self, db_session, make):
        # Fixed in 4 days, before its deadline; fixed in 8 days, after it.
        make(detected=5, fixed=1, status=Status.remediated, deadline=0, risk=9.0)
        make(detected=9, fixed=1, status=Status.remediated, deadline=3, risk=6.0)
        # Accepted, not fixed: no remediation time.
        make(detected=9, fixed=1, status=Status.risk_accepted)

        day = compute_day(db_session, TODAY - timedelta(days=1))["Servers"]

        assert (day["fixed"], day["fixed_on_time"]) == (2, 1)
        assert day["fixed_days_total"] == pytest.approx(12.0)
        assert day["fixed_risk"] == pytest.approx(15.0)

    def test_per_team_hosts_without_one_included(self, db_session, make):
        make(team="Servers")
        make(team=None)

        day = compute_day(db_session, TODAY - timedelta(days=1))

        assert set(day) == {"Servers", ""}
        assert day[""]["new_findings"] == 0
        assert day[""]["open_findings"] == 1


class TestRecording:
    def test_yesterday_is_final_and_the_past_rebuilt(self, db_session, make):
        make(detected=30)

        result = record_snapshots(db_session)

        assert result["rebuilt"] == HISTORY_DAYS - 1
        yesterday = (
            db_session.query(BacklogSnapshot)
            .filter_by(day=TODAY - timedelta(days=1))
            .one()
        )
        assert (yesterday.estimated, yesterday.open_findings) == (False, 1)
        older = (
            db_session.query(BacklogSnapshot)
            .filter_by(day=TODAY - timedelta(days=40))
            .one()
        )
        assert (older.estimated, older.open_findings) == (True, 0)

    def test_the_next_pass_rebuilds_nothing(self, db_session, make):
        make(detected=30)
        record_snapshots(db_session)

        assert record_snapshots(db_session)["rebuilt"] == 0

    def test_a_day_without_findings_is_still_recorded(self, db_session):
        record_snapshots(db_session)

        assert record_snapshots(db_session)["rebuilt"] == 0
        assert db_session.query(BacklogSnapshot).count() == HISTORY_DAYS
