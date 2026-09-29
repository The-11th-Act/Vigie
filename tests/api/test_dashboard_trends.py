"""Dashboard trends and remediation performance."""

from datetime import UTC, date, datetime, time, timedelta

import pytest

from app.core.security import decode_token, require_admin
from app.main import app
from app.models.asset import Asset, Criticality
from app.models.remediation import RemediationAction
from app.models.snapshot import BacklogSnapshot
from app.models.ticket import RemediationTicket
from app.models.vulnerability import AssetVulnerability, Status, Vulnerability
from tests.conftest import _make_user

TODAY = datetime.now(UTC).date()


def at(days_ago: int) -> datetime:
    return datetime.combine(TODAY - timedelta(days=days_ago), time(12), tzinfo=UTC)


def snapshot(day: date, team: str, **values):
    base = {
        "open_findings": 0,
        "open_high": 0,
        "open_kev": 0,
        "overdue": 0,
        "open_risk": 0.0,
        "new_findings": 0,
        "fixed": 0,
        "fixed_on_time": 0,
        "fixed_days_total": 0.0,
        "fixed_risk": 0.0,
    }
    base.update(values)
    return BacklogSnapshot(day=day, owner_team=team, **base)


class TestTrends:
    @pytest.fixture
    def history(self, db_session):
        d1, d2 = TODAY - timedelta(days=2), TODAY - timedelta(days=1)
        db_session.add_all(
            [
                snapshot(d1, "Servers", open_findings=10, open_risk=80.0, estimated=True),
                snapshot(d1, "", open_findings=2, open_risk=10.0),
                snapshot(d2, "Servers", open_findings=8, fixed=2, fixed_days_total=10.0),
                snapshot(d2, "", open_findings=2),
                # Beyond the window asked for.
                snapshot(TODAY - timedelta(days=200), "Servers", open_findings=99),
            ]
        )
        db_session.commit()

    def test_the_estate_is_the_sum_of_the_teams(self, client, history):
        points = client.get("/api/v1/dashboard/trends").json()["points"]

        assert [p["open_findings"] for p in points] == [12, 10]
        assert points[0]["estimated"] is True
        assert points[1]["estimated"] is False
        assert points[1]["mttr_days"] == 5.0
        assert points[0]["mttr_days"] is None

    def test_one_team(self, client, history):
        points = client.get(
            "/api/v1/dashboard/trends", params={"owner_team": "__none__"}
        ).json()["points"]
        assert [p["open_findings"] for p in points] == [2, 2]


@pytest.fixture
def worked(db_session):
    """Servers fixed two findings in 30 days (one late), Workplace one."""
    servers = Asset(
        ip_address="10.0.0.1",
        owner_team="Servers",
        business_criticality=Criticality.critical,
    )
    workplace = Asset(ip_address="10.0.1.1", owner_team="Workplace")
    db_session.add_all([servers, workplace])
    db_session.flush()

    def add(asset, n, status, detected, fixed=None, deadline=None, risk=8.0):
        vuln = Vulnerability(
            cve_id=f"CVE-2024-{n:04d}", title="t", cvss_score=8.0, severity="High"
        )
        db_session.add(vuln)
        db_session.flush()
        db_session.add(
            AssetVulnerability(
                asset_id=asset.id,
                vulnerability_id=vuln.id,
                status=status,
                risk_score=risk,
                detected_at=at(detected),
                fixed_at=at(fixed) if fixed is not None else None,
                remediation_deadline=at(deadline) if deadline is not None else None,
            )
        )

    add(
        servers, 1, Status.remediated, detected=20, fixed=10, deadline=5
    )  # 10 days, on time
    add(servers, 2, Status.remediated, detected=40, fixed=2, deadline=20)  # 38 days, late
    add(servers, 3, Status.open, detected=50, deadline=10, risk=9.0)  # overdue
    add(workplace, 4, Status.remediated, detected=6, fixed=4, risk=5.0)  # 2 days
    add(workplace, 5, Status.remediated, detected=100, fixed=60)  # outside the window
    action = RemediationAction(reference="KB5034127", kind="kb")
    db_session.add(action)
    db_session.flush()
    db_session.add_all(
        [
            RemediationTicket(action_id=action.id, owner_team="Servers", title="t"),
            RemediationTicket(
                action_id=action.id,
                owner_team="Workplace",
                title="t",
                status="resolved",
                resolved_at=at(3),
            ),
        ]
    )
    db_session.commit()


class TestPerformance:
    def test_the_last_30_days(self, client, worked):
        body = client.get("/api/v1/dashboard/performance").json()

        assert body["fixed"] == 3
        assert body["sla_percent"] == pytest.approx(66.7)
        assert body["mttr_days"] == pytest.approx(round((10 + 38 + 2) / 3, 1))
        assert body["mttr_by_criticality"]["Critical"] == 24.0
        assert body["mttr_by_criticality"]["Low"] is None
        assert body["risk_removed"] == pytest.approx(21.0)
        assert body["open_now"] == 1
        # Open 30 days ago: CVE-2 (fixed 2 days ago), CVE-3; CVE-5 closed at 60.
        assert body["open_at_start"] == 2
        assert body["team_names"] == ["Servers", "Workplace"]

    def test_per_team(self, client, worked):
        teams = {
            row["team"]: row
            for row in client.get("/api/v1/dashboard/performance").json()["teams"]
        }

        servers = teams["Servers"]
        assert (servers["open"], servers["overdue"], servers["fixed"]) == (1, 1, 2)
        assert servers["sla_percent"] == 50.0
        assert (servers["active_tickets"], servers["resolved_tickets"]) == (1, 0)
        assert teams["Workplace"]["resolved_tickets"] == 1
        assert teams["Workplace"]["mttr_days"] == 2.0

    def test_one_team(self, client, worked):
        body = client.get(
            "/api/v1/dashboard/performance", params={"owner_team": "Workplace"}
        ).json()
        assert body["fixed"] == 1
        assert [row["team"] for row in body["teams"]] == ["Workplace"]


class TestRebuild:
    def test_an_administrator_rebuilds_history(self, client, worked):
        response = client.post("/api/v1/dashboard/snapshots/rebuild")

        assert response.status_code == 200
        points = client.get("/api/v1/dashboard/trends").json()["points"]
        assert len(points) == 90
        assert points[-1]["estimated"] is False

    def test_nobody_else(self, client, db_session):
        user = _make_user(db_session, "ana-dash", "analyst")
        app.dependency_overrides.pop(require_admin, None)
        app.dependency_overrides[decode_token] = lambda: {
            "sub": str(user.id),
            "role": "analyst",
            "username": user.username,
        }
        assert client.post("/api/v1/dashboard/snapshots/rebuild").status_code == 403
