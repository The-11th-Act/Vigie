"""Scopes: a user limited to some teams sees nothing of the others, anywhere.

The sweep below calls every GET route of the API, read from the OpenAPI schema,
as a user scoped to team Alpha, with the ids of team Bravo's objects in the
paths. No response may carry anything of Bravo's. A route added later without
its scope fails here without anyone having to remember to write a test for it.
"""

import re
from datetime import UTC, datetime, timedelta

import pytest

from app.core.config import settings
from app.core.scope import EVERYTHING, NO_TEAM, Scope, scope_of
from app.core.security import decode_token, require_admin
from app.main import app
from app.models.asset import Asset
from app.models.extract import SavedExtract
from app.models.remediation import RemediationAction
from app.models.scan import ScanJob, ScanStatus
from app.models.snapshot import BacklogSnapshot
from app.models.ticket import RemediationTicket
from app.models.user import UserTeam
from app.models.vulnerability import AssetVulnerability, Vulnerability
from app.parsers.utils import remediation
from app.services.extracts import DATASETS
from app.services.ingestion import ingest_findings
from app.services.tickets import create_tickets
from tests.conftest import _make_user

# Everything that identifies Bravo's side of the estate.
BRAVO = {
    "ip": "10.66.6.6",
    "hostname": "bravo-secret-host",
    "cve": "CVE-2099-6666",
    "team": "BravoTeam",
    "fix": "nessus:990666",
    "fix_title": "Bravo secret fix",
    "scan": "bravo-scan.nessus",
    "figure": "4711",
}
ALPHA = {
    "ip": "10.1.1.1",
    "hostname": "alpha-host",
    "cve": "CVE-2099-1111",
    "team": "Alpha",
}


def _finding(side, fix):
    return {
        "ip_address": side["ip"],
        "hostname": side["hostname"],
        "operating_system": "Windows Server 2019",
        "cve_id": side["cve"],
        "title": f"Finding on {side['hostname']}",
        "description": None,
        "cvss_score": 8.0,
        "severity": "High",
        "remediations": [fix],
    }


@pytest.fixture
def estate(db_session, admin_user):
    """Alpha's host and Bravo's, each with its CVE, fix, ticket and figures."""
    db_session.add(Asset(ip_address=ALPHA["ip"], owner_team=ALPHA["team"]))
    db_session.add(Asset(ip_address=BRAVO["ip"], owner_team=BRAVO["team"]))
    db_session.commit()
    ingest_findings(
        db_session,
        [
            _finding(ALPHA, remediation("kb", "KB5000001", title="Alpha rollup")),
            _finding(
                BRAVO,
                remediation("vendor_fix", BRAVO["fix"], title=BRAVO["fix_title"]),
            ),
        ],
        "nessus",
        scanned_addresses={ALPHA["ip"], BRAVO["ip"]},
    )
    for action in db_session.query(RemediationAction):
        create_tickets(db_session, action, admin_user, EVERYTHING)
    yesterday = datetime.now(UTC).date() - timedelta(days=1)
    for team, figure in ((ALPHA["team"], 11), (BRAVO["team"], int(BRAVO["figure"]))):
        db_session.add(
            BacklogSnapshot(
                day=yesterday,
                owner_team=team,
                open_findings=figure,
                open_high=figure,
                open_kev=0,
                overdue=0,
                open_risk=float(figure),
                new_findings=figure,
                fixed=0,
                fixed_on_time=0,
                fixed_days_total=0.0,
                fixed_risk=0.0,
            )
        )
    db_session.add(
        ScanJob(
            scan_type="nessus",
            filename=BRAVO["scan"],
            uploaded_by=admin_user.id,
            status=ScanStatus.success,
            task_id="bravo-task",
        )
    )
    db_session.commit()

    bravo_asset = db_session.query(Asset).filter_by(ip_address=BRAVO["ip"]).one()
    bravo_finding = (
        db_session.query(AssetVulnerability).filter_by(asset_id=bravo_asset.id).one()
    )
    return {
        "asset_id": bravo_asset.id,
        "finding_id": bravo_finding.id,
        "vulnerability_id": bravo_finding.vulnerability_id,
        "action_id": db_session.query(RemediationAction)
        .filter_by(reference=BRAVO["fix"])
        .one()
        .id,
        "ticket_id": db_session.query(RemediationTicket)
        .filter_by(owner_team=BRAVO["team"])
        .one()
        .id,
        "task_id": "bravo-task",
    }


@pytest.fixture
def scoped(client, db_session):
    """Sign the client in as an analyst limited to team Alpha."""
    user = _make_user(db_session, "alpha-analyst", "analyst")
    db_session.add(UserTeam(user_id=user.id, owner_team=ALPHA["team"]))
    db_session.commit()
    app.dependency_overrides.pop(require_admin, None)
    app.dependency_overrides[decode_token] = lambda: {
        "sub": str(user.id),
        "role": "analyst",
        "username": user.username,
    }
    return user


def _get_routes():
    # Recomputed, and limited to the API: other tests mount throwaway routes
    # (one that raises on purpose) on the same application.
    app.openapi_schema = None
    return sorted(
        path
        for path, operations in app.openapi()["paths"].items()
        if "get" in operations and path.startswith(settings.API_V1_STR)
    )


# Required query parameters, and routes a path parameter fans out to.
QUERY = {
    "/api/v1/categorization/findings": {"category": "__none__", "value": "server"},
}


def _calls(path, ids, saved_id):
    if path == "/api/v1/extracts/{dataset_key}":
        return [f"/api/v1/extracts/{key}" for key in DATASETS]
    values = {**ids, "saved_id": saved_id}
    return [re.sub(r"\{(\w+)\}", lambda m: str(values[m.group(1)]), path)]


def test_a_scoped_user_sees_nothing_of_another_team(client, db_session, estate, scoped):
    saved = SavedExtract(
        user_id=scoped.id,
        name="mine",
        dataset="findings",
        columns=[],
        filters={},
        format="csv",
    )
    db_session.add(saved)
    db_session.commit()

    swept = []
    for path in _get_routes():
        for url in _calls(path, estate, saved.id):
            response = client.get(url, params=QUERY.get(path))
            body = response.text
            leaked = [name for name, marker in BRAVO.items() if marker in body]
            assert not leaked, f"GET {url} ({response.status_code}) shows {leaked}"
            swept.append((url, response.status_code))

    # Not a vacuous pass: the routes answered, and Alpha's data is there.
    assert len(swept) >= 30
    assert ALPHA["hostname"] in client.get("/api/v1/vulnerabilities/findings").text


def test_bravo_objects_are_not_found_by_id(client, estate, scoped):
    for url in (
        f"/api/v1/assets/{estate['asset_id']}",
        f"/api/v1/vulnerabilities/findings/{estate['finding_id']}/history",
        f"/api/v1/remediation/tickets/{estate['ticket_id']}",
        f"/api/v1/remediation/actions/{estate['action_id']}",
    ):
        assert client.get(url).status_code == 404, url


def test_nor_changed(client, estate, scoped):
    assert (
        client.patch(
            f"/api/v1/vulnerabilities/findings/{estate['finding_id']}",
            json={"status": "Remediated", "status_note": "not mine"},
        ).status_code
        == 404
    )
    assert (
        client.put(
            f"/api/v1/assets/{estate['asset_id']}", json={"hostname": "x"}
        ).status_code
        == 404
    )
    assert client.delete(f"/api/v1/assets/{estate['asset_id']}").status_code in (403, 404)
    assert (
        client.patch(
            f"/api/v1/remediation/tickets/{estate['ticket_id']}",
            json={"status": "in_progress"},
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"/api/v1/remediation/actions/{estate['action_id']}/tickets"
        ).status_code
        == 404
    )


def test_a_host_cannot_be_moved_out_of_scope(client, db_session, estate, scoped):
    alpha = db_session.query(Asset).filter_by(ip_address=ALPHA["ip"]).one()

    response = client.put(
        f"/api/v1/assets/{alpha.id}", json={"owner_team": BRAVO["team"]}
    )

    assert response.status_code == 403
    created = client.post(
        "/api/v1/assets/", json={"ip_address": "10.1.1.2", "owner_team": BRAVO["team"]}
    )
    assert created.status_code == 403


@pytest.mark.parametrize(
    ("method", "url", "payload"),
    [
        (
            "post",
            "/api/v1/vulnerabilities/",
            {
                "cve_id": "CVE-2099-0001",
                "title": "x",
                "cvss_score": 5.0,
                "severity": "Medium",
            },
        ),
        ("put", "/api/v1/vulnerabilities/{vulnerability_id}", {"cvss_score": 1.0}),
        ("delete", "/api/v1/vulnerabilities/{vulnerability_id}", None),
    ],
)
def test_global_actions_are_refused(client, estate, scoped, method, url, payload):
    """Editing the CVE catalogue moves every team's risk."""
    url = url.format(**estate)
    kwargs = {"json": payload} if payload is not None else {}
    assert getattr(client, method)(url, **kwargs).status_code == 403


def test_a_scoped_user_cannot_upload_a_scan(client, estate, scoped):
    """Its ingestion would create hosts and close findings wherever it covers."""
    response = client.post(
        "/api/v1/scans/upload",
        data={"scan_type": "nessus"},
        files={"file": ("x.nessus", b"<NessusClientData_v2/>", "application/xml")},
    )
    assert response.status_code == 403


class TestScopeOf:
    def test_an_account_without_teams_sees_everything(self, db_session):
        user = _make_user(db_session, "free", "analyst")
        assert scope_of(db_session, user) is EVERYTHING

    def test_an_administrator_is_never_scoped(self, db_session):
        admin = _make_user(db_session, "boss", "admin")
        db_session.add(UserTeam(user_id=admin.id, owner_team="Alpha"))
        db_session.commit()
        assert scope_of(db_session, admin) is EVERYTHING

    def test_teams_make_the_scope(self, db_session):
        user = _make_user(db_session, "scoped", "remediator")
        db_session.add_all(
            [UserTeam(user_id=user.id, owner_team=t) for t in ("Alpha", NO_TEAM)]
        )
        db_session.commit()
        scope = scope_of(db_session, user)
        assert scope.teams == {"Alpha", NO_TEAM}
        assert scope.allows("Alpha") and scope.allows(None) and not scope.allows("Bravo")

    def test_hosts_without_a_team_only_when_asked(self, db_session):
        db_session.add_all(
            [
                Asset(ip_address="10.9.0.1", owner_team="Alpha"),
                Asset(ip_address="10.9.0.2"),
            ]
        )
        db_session.commit()

        def ips(scope):
            return {a.ip_address for a in scope.filter(db_session.query(Asset))}

        assert ips(Scope(frozenset({"Alpha"}))) == {"10.9.0.1"}
        assert ips(Scope(frozenset({"Alpha", NO_TEAM}))) == {"10.9.0.1", "10.9.0.2"}
        assert ips(Scope(frozenset())) == set()


def test_the_scope_follows_vulnerabilities_by_their_findings(
    client, db_session, estate, scoped
):
    """The CVE catalogue shows a scoped user the CVEs found on their hosts."""
    body = client.get("/api/v1/vulnerabilities/").text
    assert ALPHA["cve"] in body
    assert db_session.query(Vulnerability).filter_by(cve_id=BRAVO["cve"]).count() == 1


class TestAssigningTeams:
    """An administrator sets the scope; the user sees it in /me/modules."""

    def test_an_administrator_scopes_an_account(self, client, db_session):
        user = _make_user(db_session, "to-scope", "analyst")

        response = client.put(
            f"/api/v1/users/{user.id}/teams",
            json={"teams": ["Alpha", "__none__", "Alpha"]},
        )

        assert response.status_code == 200, response.text
        assert response.json()["teams"] == ["__none__", "Alpha"]
        rows = {
            row.owner_team
            for row in db_session.query(UserTeam).filter_by(user_id=user.id)
        }
        assert rows == {"Alpha", NO_TEAM}

    def test_an_empty_list_gives_back_the_whole_estate(self, client, db_session):
        user = _make_user(db_session, "unscope", "analyst")
        client.put(f"/api/v1/users/{user.id}/teams", json={"teams": ["Alpha"]})

        response = client.put(f"/api/v1/users/{user.id}/teams", json={"teams": []})

        assert response.json()["teams"] == []
        assert scope_of(db_session, user) is EVERYTHING

    def test_changing_a_scope_keeps_the_teams_still_wanted(self, client, db_session):
        user = _make_user(db_session, "rescope", "analyst")
        client.put(f"/api/v1/users/{user.id}/teams", json={"teams": ["Alpha", "Bravo"]})

        response = client.put(
            f"/api/v1/users/{user.id}/teams", json={"teams": ["Bravo", "Charlie"]}
        )

        assert response.json()["teams"] == ["Bravo", "Charlie"]

    def test_an_administrator_cannot_be_scoped(self, client, db_session):
        admin = _make_user(db_session, "other-admin", "admin")

        response = client.put(
            f"/api/v1/users/{admin.id}/teams", json={"teams": ["Alpha"]}
        )

        assert response.status_code == 422

    def test_promotion_drops_the_scope(self, client, db_session):
        user = _make_user(db_session, "promoted", "analyst")
        client.put(f"/api/v1/users/{user.id}/teams", json={"teams": ["Alpha"]})

        client.patch(f"/api/v1/users/{user.id}/role", json={"role": "admin"})

        assert db_session.query(UserTeam).filter_by(user_id=user.id).count() == 0

    def test_only_an_administrator_sets_scopes(self, client, db_session, scoped):
        response = client.put(f"/api/v1/users/{scoped.id}/teams", json={"teams": []})

        assert response.status_code == 403

    def test_the_user_sees_their_scope(self, client, scoped):
        assert client.get("/api/v1/me/modules").json()["teams"] == ["Alpha"]

    def test_an_unscoped_user_sees_none(self, client):
        assert client.get("/api/v1/me/modules").json()["teams"] is None
