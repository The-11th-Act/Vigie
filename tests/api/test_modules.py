"""Modules: who sees which section, and the server refusing the others."""

import pytest

from app.core.modules import MODULES, ROLES
from app.core.security import decode_token, require_admin
from app.main import app
from app.models.asset import Asset
from app.models.vulnerability import AssetVulnerability, Status, Vulnerability
from app.schemas.user import VALID_ROLES
from tests.conftest import _make_user

ALL_MODULES = [module.key for module in MODULES]
ANALYST_MODULES = [
    "dashboard",
    "backlog",
    "remediation",
    "categorization",
    "assets",
    "vulnerabilities",
    "scans",
    "extracts",
]


@pytest.fixture
def act_as(client, db_session):
    """Switch the test client to a new user of ``role``, checked for real.

    require_admin is no longer bypassed: like require_module, it must read the
    role from the database.
    """

    def switch(role, username=None):
        user = _make_user(db_session, username or f"a-{role}", role)
        app.dependency_overrides.pop(require_admin, None)
        app.dependency_overrides[decode_token] = lambda: {
            "sub": str(user.id),
            "role": role,
            "username": user.username,
        }
        return user

    return switch


def keys(response):
    assert response.status_code == 200, response.text
    return [module["key"] for module in response.json()["modules"]]


def my_modules(client):
    return keys(client.get("/api/v1/me/modules"))


@pytest.fixture
def finding(db_session):
    asset = Asset(ip_address="10.70.0.1")
    vuln = Vulnerability(
        cve_id="CVE-2024-7700", title="Fix me", cvss_score=8.0, severity="High"
    )
    db_session.add_all([asset, vuln])
    db_session.flush()
    link = AssetVulnerability(
        asset_id=asset.id, vulnerability_id=vuln.id, status=Status.open, risk_score=8.0
    )
    db_session.add(link)
    db_session.commit()
    return link


class TestDefaults:
    def test_an_administrator_has_every_module(self, client):
        assert my_modules(client) == ALL_MODULES

    def test_an_analyst_has_everything_but_administration(self, client, act_as):
        act_as("analyst")
        assert my_modules(client) == ANALYST_MODULES

    def test_a_remediator_has_a_short_list(self, client, act_as):
        act_as("remediator")
        assert my_modules(client) == [
            "remediation",
            "dashboard",
            "backlog",
            "assets",
            "extracts",
        ]

    def test_a_module_outside_the_role_is_refused_by_the_server(self, client, act_as):
        """Hiding the tab is not enough: the API behind it must say no."""
        act_as("remediator")
        assert client.get("/api/v1/scans/").status_code == 403
        assert client.get("/api/v1/vulnerabilities/").status_code == 403
        assert client.get("/api/v1/assets/").status_code == 200

    def test_the_roles_accepted_by_the_api_are_the_known_ones(self):
        assert VALID_ROLES == set(ROLES)

    def test_signed_out_there_are_no_modules(self, unauthenticated_client):
        assert unauthenticated_client.get("/api/v1/me/modules").status_code == 401


class TestInstanceSwitches:
    def test_a_disabled_module_disappears_and_is_refused(self, client, act_as):
        response = client.patch("/api/v1/admin/modules/scans", json={"enabled": False})
        assert response.status_code == 200
        assert {m["key"]: m["enabled"] for m in response.json()["modules"]}[
            "scans"
        ] is False

        act_as("analyst")
        assert "scans" not in my_modules(client)
        assert client.get("/api/v1/scans/").status_code == 403

    def test_it_comes_back_when_enabled_again(self, client, act_as):
        client.patch("/api/v1/admin/modules/scans", json={"enabled": False})
        client.patch("/api/v1/admin/modules/scans", json={"enabled": True})

        act_as("analyst")
        assert client.get("/api/v1/scans/").status_code == 200

    def test_administration_cannot_be_switched_off(self, client):
        response = client.patch("/api/v1/admin/modules/admin", json={"enabled": False})
        assert response.status_code == 422

    def test_an_unknown_module_is_404(self, client):
        response = client.patch("/api/v1/admin/modules/nope", json={"enabled": False})
        assert response.status_code == 404

    def test_only_an_administrator_manages_modules(self, client, act_as):
        act_as("analyst")
        assert client.get("/api/v1/admin/modules").status_code == 403
        response = client.patch("/api/v1/admin/modules/scans", json={"enabled": False})
        assert response.status_code == 403


class TestRoleProfiles:
    def test_a_profile_sets_the_modules_and_their_order(self, client, act_as):
        response = client.put(
            "/api/v1/admin/roles/analyst/modules",
            json={"modules": ["backlog", "dashboard"]},
        )
        assert response.status_code == 200
        assert response.json()["profiles"]["analyst"] == ["backlog", "dashboard"]
        assert response.json()["customized"] == ["analyst"]

        act_as("analyst")
        assert my_modules(client) == ["backlog", "dashboard"]
        assert client.get("/api/v1/assets/").status_code == 403

    def test_administration_is_reserved_to_administrators(self, client):
        response = client.put(
            "/api/v1/admin/roles/remediator/modules", json={"modules": ["admin"]}
        )
        assert response.status_code == 422

    def test_administrators_keep_administration_whatever_their_profile(self, client):
        response = client.put(
            "/api/v1/admin/roles/admin/modules", json={"modules": ["dashboard"]}
        )
        assert response.json()["profiles"]["admin"] == ["dashboard", "admin"]
        assert my_modules(client) == ["dashboard", "admin"]

    def test_a_reset_returns_to_the_default(self, client, act_as):
        client.put("/api/v1/admin/roles/analyst/modules", json={"modules": ["backlog"]})
        response = client.delete("/api/v1/admin/roles/analyst/modules")
        assert response.json()["customized"] == []

        act_as("analyst")
        assert my_modules(client) == ANALYST_MODULES

    @pytest.mark.parametrize(
        "body",
        [{"modules": ["nope"]}, {"modules": ["backlog", "backlog"]}],
    )
    def test_invalid_profiles_are_rejected(self, client, body):
        response = client.put("/api/v1/admin/roles/analyst/modules", json=body)
        assert response.status_code == 422

    def test_an_unknown_role_is_404(self, client):
        response = client.put("/api/v1/admin/roles/nobody/modules", json={"modules": []})
        assert response.status_code == 404


class TestPreferences:
    def test_a_user_reorders_and_hides_their_modules(self, client, act_as):
        act_as("analyst")
        response = client.put(
            "/api/v1/me/preferences",
            json={"order": ["backlog", "scans"], "hidden": ["vulnerabilities"]},
        )

        modules = response.json()["modules"]
        # Placed ones first, the others in their profile order after them.
        assert [m["key"] for m in modules] == [
            "backlog",
            "scans",
            "dashboard",
            "remediation",
            "categorization",
            "assets",
            "vulnerabilities",
            "extracts",
        ]
        assert [m["key"] for m in modules if m["hidden"]] == ["vulnerabilities"]

    def test_hiding_is_not_forbidding(self, client, act_as):
        act_as("analyst")
        client.put("/api/v1/me/preferences", json={"hidden": ["vulnerabilities"]})
        assert client.get("/api/v1/vulnerabilities/").status_code == 200

    def test_a_preference_grants_nothing(self, client, act_as):
        act_as("remediator")
        response = client.put("/api/v1/me/preferences", json={"order": ["scans"]})

        assert response.status_code == 200
        assert "scans" not in keys(response)
        assert client.get("/api/v1/scans/").status_code == 403

    def test_unknown_modules_are_rejected(self, client):
        response = client.put("/api/v1/me/preferences", json={"hidden": ["nope"]})
        assert response.status_code == 422

    def test_preferences_are_per_user(self, client, act_as):
        act_as("analyst", "first")
        client.put("/api/v1/me/preferences", json={"hidden": ["scans"]})
        act_as("analyst", "second")

        hidden = [
            m for m in client.get("/api/v1/me/modules").json()["modules"] if m["hidden"]
        ]
        assert hidden == []


class TestRemediator:
    def test_can_mark_a_finding_remediated(self, client, act_as, finding):
        act_as("remediator")
        response = client.patch(
            f"/api/v1/vulnerabilities/findings/{finding.id}",
            json={"status": "Remediated"},
        )
        assert response.status_code == 200

    @pytest.mark.parametrize("status", ["Risk Accepted", "False Positive"])
    def test_cannot_decide_a_risk(self, client, act_as, finding, db_session, status):
        act_as("remediator")
        response = client.patch(
            f"/api/v1/vulnerabilities/findings/{finding.id}",
            json={"status": status, "status_note": "Not ours to fix."},
        )

        assert response.status_code == 403
        db_session.refresh(finding)
        assert finding.status == Status.open

    def test_cannot_change_what_an_asset_weighs(self, client, act_as, finding):
        act_as("remediator")
        response = client.put(
            f"/api/v1/assets/{finding.asset_id}", json={"business_criticality": "Low"}
        )
        assert response.status_code == 403

    def test_an_analyst_still_can(self, client, act_as, finding):
        act_as("analyst")
        response = client.patch(
            f"/api/v1/vulnerabilities/findings/{finding.id}",
            json={"status": "Risk Accepted", "status_note": "Compensating control."},
        )
        assert response.status_code == 200


class TestUsers:
    def test_an_administrator_lists_accounts(self, client, other_user):
        response = client.get("/api/v1/users/")
        assert response.status_code == 200
        assert "someone-else" in [user["username"] for user in response.json()]

    def test_an_analyst_cannot(self, client, act_as):
        act_as("analyst")
        assert client.get("/api/v1/users/").status_code == 403

    def test_a_remediator_can_be_named(self, client, other_user):
        response = client.patch(
            f"/api/v1/users/{other_user.id}/role", json={"role": "remediator"}
        )
        assert response.json()["role"] == "remediator"

    def test_the_last_administrator_cannot_be_demoted(self, client, admin_user):
        response = client.patch(
            f"/api/v1/users/{admin_user.id}/role", json={"role": "analyst"}
        )
        assert response.status_code == 409

    def test_with_another_administrator_it_can(self, client, admin_user, db_session):
        _make_user(db_session, "second-admin", "admin")
        response = client.patch(
            f"/api/v1/users/{admin_user.id}/role", json={"role": "analyst"}
        )
        assert response.status_code == 200
