"""Accounts: created by an administrator, disabled, reset, deleted, and each
user's own password change. With real authentication throughout: the
``client`` fixture bypasses it, which would hide what these tests check."""

from datetime import UTC, datetime, timedelta

import pytest

from app.core.api_tokens import new_token
from app.models.extract import ApiToken
from app.models.user import User
from tests.conftest import VALID_PASSWORD, _make_user

NEW_PASSWORD = "brand-new-passw0rd"


@pytest.fixture
def api(unauthenticated_client):
    return unauthenticated_client


def login(api, username, password=VALID_PASSWORD):
    return api.post(
        "/api/v1/auth/login", json={"username": username, "password": password}
    )


def bearer(api, username, password=VALID_PASSWORD):
    response = login(api, username, password)
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture
def admin(db_session, api):
    _make_user(db_session, "placeholder", "analyst")
    user = _make_user(db_session, "boss", "admin")
    return user, bearer(api, "boss")


@pytest.fixture
def alice(db_session):
    return _make_user(db_session, "alice", "analyst")


def create(api, headers, **fields):
    body = {
        "username": "newbie",
        "email": "newbie@test.com",
        "password": VALID_PASSWORD,
        **fields,
    }
    return api.post("/api/v1/users/", json=body, headers=headers)


class TestSelfRegistrationIsClosed:
    def test_there_is_no_way_to_open_an_account_alone(self, api):
        response = api.post(
            "/api/v1/auth/register",
            json={
                "email": "x@test.com",
                "username": "intruder",
                "password": VALID_PASSWORD,
            },
        )
        assert response.status_code in (404, 405)
        assert login(api, "intruder").status_code == 401


class TestCreation:
    def test_an_administrator_opens_an_account(self, api, admin):
        _, headers = admin

        response = create(api, headers, role="remediator", teams=["Servers"])

        assert response.status_code == 201, response.text
        body = response.json()
        assert (body["username"], body["role"], body["teams"]) == (
            "newbie",
            "remediator",
            ["Servers"],
        )
        assert body["is_active"] is True
        assert "hashed_password" not in body and "password" not in body
        # The initial password, handed over, works.
        assert login(api, "newbie").status_code == 200

    def test_an_analyst_by_default(self, api, admin):
        assert create(api, admin[1]).json()["role"] == "analyst"

    @pytest.mark.parametrize(
        "fields",
        [
            {"password": "short1"},
            {"password": "nodigitsatall"},
            {"password": "1234567890123"},
            {"role": "superuser"},
            {"username": "no spaces"},
            {"email": "not-an-email"},
            {"role": "admin", "teams": ["Servers"]},
        ],
    )
    def test_invalid_accounts_are_refused(self, api, admin, fields):
        assert create(api, admin[1], **fields).status_code == 422

    def test_a_taken_username_or_email(self, api, admin, alice):
        assert create(api, admin[1], username="alice").status_code == 409
        assert create(api, admin[1], email="ALICE@test.com").status_code == 409

    def test_administrators_only(self, api, admin, alice):
        assert create(api, bearer(api, "alice")).status_code == 403
        assert create(api, {}).status_code == 401


class TestDisabling:
    def test_a_disabled_account_is_out_at_once(self, api, admin, alice, db_session):
        alice_headers = bearer(api, "alice")
        refresh = login(api, "alice").json()["refresh_token"]
        _, secret = new_token(db_session, alice, "script", timedelta(days=30))
        db_session.commit()

        response = api.patch(
            f"/api/v1/users/{alice.id}/active", json={"active": False}, headers=admin[1]
        )

        assert response.status_code == 200
        assert response.json()["is_active"] is False
        # Its open session, its refresh token and its personal token all stop.
        assert api.get("/api/v1/auth/me", headers=alice_headers).status_code == 401
        assert (
            api.post("/api/v1/auth/refresh", json={"refresh_token": refresh}).status_code
            == 401
        )
        token_headers = {"Authorization": f"Bearer {secret}"}
        assert (
            api.get("/api/v1/extracts/datasets", headers=token_headers).status_code == 401
        )
        # The same answer as a wrong password.
        refused = login(api, "alice")
        assert refused.status_code == 401
        assert refused.json() == login(api, "alice", "wrong-password-1").json()

    def test_enabled_again(self, api, admin, alice):
        path = f"/api/v1/users/{alice.id}/active"
        api.patch(path, json={"active": False}, headers=admin[1])

        assert api.patch(path, json={"active": True}, headers=admin[1]).status_code == 200
        assert login(api, "alice").status_code == 200

    def test_not_oneself(self, api, admin):
        user, headers = admin
        response = api.patch(
            f"/api/v1/users/{user.id}/active", json={"active": False}, headers=headers
        )
        assert response.status_code == 409

    def test_not_the_last_active_administrator(self, api, admin, db_session):
        other = _make_user(db_session, "boss2", "admin")
        headers = bearer(api, "boss2")
        user, _ = admin
        # boss2 disables boss, then nobody may disable boss2... but boss2
        # cannot disable itself either, and boss is out: boss2 is the last.
        assert (
            api.patch(
                f"/api/v1/users/{user.id}/active", json={"active": False}, headers=headers
            ).status_code
            == 200
        )
        demoted = api.patch(
            f"/api/v1/users/{other.id}/role", json={"role": "analyst"}, headers=headers
        )
        assert demoted.status_code == 409
        assert "last active administrator" in demoted.json()["detail"]


class TestPasswordReset:
    def test_a_new_password_and_the_old_sessions_end(self, api, admin, alice):
        alice_headers = bearer(api, "alice")

        response = api.put(
            f"/api/v1/users/{alice.id}/password",
            json={"password": NEW_PASSWORD},
            headers=admin[1],
        )

        assert response.status_code == 204
        assert api.get("/api/v1/auth/me", headers=alice_headers).status_code == 401
        assert login(api, "alice").status_code == 401
        assert login(api, "alice", NEW_PASSWORD).status_code == 200

    def test_a_weak_one_is_refused(self, api, admin, alice):
        response = api.put(
            f"/api/v1/users/{alice.id}/password",
            json={"password": "weak"},
            headers=admin[1],
        )
        assert response.status_code == 422


class TestDeletion:
    def test_gone_with_what_was_only_theirs(self, api, admin, alice, db_session):
        new_token(db_session, alice, "script", timedelta(days=30))
        db_session.commit()

        response = api.delete(f"/api/v1/users/{alice.id}", headers=admin[1])

        assert response.status_code == 204
        db_session.expire_all()
        assert db_session.get(User, alice.id) is None
        assert db_session.query(ApiToken).count() == 0
        assert login(api, "alice").status_code == 401

    def test_not_oneself_nor_an_unknown_account(self, api, admin):
        user, headers = admin
        assert api.delete(f"/api/v1/users/{user.id}", headers=headers).status_code == 409
        assert api.delete("/api/v1/users/999999", headers=headers).status_code == 404


class TestChangingOnesPassword:
    def change(self, api, headers, current=VALID_PASSWORD, new=NEW_PASSWORD):
        return api.put(
            "/api/v1/me/password",
            json={"current_password": current, "new_password": new},
            headers=headers,
        )

    def test_with_the_current_one_as_proof(self, api, alice):
        headers = bearer(api, "alice")

        assert self.change(api, headers, current="not-my-password-1").status_code == 403
        assert self.change(api, headers, new="weak").status_code == 422
        assert self.change(api, headers).status_code == 204

        # Every session ends, this one included; the new password opens one.
        assert api.get("/api/v1/auth/me", headers=headers).status_code == 401
        assert login(api, "alice").status_code == 401
        fresh = bearer(api, "alice", NEW_PASSWORD)
        assert api.get("/api/v1/auth/me", headers=fresh).status_code == 200


class TestSessionsValidAfter:
    def test_a_token_from_before_is_refused_one_from_after_accepted(
        self, api, alice, db_session
    ):
        before = bearer(api, "alice")
        alice.sessions_valid_after = datetime.now(UTC)
        db_session.commit()
        after = bearer(api, "alice")

        assert api.get("/api/v1/auth/me", headers=before).status_code == 401
        assert api.get("/api/v1/auth/me", headers=after).status_code == 200
