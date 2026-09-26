import pytest

from app.core.config import settings
from app.core.security import get_password_hash
from app.models.user import User
from tests.conftest import VALID_PASSWORD


@pytest.fixture
def registered_user(db_session):
    user = User(
        email="session@test.com",
        username="sessionuser",
        hashed_password=get_password_hash(VALID_PASSWORD),
        role="analyst",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def login(client, username="sessionuser", password=VALID_PASSWORD):
    return client.post(
        "/api/v1/auth/login", json={"username": username, "password": password}
    )


class TestAuth:
    def test_register_user(self, client):
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@test.com",
                "username": "newuser",
                "password": VALID_PASSWORD,
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == "newuser"
        assert data["role"] == "analyst"
        assert "hashed_password" not in data

    def test_register_cannot_self_assign_admin(self, client):
        """The role in the request body must be ignored."""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "wannabe@test.com",
                "username": "wannabe",
                "password": VALID_PASSWORD,
                "role": "admin",
            },
        )
        assert response.status_code == 201
        assert response.json()["role"] == "analyst"

    @pytest.mark.parametrize(
        "password",
        [
            "short1",  # below the minimum length
            "nodigitsatall",  # missing a digit
            "1234567890123",  # missing a letter
        ],
    )
    def test_register_rejects_weak_password(self, client, password):
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "weak@test.com",
                "username": "weakuser",
                "password": password,
            },
        )
        assert response.status_code == 422

    def test_register_duplicate_username(self, client, db_session):
        from app.core.security import get_password_hash
        from app.models.user import User

        db_session.add(
            User(
                email="existing@test.com",
                username="existing",
                hashed_password=get_password_hash(VALID_PASSWORD),
            )
        )
        db_session.commit()

        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "other@test.com",
                "username": "existing",
                "password": VALID_PASSWORD,
            },
        )
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"]

    def test_login_success(self, client, auth_token):
        assert auth_token is not None

    def test_login_wrong_password(self, client, db_session):
        from app.core.security import get_password_hash
        from app.models.user import User

        db_session.add(
            User(
                email="login@test.com",
                username="loginuser",
                hashed_password=get_password_hash("correctpass123"),
            )
        )
        db_session.commit()

        response = client.post(
            "/api/v1/auth/login",
            json={"username": "loginuser", "password": "wrongpass123"},
        )
        assert response.status_code == 401

    def test_login_unknown_user_gives_same_error(self, client):
        """No user enumeration: unknown user and wrong password look identical."""
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "ghost", "password": "whatever12345"},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Incorrect username or password"

    def test_get_current_user(self, client, auth_headers):
        response = client.get("/api/v1/auth/me", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["username"] == "admin"


class TestLoginThrottling:
    @pytest.fixture(autouse=True)
    def throttle_enabled(self, monkeypatch):
        monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
        monkeypatch.setattr(settings, "LOGIN_MAX_ATTEMPTS", 3)

    def test_repeated_failures_are_locked_out(
        self, unauthenticated_client, registered_user
    ):
        for _ in range(settings.LOGIN_MAX_ATTEMPTS):
            assert (
                login(unauthenticated_client, password="wrongpass12345").status_code
                == 401
            )

        response = login(unauthenticated_client, password="wrongpass12345")
        assert response.status_code == 429
        assert "Retry-After" in response.headers

    def test_lockout_blocks_the_correct_password_too(
        self, unauthenticated_client, registered_user
    ):
        """Otherwise an attacker who guesses right on attempt N+1 still wins."""
        for _ in range(settings.LOGIN_MAX_ATTEMPTS):
            login(unauthenticated_client, password="wrongpass12345")

        assert login(unauthenticated_client).status_code == 429

    def test_successful_login_clears_the_counter(
        self, unauthenticated_client, registered_user
    ):
        for _ in range(settings.LOGIN_MAX_ATTEMPTS - 1):
            login(unauthenticated_client, password="wrongpass12345")

        assert login(unauthenticated_client).status_code == 200

        # The earlier failures must not carry over into the next window.
        for _ in range(settings.LOGIN_MAX_ATTEMPTS - 1):
            assert (
                login(unauthenticated_client, password="wrongpass12345").status_code
                == 401
            )


class TestTokenLifecycle:
    def test_login_returns_both_tokens(self, unauthenticated_client, registered_user):
        body = login(unauthenticated_client).json()
        assert body["access_token"]
        assert body["refresh_token"]

    def test_refresh_issues_a_new_usable_access_token(
        self, unauthenticated_client, registered_user
    ):
        refresh_token = login(unauthenticated_client).json()["refresh_token"]

        response = unauthenticated_client.post(
            "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
        )
        assert response.status_code == 200

        new_access = response.json()["access_token"]
        me = unauthenticated_client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {new_access}"}
        )
        assert me.status_code == 200
        assert me.json()["username"] == "sessionuser"

    def test_refresh_token_is_single_use(self, unauthenticated_client, registered_user):
        """Rotation: replaying a captured refresh token must fail once the
        legitimate client has already used it."""
        refresh_token = login(unauthenticated_client).json()["refresh_token"]

        first = unauthenticated_client.post(
            "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
        )
        assert first.status_code == 200

        replay = unauthenticated_client.post(
            "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
        )
        assert replay.status_code == 401

    def test_access_token_cannot_be_used_to_refresh(
        self, unauthenticated_client, registered_user
    ):
        access_token = login(unauthenticated_client).json()["access_token"]

        response = unauthenticated_client.post(
            "/api/v1/auth/refresh", json={"refresh_token": access_token}
        )
        assert response.status_code == 401

    def test_logout_revokes_the_access_token(
        self, unauthenticated_client, registered_user
    ):
        body = login(unauthenticated_client).json()
        headers = {"Authorization": f"Bearer {body['access_token']}"}

        assert (
            unauthenticated_client.get("/api/v1/auth/me", headers=headers).status_code
            == 200
        )

        logout = unauthenticated_client.post(
            "/api/v1/auth/logout",
            headers=headers,
            json={"refresh_token": body["refresh_token"]},
        )
        assert logout.status_code == 204

        # Regression: clearing browser storage used to leave a token valid for
        # its full remaining lifetime.
        assert (
            unauthenticated_client.get("/api/v1/auth/me", headers=headers).status_code
            == 401
        )

    def test_logout_revokes_the_refresh_token(
        self, unauthenticated_client, registered_user
    ):
        body = login(unauthenticated_client).json()

        unauthenticated_client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {body['access_token']}"},
            json={"refresh_token": body["refresh_token"]},
        )

        response = unauthenticated_client.post(
            "/api/v1/auth/refresh", json={"refresh_token": body["refresh_token"]}
        )
        assert response.status_code == 401

    def test_logout_requires_authentication(self, unauthenticated_client):
        assert unauthenticated_client.post("/api/v1/auth/logout").status_code == 401


COOKIE_MODE = {"X-Session-Mode": "cookie"}


def cookie_login(client, username="admin"):
    response = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": VALID_PASSWORD},
        headers=COOKIE_MODE,
    )
    assert response.status_code == 200
    return response


def set_cookies(response) -> dict[str, str]:
    """Set-Cookie headers by cookie name, attributes lower-cased."""
    cookies = {}
    for header in response.headers.get_list("set-cookie"):
        name = header.split("=", 1)[0]
        cookies[name] = header.lower()
    return cookies


def csrf(client) -> dict[str, str]:
    return {"X-CSRF-Token": client.cookies.get("vigie_csrf")}


class TestBrowserSessions:
    """Tokens in localStorage were readable by any script injected into the page
    (T6). A browser client now asks for HttpOnly cookies instead."""

    def test_login_sets_the_cookies_and_keeps_tokens_out_of_the_body(
        self, unauthenticated_client, admin_user
    ):
        response = cookie_login(unauthenticated_client)

        body = response.json()
        assert "access_token" not in body and "refresh_token" not in body
        assert body["username"] == "admin"

        cookies = set_cookies(response)
        assert "httponly" in cookies["vigie_access"]
        assert "samesite=strict" in cookies["vigie_access"]
        assert "path=/api/v1" in cookies["vigie_access"]
        # The long-lived token only ever travels to the auth routes.
        assert "path=/api/v1/auth" in cookies["vigie_refresh"]
        assert "httponly" in cookies["vigie_refresh"]
        # The page must read the CSRF value to echo it in a header.
        assert "httponly" not in cookies["vigie_csrf"]

    def test_without_the_header_api_clients_are_unchanged(
        self, unauthenticated_client, admin_user
    ):
        response = unauthenticated_client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": VALID_PASSWORD}
        )
        assert response.json()["access_token"]
        assert not set_cookies(response)

    def test_the_cookie_authenticates_reads(self, unauthenticated_client, admin_user):
        cookie_login(unauthenticated_client)

        response = unauthenticated_client.get("/api/v1/auth/me")

        assert response.status_code == 200
        assert response.json()["username"] == "admin"

    def test_a_cookie_write_without_csrf_token_is_refused(
        self, unauthenticated_client, admin_user
    ):
        """The browser attaches cookies to a request another site triggers; the
        CSRF header is what that site cannot forge."""
        cookie_login(unauthenticated_client)

        response = unauthenticated_client.post(
            "/api/v1/assets/", json={"ip_address": "10.70.0.1"}
        )

        assert response.status_code == 403

    def test_a_wrong_csrf_token_is_refused(self, unauthenticated_client, admin_user):
        cookie_login(unauthenticated_client)

        response = unauthenticated_client.post(
            "/api/v1/assets/",
            json={"ip_address": "10.70.0.2"},
            headers={"X-CSRF-Token": "forged"},
        )

        assert response.status_code == 403

    def test_a_cookie_write_with_the_csrf_token_goes_through(
        self, unauthenticated_client, admin_user
    ):
        cookie_login(unauthenticated_client)

        response = unauthenticated_client.post(
            "/api/v1/assets/",
            json={"ip_address": "10.70.0.3"},
            headers=csrf(unauthenticated_client),
        )

        assert response.status_code == 201

    def test_a_bearer_write_needs_no_csrf_token(self, unauthenticated_client, admin_user):
        token = unauthenticated_client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": VALID_PASSWORD}
        ).json()["access_token"]

        response = unauthenticated_client.post(
            "/api/v1/assets/",
            json={"ip_address": "10.70.0.4"},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 201

    def test_refresh_rotates_the_cookies(self, unauthenticated_client, admin_user):
        cookie_login(unauthenticated_client)
        old_refresh = unauthenticated_client.cookies.get("vigie_refresh")

        response = unauthenticated_client.post(
            "/api/v1/auth/refresh", headers=csrf(unauthenticated_client)
        )

        assert response.status_code == 200
        assert "access_token" not in response.json()
        new_refresh = set_cookies(response)["vigie_refresh"]
        assert old_refresh.lower() not in new_refresh

        # The previous refresh token was revoked by the exchange.
        replay = unauthenticated_client.post(
            "/api/v1/auth/refresh", json={"refresh_token": old_refresh}
        )
        assert replay.status_code == 401

    def test_a_cookie_refresh_needs_the_csrf_token(
        self, unauthenticated_client, admin_user
    ):
        cookie_login(unauthenticated_client)

        assert unauthenticated_client.post("/api/v1/auth/refresh").status_code == 403

    def test_logout_revokes_and_clears_the_cookies(
        self, unauthenticated_client, admin_user
    ):
        cookie_login(unauthenticated_client)
        access = unauthenticated_client.cookies.get("vigie_access")
        refresh = unauthenticated_client.cookies.get("vigie_refresh")

        response = unauthenticated_client.post(
            "/api/v1/auth/logout", headers=csrf(unauthenticated_client)
        )

        assert response.status_code == 204
        cleared = set_cookies(response)
        assert {"vigie_access", "vigie_refresh", "vigie_csrf"} <= set(cleared)
        assert all("max-age=0" in header for header in cleared.values())
        # Both tokens are dead server-side, not merely forgotten by the browser.
        bearer = {"Authorization": f"Bearer {access}"}
        assert (
            unauthenticated_client.get("/api/v1/auth/me", headers=bearer).status_code
            == 401
        )
        replay = unauthenticated_client.post(
            "/api/v1/auth/refresh", json={"refresh_token": refresh}
        )
        assert replay.status_code == 401

    def test_cookies_are_secure_when_configured(
        self, unauthenticated_client, admin_user, monkeypatch
    ):
        monkeypatch.setattr(settings, "AUTH_COOKIE_SECURE", True)

        cookies = set_cookies(cookie_login(unauthenticated_client))

        assert all("secure" in header for header in cookies.values())
