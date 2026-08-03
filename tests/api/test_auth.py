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
            "short1",          # below the minimum length
            "nodigitsatall",   # missing a digit
            "1234567890123",   # missing a letter
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

        db_session.add(User(
            email="existing@test.com",
            username="existing",
            hashed_password=get_password_hash(VALID_PASSWORD),
        ))
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

        db_session.add(User(
            email="login@test.com",
            username="loginuser",
            hashed_password=get_password_hash("correctpass123"),
        ))
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
            assert login(unauthenticated_client, password="wrongpass12345").status_code == 401

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
            assert login(unauthenticated_client, password="wrongpass12345").status_code == 401


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

        assert unauthenticated_client.get("/api/v1/auth/me", headers=headers).status_code == 200

        logout = unauthenticated_client.post(
            "/api/v1/auth/logout",
            headers=headers,
            json={"refresh_token": body["refresh_token"]},
        )
        assert logout.status_code == 204

        # Regression: clearing browser storage used to leave a token valid for
        # its full remaining lifetime.
        assert unauthenticated_client.get("/api/v1/auth/me", headers=headers).status_code == 401

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
