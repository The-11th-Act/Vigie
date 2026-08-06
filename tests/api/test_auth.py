import pytest

from tests.conftest import VALID_PASSWORD


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
