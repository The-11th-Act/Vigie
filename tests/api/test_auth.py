class TestAuth:
    def test_register_user(self, client):
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@test.com",
                "username": "newuser",
                "password": "password123",
                "role": "analyst",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == "newuser"
        assert data["role"] == "analyst"
        assert "hashed_password" not in data

    def test_register_duplicate_username(self, client, db_session):
        from app.core.security import get_password_hash
        from app.models.user import User

        db_session.add(User(
            email="existing@test.com",
            username="existing",
            hashed_password=get_password_hash("pass123"),
        ))
        db_session.commit()

        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "other@test.com",
                "username": "existing",
                "password": "pass123",
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
            hashed_password=get_password_hash("correctpass"),
        ))
        db_session.commit()

        response = client.post(
            "/api/v1/auth/login",
            json={"username": "loginuser", "password": "wrongpass"},
        )
        assert response.status_code == 401

    def test_get_current_user(self, client, auth_headers):
        response = client.get("/api/v1/auth/me", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["username"] == "admin"