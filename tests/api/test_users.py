from app.core.security import get_password_hash
from app.models.user import User
from tests.conftest import VALID_PASSWORD


def _create_analyst(db_session, username, email):
    user = User(
        email=email,
        username=username,
        hashed_password=get_password_hash(VALID_PASSWORD),
        role="analyst",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


class TestUserRoleUpdate:
    def test_promote_requires_admin(self, unauthenticated_client, db_session):
        analyst = _create_analyst(db_session, "analystuser", "analyst@test.com")

        login = unauthenticated_client.post(
            "/api/v1/auth/login",
            json={"username": "analystuser", "password": VALID_PASSWORD},
        )
        token = login.json()["access_token"]

        response = unauthenticated_client.patch(
            f"/api/v1/users/{analyst.id}/role",
            json={"role": "admin"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403

    def test_admin_can_promote_user(self, client, db_session):
        analyst = _create_analyst(db_session, "analystuser2", "analyst2@test.com")

        response = client.patch(
            f"/api/v1/users/{analyst.id}/role", json={"role": "admin"}
        )
        assert response.status_code == 200
        assert response.json()["role"] == "admin"

    def test_promote_nonexistent_user_404(self, client):
        response = client.patch("/api/v1/users/99999/role", json={"role": "admin"})
        assert response.status_code == 404

    def test_promote_invalid_role_422(self, client, db_session):
        analyst = _create_analyst(db_session, "analystuser3", "analyst3@test.com")

        response = client.patch(
            f"/api/v1/users/{analyst.id}/role", json={"role": "superuser"}
        )
        assert response.status_code == 422
