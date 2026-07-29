from app.core.bootstrap import bootstrap_admin_user
from app.core.config import settings
from app.core.security import get_password_hash
from app.models.user import User

ADMIN_PASSWORD = "adminpass123456"


class TestBootstrapAdmin:
    def test_noop_when_unconfigured(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "ADMIN_USERNAME", None)
        monkeypatch.setattr(settings, "ADMIN_EMAIL", None)
        monkeypatch.setattr(settings, "ADMIN_PASSWORD", None)

        bootstrap_admin_user(db_session)

        assert db_session.query(User).count() == 0

    def test_creates_admin_when_configured(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "ADMIN_USERNAME", "bootstrapadmin")
        monkeypatch.setattr(settings, "ADMIN_EMAIL", "bootstrap@test.com")
        monkeypatch.setattr(settings, "ADMIN_PASSWORD", ADMIN_PASSWORD)

        bootstrap_admin_user(db_session)

        user = db_session.query(User).filter(User.username == "bootstrapadmin").one()
        assert user.role == "admin"

    def test_promotes_existing_user_instead_of_duplicating(self, db_session, monkeypatch):
        db_session.add(
            User(
                email="existing@test.com",
                username="existinguser",
                hashed_password=get_password_hash(ADMIN_PASSWORD),
                role="analyst",
            )
        )
        db_session.commit()

        monkeypatch.setattr(settings, "ADMIN_USERNAME", "existinguser")
        monkeypatch.setattr(settings, "ADMIN_EMAIL", "existing@test.com")
        monkeypatch.setattr(settings, "ADMIN_PASSWORD", ADMIN_PASSWORD)

        bootstrap_admin_user(db_session)

        assert db_session.query(User).count() == 1
        user = db_session.query(User).filter(User.username == "existinguser").one()
        assert user.role == "admin"

    def test_idempotent_rerun_does_not_duplicate(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "ADMIN_USERNAME", "repeatadmin")
        monkeypatch.setattr(settings, "ADMIN_EMAIL", "repeat@test.com")
        monkeypatch.setattr(settings, "ADMIN_PASSWORD", ADMIN_PASSWORD)

        bootstrap_admin_user(db_session)
        bootstrap_admin_user(db_session)

        assert db_session.query(User).filter(User.username == "repeatadmin").count() == 1

    def test_invalid_credentials_are_skipped_without_raising(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "ADMIN_USERNAME", "bad")
        monkeypatch.setattr(settings, "ADMIN_EMAIL", "not-an-email")
        monkeypatch.setattr(settings, "ADMIN_PASSWORD", "short")

        bootstrap_admin_user(db_session)

        assert db_session.query(User).count() == 0
