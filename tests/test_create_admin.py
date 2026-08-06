"""Tests du script de creation d'administrateur.

Ce script est le chemin recommande en production pour obtenir le premier
admin : s'il est casse, une nouvelle installation n'a aucun moyen d'obtenir un
compte administrateur, puisque l'inscription cree toujours un `analyst`.
"""

import pytest

from app.models.user import User
from scripts.create_admin import create_admin, parse_args, read_password

VALID = "adminpass123456"


class TestArguments:
    def test_username_and_email_are_required(self):
        with pytest.raises(SystemExit):
            parse_args([])

    def test_parses_a_complete_invocation(self):
        args = parse_args(
            ["--username", "admin", "--email", "a@b.com", "--password-from-env"]
        )
        assert args.username == "admin"
        assert args.email == "a@b.com"
        assert args.password_from_env is True


class TestPasswordSource:
    def test_reads_the_environment_when_asked(self, monkeypatch):
        monkeypatch.setenv("ADMIN_PASSWORD", VALID)
        assert read_password(from_env=True) == VALID

    def test_refuses_an_empty_environment_password(self, monkeypatch):
        monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
        with pytest.raises(SystemExit):
            read_password(from_env=True)

    def test_never_accepts_the_password_as_an_argument(self):
        """Un mot de passe en argument finit dans l'historique du shell et dans
        la table des processus, lisible par tout utilisateur de la machine."""
        with pytest.raises(SystemExit):
            parse_args(["--username", "a", "--email", "a@b.com", "--password", VALID])


class TestCreateAdmin:
    @pytest.fixture(autouse=True)
    def _use_the_test_session(self, db_session, monkeypatch):
        # Le script ouvre sa propre session ; on la remplace par celle du test,
        # dont la transaction est annulee en fin de test.
        monkeypatch.setattr(
            "scripts.create_admin.SessionLocal", lambda: _NonClosing(db_session)
        )
        self.db = db_session

    def test_creates_a_new_admin(self):
        assert create_admin("admin", "admin@example.com", VALID) == 0

        user = self.db.query(User).filter(User.username == "admin").one()
        assert user.role == "admin"
        # Le mot de passe ne doit jamais etre stocke en clair.
        assert user.hashed_password != VALID
        assert VALID not in user.hashed_password

    def test_promotes_an_existing_analyst(self):
        from app.core.security import get_password_hash

        self.db.add(
            User(
                username="existing",
                email="existing@example.com",
                hashed_password=get_password_hash(VALID),
                role="analyst",
            )
        )
        self.db.commit()

        assert create_admin("existing", "existing@example.com", VALID) == 0
        user = self.db.query(User).filter(User.username == "existing").one()
        assert user.role == "admin"

    def test_is_idempotent(self):
        assert create_admin("admin", "admin@example.com", VALID) == 0
        assert create_admin("admin", "admin@example.com", VALID) == 0
        assert self.db.query(User).filter(User.username == "admin").count() == 1

    def test_rejects_a_weak_password(self):
        """La meme politique qu'a l'inscription : un compte administrateur ne
        doit pas etre le maillon faible."""
        assert create_admin("admin", "admin@example.com", "short") == 1
        assert self.db.query(User).filter(User.username == "admin").count() == 0

    def test_rejects_a_malformed_email(self):
        assert create_admin("admin", "not-an-email", VALID) == 1
        assert self.db.query(User).filter(User.username == "admin").count() == 0


class _NonClosing:
    """Enveloppe une session partagee pour que le `close()` du script ne ferme
    pas la session du test, qui doit survivre jusqu'aux assertions."""

    def __init__(self, session):
        self._session = session

    def __getattr__(self, name):
        return getattr(self._session, name)

    def close(self):
        pass
