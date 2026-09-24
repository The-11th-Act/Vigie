"""Configuration de la suite de tests.

La base de test est choisie par ``VIGIE_TEST_DATABASE_URL``. Par défaut,
SQLite : rapide, sans service externe, suffisant pour la logique métier. En
CI, la suite API est rejouée sur un vrai PostgreSQL, parce que SQLite ne dit
rien des ENUM natifs, des ``ON DELETE CASCADE`` ni des collations — et que la
production, elle, tourne sur PostgreSQL.
"""

import os

# Doit être défini avant tout import de app.core.config / app.db.database, qui
# construisent le moteur au moment de l'import. Sans cela, la collecte des
# tests tenterait de joindre une vraie instance PostgreSQL.
TEST_DATABASE_URL = os.environ.get("VIGIE_TEST_DATABASE_URL", "sqlite:///./test.db")

os.environ.setdefault("DATABASE_URL", TEST_DATABASE_URL)
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-used-in-production-0123456789")
os.environ.setdefault("ENVIRONMENT", "development")
# Most tests drive the login endpoint well past the lockout threshold on
# purpose; the throttle is exercised explicitly in tests/test_ratelimit.py.
os.environ.setdefault("RATE_LIMIT_ENABLED", "false")

import pytest  # noqa: E402
from sqlalchemy import create_engine, event  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.core.config import settings, sqlalchemy_url  # noqa: E402
from app.db.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402

# Satisfait la politique de mot de passe à l'inscription (>= 12 caractères,
# au moins une lettre et un chiffre).
VALID_PASSWORD = "testpass123456"

IS_SQLITE = TEST_DATABASE_URL.startswith("sqlite")


@pytest.fixture(autouse=True)
def scan_upload_dir(tmp_path, monkeypatch):
    """Stage scan uploads in a throwaway directory rather than the real volume."""
    monkeypatch.setattr(settings, "SCAN_UPLOAD_DIR", str(tmp_path / "scans"))
    return tmp_path / "scans"


@pytest.fixture(autouse=True)
def isolated_key_value_store():
    """Give every test a clean throttle/revocation store, never a real Redis."""
    from app.core.keyvalue import InMemoryStore, reset_store

    store = InMemoryStore()
    reset_store(store)
    yield store
    reset_store(None)


@pytest.fixture(scope="session")
def db_engine():
    # check_same_thread ne concerne que SQLite ; le passer à PostgreSQL lève
    # une erreur de connexion.
    connect_args = {"check_same_thread": False} if IS_SQLITE else {}
    engine = create_engine(sqlalchemy_url(TEST_DATABASE_URL), connect_args=connect_args)

    if IS_SQLITE:
        # SQLite ignore les clés étrangères par défaut, PostgreSQL non. Sans
        # cette ligne, un test qui référence un utilisateur inexistant passe
        # en local et n'échoue qu'en CI, sur la suite PostgreSQL.
        @event.listens_for(engine, "connect")
        def _enforce_foreign_keys(dbapi_connection, _record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    # Repart d'un schéma vierge : un run précédent interrompu laisse sinon des
    # tables (et des types ENUM) qui font échouer la création.
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def db_session(db_engine):
    connection = db_engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(bind=connection)
    session = Session()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


def _make_user(db_session, username, role):
    from app.core.security import get_password_hash
    from app.models.user import User

    user = User(
        email=f"{username}@test.com",
        username=username,
        hashed_password=get_password_hash(VALID_PASSWORD),
        role=role,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="function")
def admin_user(db_session):
    """L'administrateur que le client de test incarne, réellement en base.

    L'identité simulée doit désigner une ligne existante : sur PostgreSQL, les
    clés étrangères (``scan_jobs.uploaded_by``…) sont appliquées, et les
    séquences ne reculent pas avec le rollback, donc aucun id n'est prévisible.

    Un premier compte est créé avant lui : sur SQLite, l'admin aurait sinon
    toujours l'id 1, et un test qui le suppose passerait en local pour
    n'échouer que sur PostgreSQL. Il est conservé, car SQLite réattribuerait
    l'id d'un compte supprimé.
    """
    _make_user(db_session, "placeholder", "analyst")
    return _make_user(db_session, "admin", "admin")


@pytest.fixture(scope="function")
def other_user(db_session):
    """Un second compte, propriétaire de ressources que l'admin ne possède pas."""
    return _make_user(db_session, "someone-else", "analyst")


@pytest.fixture(scope="function")
def client(db_session, admin_user):
    from fastapi.testclient import TestClient

    from app.core.security import decode_token, require_admin

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    identity = {"sub": str(admin_user.id), "role": "admin", "username": "admin"}

    def override_auth():
        return identity

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[decode_token] = override_auth
    app.dependency_overrides[require_admin] = override_auth
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def unauthenticated_client(db_session):
    """Client with the auth dependency left in place, for access-control tests."""
    from fastapi.testclient import TestClient

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def auth_token(client, admin_user):
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": VALID_PASSWORD},
    )
    return response.json()["access_token"]


@pytest.fixture(scope="function")
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}
