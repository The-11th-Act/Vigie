"""Le driver PostgreSQL doit être explicite dans toute URL passée à SQLAlchemy.

SQLAlchemy 2.1 a changé le driver par défaut d'une URL ``postgresql://`` :
psycopg2 → psycopg 3. Seul psycopg2 est installé, donc une URL nue fait
échouer l'API, le worker et Alembic dès l'import avec ``No module named
'psycopg'``. Sur SQLite, la suite ne le voit pas : ce test, si.
"""

import pytest

from app.core.config import sqlalchemy_url


@pytest.mark.parametrize(
    "url",
    [
        "postgresql://user:pass@db:5432/vigie",
        "postgres://user:pass@db:5432/vigie",
    ],
)
def test_bare_postgres_url_gets_the_installed_driver(url):
    assert sqlalchemy_url(url) == "postgresql+psycopg2://user:pass@db:5432/vigie"


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+psycopg2://user:pass@db:5432/vigie",
        "postgresql+asyncpg://user:pass@db:5432/vigie",
        "sqlite:///./test.db",
    ],
)
def test_explicit_driver_or_other_database_is_left_alone(url):
    assert sqlalchemy_url(url) == url


def test_the_driver_it_names_is_importable():
    """Le préfixe ne sert à rien s'il désigne un driver absent de l'image."""
    from sqlalchemy.dialects import registry

    registry.load("postgresql.psycopg2").import_dbapi()
