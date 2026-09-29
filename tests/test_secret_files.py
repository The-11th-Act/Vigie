"""Secrets read from files (NAME_FILE), and kept out of URLs in logs."""

import pytest

from app.core.config import Settings, redacted, with_password

KEY = "a-secret-key-read-from-a-file-0123456789abcdef"


def settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


def test_a_setting_comes_from_its_file(tmp_path, monkeypatch):
    path = tmp_path / "secret_key"
    path.write_text(KEY + "\n", encoding="utf-8")  # as `echo` writes it
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setenv("SECRET_KEY_FILE", str(path))

    assert Settings(_env_file=None).SECRET_KEY == KEY


def test_an_explicit_value_wins(tmp_path, monkeypatch):
    path = tmp_path / "secret_key"
    path.write_text(KEY, encoding="utf-8")
    monkeypatch.setenv("SECRET_KEY_FILE", str(path))

    other = "an-explicit-secret-key-set-directly-0123456789"
    assert settings(SECRET_KEY=other).SECRET_KEY == other


def test_an_empty_value_does_not_hide_the_file(tmp_path, monkeypatch):
    """Production blanks SECRET_KEY so that a leftover .env value cannot win."""
    path = tmp_path / "secret_key"
    path.write_text(KEY, encoding="utf-8")
    monkeypatch.setenv("SECRET_KEY", "")
    monkeypatch.setenv("SECRET_KEY_FILE", str(path))

    assert Settings(_env_file=None).SECRET_KEY == KEY


def test_an_unreadable_file_names_the_path_not_the_content(tmp_path, monkeypatch):
    missing = tmp_path / "nope"
    monkeypatch.setenv("REDIS_PASSWORD_FILE", str(missing))

    with pytest.raises(ValueError, match="REDIS_PASSWORD_FILE") as caught:
        Settings(_env_file=None)
    assert str(missing) in str(caught.value)


def test_retired_keys_come_as_json(tmp_path, monkeypatch):
    path = tmp_path / "previous"
    path.write_text('{"k0": "a-retired-secret-key-0123456789abcdefgh"}', encoding="utf-8")
    monkeypatch.setenv("PREVIOUS_SECRET_KEYS_FILE", str(path))

    assert Settings(_env_file=None).PREVIOUS_SECRET_KEYS == {
        "k0": "a-retired-secret-key-0123456789abcdefgh"
    }


class TestUrls:
    def test_the_password_goes_into_a_url_without_one(self):
        assert (
            with_password("postgresql://vigie@db:5432/vigie", "p@ss/word")
            == "postgresql://vigie:p%40ss%2Fword@db:5432/vigie"
        )
        assert (
            with_password("redis://redis:6379/0", "s3cret")
            == "redis://:s3cret@redis:6379/0"
        )

    def test_a_url_with_a_password_is_left_alone(self):
        url = "postgresql://vigie:inline@db:5432/vigie"
        assert with_password(url, "other") == url
        assert with_password("sqlite:///x.db", "p") == "sqlite:///x.db"
        assert with_password(url, None) == url

    def test_the_settings_expose_the_full_urls(self):
        s = settings(
            SECRET_KEY=KEY,
            DATABASE_URL="postgresql://vigie@db:5432/vigie",
            DATABASE_PASSWORD="dbpass",
            REDIS_URL="redis://redis:6379/0",
            REDIS_PASSWORD="redispass",
        )
        assert s.sqlalchemy_database_url == (
            "postgresql+psycopg2://vigie:dbpass@db:5432/vigie"
        )
        assert s.redis_url == "redis://:redispass@redis:6379/0"

    def test_a_logged_url_hides_its_password(self):
        assert redacted("redis://:s3cret@redis:6379/0") == "redis://:***@redis:6379/0"
        assert redacted("redis://redis:6379/0") == "redis://redis:6379/0"
