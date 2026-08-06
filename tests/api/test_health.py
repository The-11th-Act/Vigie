"""Tests des sondes de disponibilité.

``/health`` (liveness) et ``/ready`` (readiness) doivent diverger : une panne
Redis laisse la première verte et fait tomber la seconde. C'est précisément
l'écart qui empêchait de détecter qu'une ingestion était morte alors que la
plateforme se déclarait en bonne santé.
"""

from unittest.mock import patch

import pytest
from sqlalchemy.exc import SQLAlchemyError


class _FakeRedis:
    def __init__(self, reachable=True):
        self.reachable = reachable
        self.closed = False

    def ping(self):
        if not self.reachable:
            raise ConnectionError("redis is down")
        return True

    def close(self):
        self.closed = True


@pytest.fixture
def redis_up():
    fake = _FakeRedis(reachable=True)
    with patch("app.main.redis.Redis.from_url", return_value=fake):
        yield fake


@pytest.fixture
def redis_down():
    fake = _FakeRedis(reachable=False)
    with patch("app.main.redis.Redis.from_url", return_value=fake):
        yield fake


class TestHealth:
    def test_health_is_green_when_the_database_answers(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy", "database": "ok"}

    def test_health_ignores_redis(self, client, redis_down):
        """Liveness must not depend on the broker: a Redis outage is not a
        reason to have the orchestrator restart the API process."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"


class TestReadiness:
    def test_ready_when_every_dependency_answers(self, client, redis_up):
        response = client.get("/ready")
        assert response.status_code == 200
        body = response.json()
        assert body == {"status": "ready", "database": "ok", "redis": "ok"}
        assert redis_up.closed, "the probe must not leak a Redis connection"

    def test_not_ready_when_redis_is_down(self, client, redis_down):
        """The regression this endpoint exists for: uploads return 503 while
        /health stays green."""
        response = client.get("/ready")
        assert response.status_code == 503
        body = response.json()
        assert body["status"] == "not_ready"
        assert body["database"] == "ok"
        assert body["redis"] == "unreachable"

    def test_not_ready_when_the_database_is_down(self, client, redis_up):
        from app.db.database import get_db
        from app.main import app

        class _BrokenSession:
            def execute(self, *args, **kwargs):
                raise SQLAlchemyError("database is down")

        def _broken_db():
            yield _BrokenSession()

        app.dependency_overrides[get_db] = _broken_db
        try:
            response = client.get("/ready")
        finally:
            app.dependency_overrides.pop(get_db, None)

        assert response.status_code == 503
        assert response.json()["database"] == "unreachable"

    def test_ready_does_not_leak_the_failure_reason(self, client, redis_down):
        """The probe is often exposed unauthenticated; it must not describe the
        internals of the outage."""
        body = client.get("/ready").json()
        assert "redis is down" not in str(body)
        assert body["redis"] == "unreachable"
