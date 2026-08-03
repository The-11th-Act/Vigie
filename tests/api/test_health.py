"""Liveness, readiness, correlation ids and the error envelope."""
import pytest
from fastapi import APIRouter


class TestLiveness:
    def test_health_does_not_touch_dependencies(self, client, monkeypatch):
        """A liveness probe that fails on a database blip gets the container
        killed and restarted, which does nothing to fix the database."""

        def exploding_check(*args, **kwargs):
            raise AssertionError("liveness must not query the database")

        monkeypatch.setattr("app.main._check_database", exploding_check)

        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"


class TestReadiness:
    def _stub(self, monkeypatch, database="ok", redis="ok", celery="ok"):
        monkeypatch.setattr("app.main._check_database", lambda db: database)
        monkeypatch.setattr("app.main._check_redis", lambda: redis)
        monkeypatch.setattr("app.main._check_celery", lambda: celery)

    def test_ready_when_every_dependency_answers(self, client, monkeypatch):
        self._stub(monkeypatch)
        response = client.get("/ready")
        assert response.status_code == 200
        assert response.json()["status"] == "ready"

    @pytest.mark.parametrize(
        "failing", ["database", "redis", "celery"]
    )
    def test_degraded_when_a_dependency_is_down(self, client, monkeypatch, failing):
        self._stub(monkeypatch, **{failing: "unreachable"})

        response = client.get("/ready")
        assert response.status_code == 503
        assert response.json()["status"] == "degraded"

    def test_reports_which_dependency_failed(self, client, monkeypatch):
        self._stub(monkeypatch, redis="unreachable")

        checks = client.get("/ready").json()["checks"]
        assert checks["redis"] == "unreachable"
        assert checks["database"] == "ok"

    def test_no_workers_is_not_ready(self, client, monkeypatch):
        """A broker that answers but has no workers means uploads queue forever."""
        self._stub(monkeypatch, celery="no workers")
        assert client.get("/ready").status_code == 503


class TestRequestCorrelation:
    def test_response_carries_a_request_id(self, client):
        response = client.get("/health")
        assert response.headers.get("X-Request-ID")

    def test_inbound_request_id_is_reused(self, client):
        """A trace started upstream must keep its id through this service."""
        response = client.get("/health", headers={"X-Request-ID": "upstream-42"})
        assert response.headers["X-Request-ID"] == "upstream-42"

    def test_ids_differ_between_requests(self, client):
        first = client.get("/health").headers["X-Request-ID"]
        second = client.get("/health").headers["X-Request-ID"]
        assert first != second


class TestErrorEnvelope:
    def test_unhandled_error_does_not_leak_internals(self, client):
        """The traceback belongs in the log, not in the response body."""
        from fastapi.testclient import TestClient

        from app.main import app as fastapi_app

        router = APIRouter()

        @router.get("/boom")
        def boom():
            raise RuntimeError("SELECT * FROM users -- internal detail")

        fastapi_app.include_router(router)
        original_routes = list(fastapi_app.router.routes)
        try:
            # The default TestClient re-raises server exceptions, which would
            # bypass the very handler under test.
            with TestClient(fastapi_app, raise_server_exceptions=False) as raw:
                response = raw.get("/boom")
        finally:
            fastapi_app.router.routes = original_routes

        assert response.status_code == 500
        body = response.json()
        assert body["detail"] == "Internal server error"
        assert "internal detail" not in response.text
        # The id ties the sanitised response back to the logged traceback.
        assert body["request_id"]


class TestMetrics:
    def test_exposes_prometheus_exposition(self, client):
        response = client.get("/metrics")
        assert response.status_code == 200
        assert "vigie_http_requests_total" in response.text

    def test_counts_requests_by_route_template(self, client, db_session):
        """Labels must use the route template, not the resolved path, or every
        asset id would mint its own time series."""
        from app.models.asset import Asset

        asset = Asset(ip_address="10.9.9.9")
        db_session.add(asset)
        db_session.commit()

        client.get(f"/api/v1/assets/{asset.id}")

        body = client.get("/metrics").text
        assert 'route="/api/v1/assets/{asset_id}"' in body
        assert f'route="/api/v1/assets/{asset.id}"' not in body
