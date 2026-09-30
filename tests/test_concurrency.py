"""The API's concurrency model: synchronous routes, a bounded threadpool, and
a connection pool that covers it (docs/EXPLOITATION.md, "Dimensionnement")."""

import ast
from pathlib import Path

import anyio
import pytest
from anyio import to_thread
from pydantic import ValidationError

from app.core.config import Settings, settings
from app.main import configure_threadpool

KEY = "a-secret-key-for-the-concurrency-tests-0123456789"


APP_DIR = Path(__file__).resolve().parents[1] / "app"

# The middleware, the lifespan and the error handler: no per-request blocking
# I/O, and they must be async to wrap the application.
ASYNC_ALLOWED = {APP_DIR / "main.py"}


def test_no_code_runs_on_the_event_loop():
    """An ``async def`` route or dependency runs on the event loop itself: its
    blocking calls (psycopg2, the Celery broker, the disk) then freeze every
    request of the process, probes included. The scan upload did exactly that.
    Everything is a plain ``def``, run in the threadpool.

    Read from the source rather than from ``app.routes``: FastAPI keeps
    included routers in private structures that change between versions."""
    on_the_loop = sorted(
        f"{path.relative_to(APP_DIR.parent)}:{node.lineno} {node.name}"
        for path in APP_DIR.rglob("*.py")
        if path not in ASYNC_ALLOWED
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.AsyncFunctionDef)
    )
    assert not on_the_loop


def test_the_threadpool_is_capped_at_api_threads():
    async def configured() -> float:
        configure_threadpool()
        return to_thread.current_default_thread_limiter().total_tokens

    assert anyio.run(configured) == settings.API_THREADS


def test_the_pool_must_cover_the_threads():
    """A thread without a connection waits on the pool, unseen, then fails."""
    with pytest.raises(ValidationError, match="API_THREADS"):
        Settings(
            _env_file=None,
            SECRET_KEY=KEY,
            API_THREADS=20,
            DB_POOL_SIZE=10,
            DB_MAX_OVERFLOW=5,
        )

    sized = Settings(
        _env_file=None, SECRET_KEY=KEY, API_THREADS=15, DB_POOL_SIZE=10, DB_MAX_OVERFLOW=5
    )
    assert sized.API_THREADS == 15


def test_the_engine_uses_the_configured_pool():
    from app.db.database import engine

    if engine.dialect.name == "sqlite":
        pytest.skip("SQLite pool, not the PostgreSQL one")
    assert engine.pool.size() == settings.DB_POOL_SIZE
    assert engine.pool._max_overflow == settings.DB_MAX_OVERFLOW
    assert engine.pool._timeout == settings.DB_POOL_TIMEOUT_SECONDS
