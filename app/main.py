import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse, Response

from app.api.v1 import assets, auth, dashboard, scans, users, vulnerabilities
from app.core import metrics
from app.core.bootstrap import bootstrap_admin_user
from app.core.config import settings
from app.core.logging import configure_logging, get_request_id, set_request_id
from app.db.database import SessionLocal, get_db

configure_logging()
logger = logging.getLogger(__name__)

REQUEST_ID_HEADER = "X-Request-ID"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Startup / shutdown hooks.

    Replaces the deprecated ``@app.on_event("startup")``, which FastAPI warns
    about at import time and plans to remove.
    """
    db = SessionLocal()
    try:
        bootstrap_admin_user(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    lifespan=lifespan,
    description="Risk-Based Vulnerability Management (RBVM) Platform",
    # The interactive docs expose the full API surface; keep them out of prod.
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    expose_headers=[REQUEST_ID_HEADER],
)


@app.middleware("http")
async def request_context(request: Request, call_next):
    """Attach a correlation id to the request and record its timing.

    An inbound ``X-Request-ID`` is honoured so a trace started at the load
    balancer (or by the caller) carries through; otherwise one is minted.
    """
    request_id = request.headers.get(REQUEST_ID_HEADER) or uuid.uuid4().hex
    set_request_id(request_id)

    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        # Timing is recorded for failures too, otherwise latency graphs only
        # show the happy path. The exception handler below produces the body.
        metrics.observe_request(
            request.method,
            _route_of(request),
            500,
            time.perf_counter() - started,
        )
        raise

    metrics.observe_request(
        request.method,
        _route_of(request),
        response.status_code,
        time.perf_counter() - started,
    )
    response.headers[REQUEST_ID_HEADER] = request_id
    return response


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Return a normalised error instead of leaking a stack trace.

    The full traceback goes to the log, tagged with the request id the client
    is given, so an operator can find it without the client ever seeing
    internal detail.
    """
    request_id = get_request_id()
    logger.exception(
        "Unhandled error on %s %s (request_id=%s)",
        request.method,
        request.url.path,
        request_id,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "request_id": request_id},
        headers={REQUEST_ID_HEADER: request_id},
    )


app.include_router(auth.router, prefix=f"{settings.API_V1_STR}/auth", tags=["Auth"])
app.include_router(users.router, prefix=f"{settings.API_V1_STR}/users", tags=["Users"])
app.include_router(
    dashboard.router, prefix=f"{settings.API_V1_STR}/dashboard", tags=["Dashboard"]
)
app.include_router(assets.router, prefix=f"{settings.API_V1_STR}/assets", tags=["Assets"])
app.include_router(
    vulnerabilities.router,
    prefix=f"{settings.API_V1_STR}/vulnerabilities",
    tags=["Vulnerabilities"],
)
app.include_router(scans.router, prefix=f"{settings.API_V1_STR}/scans", tags=["Scans"])


@app.get("/", tags=["Health"])
def read_root():
    return {"status": "online", "project": settings.PROJECT_NAME, "docs": "/docs"}


@app.get("/health", tags=["Health"])
def health_check():
    """Liveness only: is this process running and able to answer?

    Deliberately free of dependency checks. A liveness probe that fails when
    the database blips gets the container killed and restarted, which does
    nothing to fix the database — that judgement belongs to /ready.
    """
    return {"status": "healthy"}


@app.get("/ready", tags=["Health"])
def readiness_check(db: Session = Depends(get_db)):
    """Readiness: can this instance actually serve traffic?

    Reports each dependency separately so an operator can see which one is at
    fault, and returns 503 as soon as one is unusable.
    """
    checks = {
        "database": _check_database(db),
        "redis": _check_redis(),
        "celery_workers": _check_celery(),
    }
    ready = all(state == "ok" for state in checks.values())

    body = {"status": "ready" if ready else "degraded", "checks": checks}
    return body if ready else JSONResponse(status_code=503, content=body)


@app.get("/metrics", tags=["Health"], include_in_schema=False)
def prometheus_metrics(db: Session = Depends(get_db)):
    metrics.refresh_backlog_gauges(db)
    return Response(
        content=generate_latest(metrics.REGISTRY), media_type=CONTENT_TYPE_LATEST
    )


def _route_of(request: Request) -> str:
    """The route template (``/api/v1/assets/{asset_id}``), so labels stay bounded.

    Rebuilt from the path parameters segment by segment rather than read off the
    route object: FastAPI mounts included routers, so the matched route only
    knows its own suffix ("/{asset_id}"), not the prefix it was mounted under.
    Substituting segment-wise — never as a substring — keeps "/api/v1/..." from
    being mangled when an id happens to be "1".

    Unmatched paths collapse to a single label instead of minting a series per
    URL a scanner probes.
    """
    if request.scope.get("route") is None:
        return "unmatched"

    params = request.scope.get("path_params") or {}
    if not params:
        return request.url.path

    name_by_value = {str(value): name for name, value in params.items()}
    return "/".join(
        "{" + name_by_value[segment] + "}" if segment in name_by_value else segment
        for segment in request.url.path.split("/")
    )


def _check_database(db: Session) -> str:
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        logger.error("Readiness: database unreachable: %s", exc)
        return "unreachable"
    return "ok"


def _check_redis() -> str:
    import redis

    client = redis.Redis.from_url(
        settings.REDIS_URL, socket_connect_timeout=1, socket_timeout=1
    )
    try:
        client.ping()
    except Exception as exc:  # redis raises a wide range of connection errors
        logger.error("Readiness: Redis unreachable: %s", exc)
        return "unreachable"
    finally:
        # The probe runs on every poll of the load balancer: an unclosed
        # client would leak one connection per check.
        client.close()
    return "ok"


def _check_celery() -> str:
    """Whether any worker answers. Without one, uploads queue up forever."""
    try:
        from app.worker.celery_app import celery_app

        replies = celery_app.control.ping(timeout=1)
    except Exception as exc:
        logger.error("Readiness: could not reach Celery: %s", exc)
        return "unreachable"
    return "ok" if replies else "no workers"
