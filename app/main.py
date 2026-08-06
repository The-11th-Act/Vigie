import logging
import logging.config
from contextlib import asynccontextmanager

import redis
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse

from app.api.v1 import assets, auth, dashboard, scans, users, vulnerabilities
from app.core.bootstrap import bootstrap_admin_user
from app.core.config import settings
from app.db.database import SessionLocal, get_db


def configure_logging() -> None:
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "standard": {
                    "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                }
            },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": "standard",
                }
            },
            "root": {"handlers": ["console"], "level": settings.LOG_LEVEL},
        }
    )


configure_logging()
logger = logging.getLogger(__name__)


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
def health_check(db: Session = Depends(get_db)):
    """Liveness + database connectivity.

    Returns 503 rather than 500 when the database is unreachable so that
    orchestrators treat it as "not ready" instead of a crashed process.
    """
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        logger.error("Health check failed: %s", exc)
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "database": "unreachable"},
        )
    return {"status": "healthy", "database": "ok"}


@app.get("/ready", tags=["Health"])
def readiness_check(db: Session = Depends(get_db)):
    """Readiness: every dependency needed to actually serve traffic.

    ``/health`` only proves the process and its database are alive. Redis being
    down leaves that probe green while every scan upload fails with a 503, so a
    load balancer would keep routing traffic to a node that cannot ingest
    anything. This probe covers the broker too.
    """
    checks: dict[str, str] = {}
    ready = True

    try:
        db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except SQLAlchemyError as exc:
        logger.error("Readiness: database unreachable: %s", exc)
        checks["database"] = "unreachable"
        ready = False

    try:
        redis_client = redis.Redis.from_url(
            settings.REDIS_URL, socket_connect_timeout=2, socket_timeout=2
        )
        redis_client.ping()
        redis_client.close()
        checks["redis"] = "ok"
    except Exception as exc:  # redis raises a wide range of connection errors
        logger.error("Readiness: redis unreachable: %s", exc)
        checks["redis"] = "unreachable"
        ready = False

    if not ready:
        return JSONResponse(
            status_code=503, content={"status": "not_ready", **checks}
        )
    return {"status": "ready", **checks}
