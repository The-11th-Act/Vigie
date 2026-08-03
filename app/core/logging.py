"""Logging setup with request correlation.

Every log line carries the id of the request that produced it, so a scan
ingestion failure in the worker can be traced back to the upload that caused
it. The id travels in a context variable rather than being threaded through
every call signature.
"""
import logging
import logging.config
from contextvars import ContextVar

from app.core.config import settings

NO_REQUEST = "-"

request_id_var: ContextVar[str] = ContextVar("request_id", default=NO_REQUEST)


def get_request_id() -> str:
    return request_id_var.get()


def set_request_id(request_id: str) -> None:
    request_id_var.set(request_id)


class RequestIdFilter(logging.Filter):
    """Make ``%(request_id)s`` available to every record.

    A filter rather than an adapter: records emitted by third-party libraries
    (SQLAlchemy, Celery, uvicorn) go through the same handler and would break
    the format string without it.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        return True


def configure_logging() -> None:
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "filters": {
                "request_id": {"()": RequestIdFilter},
            },
            "formatters": {
                "standard": {
                    "format": (
                        "%(asctime)s [%(levelname)s] [%(request_id)s] "
                        "%(name)s: %(message)s"
                    ),
                }
            },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": "standard",
                    "filters": ["request_id"],
                }
            },
            "root": {"handlers": ["console"], "level": settings.LOG_LEVEL},
        }
    )
