"""Logging setup with request correlation.

Every log line carries the id of the request that produced it, so a scan
ingestion failure in the worker can be traced back to the upload that caused
it. The id travels in a context variable rather than being threaded through
every call signature.
"""

import json
import logging
import logging.config
from contextvars import ContextVar
from datetime import UTC, datetime

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


# Attributes every LogRecord has: anything else was passed as ``extra=`` and
# belongs in the JSON document.
_RECORD_FIELDS = set(vars(logging.makeLogRecord({}))) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    """One JSON document per line, for a log collector (Loki, ELK, Datadog).

    Text lines have to be parsed back with a pattern that breaks with the first
    message containing a bracket; JSON is read as is, request_id included.
    """

    def format(self, record: logging.LogRecord) -> str:
        document = {
            "time": datetime.fromtimestamp(record.created, UTC).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "request_id": getattr(record, "request_id", NO_REQUEST),
            "message": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _RECORD_FIELDS and key not in document:
                document[key] = value
        if record.exc_info:
            document["exception"] = self.formatException(record.exc_info)
        return json.dumps(document, ensure_ascii=False, default=str)


# Loggers that come with their own handlers (uvicorn configures its own before
# the application is imported). Routed to the root handler instead, so every
# line has the same shape and carries the request id.
ROUTED_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access", "celery")


def configure_logging() -> None:
    formatter = "json" if settings.LOG_FORMAT == "json" else "standard"
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
                },
                "json": {"()": JsonFormatter},
            },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": formatter,
                    "filters": ["request_id"],
                }
            },
            "loggers": {
                name: {"handlers": [], "propagate": True} for name in ROUTED_LOGGERS
            },
            "root": {"handlers": ["console"], "level": settings.LOG_LEVEL},
        }
    )
