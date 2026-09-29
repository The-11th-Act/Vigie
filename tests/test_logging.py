"""Log format: text for a terminal, JSON for a collector, request id in both."""

import json
import logging

import pytest

from app.core.config import settings
from app.core.logging import (
    ROUTED_LOGGERS,
    JsonFormatter,
    RequestIdFilter,
    configure_logging,
    request_id_var,
)


def record(message="Ingested 3 findings", **extra):
    entry = logging.LogRecord(
        "app.services.ingestion", logging.INFO, __file__, 1, message, (), None
    )
    for key, value in extra.items():
        setattr(entry, key, value)
    RequestIdFilter().filter(entry)
    return entry


@pytest.fixture
def request_id():
    token = request_id_var.set("req-42")
    yield "req-42"
    request_id_var.reset(token)


def test_one_json_document_per_line(request_id):
    line = JsonFormatter().format(record(scan_job_id=7))

    document = json.loads(line)
    assert document["message"] == "Ingested 3 findings"
    assert document["level"] == "INFO"
    assert document["logger"] == "app.services.ingestion"
    assert document["request_id"] == "req-42"
    assert document["time"].endswith("+00:00")
    # Passed as extra=: kept, as a field of its own.
    assert document["scan_job_id"] == 7
    assert "\n" not in line


def test_exceptions_stay_on_the_line():
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        entry = record("failed")
        entry.exc_info = sys.exc_info()

    document = json.loads(JsonFormatter().format(entry))
    assert "ValueError: boom" in document["exception"]


@pytest.fixture
def restore_logging():
    yield
    configure_logging()


def test_json_is_a_setting(monkeypatch, restore_logging):
    monkeypatch.setattr(settings, "LOG_FORMAT", "json")
    configure_logging()

    [handler] = logging.getLogger().handlers
    assert isinstance(handler.formatter, JsonFormatter)


def test_text_remains_the_default(restore_logging):
    configure_logging()
    [handler] = logging.getLogger().handlers
    assert not isinstance(handler.formatter, JsonFormatter)


def test_uvicorn_and_celery_go_through_the_same_handler(restore_logging):
    """They install their own handlers otherwise, with their own format."""
    logging.getLogger("uvicorn.access").addHandler(logging.StreamHandler())

    configure_logging()

    for name in ROUTED_LOGGERS:
        logger = logging.getLogger(name)
        assert logger.handlers == []
        assert logger.propagate


def test_the_worker_logs_like_the_api():
    from celery.signals import setup_logging

    from app.worker import celery_app

    receivers = [ref() if callable(ref) else ref for _, ref in setup_logging.receivers]
    assert celery_app._use_application_logging in receivers
