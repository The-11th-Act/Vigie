from datetime import timedelta

from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

celery_app = Celery("tasks", broker=settings.REDIS_URL, backend=settings.REDIS_URL)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)


def build_beat_schedule() -> dict:
    """Periodic jobs, rebuilt from the settings so tests can check each toggle."""
    schedule = {
        # The overdue penalty grows every day, but stored scores only moved when
        # a scan came in: a late finding on a host nobody rescans kept its rank.
        "rescore-open-findings": {
            "task": "app.worker.tasks.rescore_open_findings_task",
            "schedule": crontab(hour=settings.RESCORE_HOUR_UTC, minute=0),
        },
    }
    # The periodic pull is only scheduled when the integration is actually
    # turned on, so a deployment without CrowdStrike credentials does not
    # accumulate a failing beat entry.
    if settings.THREAT_INTEL_ENABLED:
        schedule["threat-intel-refresh"] = {
            "task": "app.worker.tasks.refresh_threat_intel_task",
            "schedule": crontab(hour=settings.THREAT_INTEL_REFRESH_HOUR_UTC, minute=15),
        }
    if settings.CROWDSTRIKE_SYNC_ENABLED:
        schedule["crowdstrike-sync"] = {
            "task": "app.worker.tasks.sync_crowdstrike_task",
            "schedule": timedelta(minutes=settings.CROWDSTRIKE_SYNC_INTERVAL_MINUTES),
        }
    return schedule


celery_app.conf.beat_schedule = build_beat_schedule()

celery_app.autodiscover_tasks(["app.worker"])
