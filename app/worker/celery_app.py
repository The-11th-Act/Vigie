from datetime import timedelta

from celery import Celery

from app.core.config import settings

celery_app = Celery("tasks", broker=settings.REDIS_URL, backend=settings.REDIS_URL)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

# The periodic pull is only scheduled when the integration is actually turned
# on, so a deployment without CrowdStrike credentials does not accumulate a
# failing beat entry.
if settings.CROWDSTRIKE_SYNC_ENABLED:
    celery_app.conf.beat_schedule = {
        "crowdstrike-sync": {
            "task": "app.worker.tasks.sync_crowdstrike_task",
            "schedule": timedelta(
                minutes=settings.CROWDSTRIKE_SYNC_INTERVAL_MINUTES
            ),
        }
    }

celery_app.autodiscover_tasks(["app.worker"])
