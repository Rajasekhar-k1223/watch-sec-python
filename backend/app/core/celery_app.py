import os # type: ignore
from celery import Celery # type: ignore

# Default to local Redis if not set
#CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://default:jKitLvLgbzIcEdttPdeecllDxzuuughO@turntable.proxy.rlwy.net:35861")
#CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://default:jKitLvLgbzIcEdttPdeecllDxzuuughO@turntable.proxy.rlwy.net:35861")

CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND")

celery_app = Celery(
    "watchsec",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # task_always_eager=True, # Uncomment for testing without worker
)

# Auto-discover tasks in packages
celery_app.autodiscover_tasks(["app.tasks.general", "app.tasks.reports", "app.tasks.security"])

celery_app.conf.beat_schedule = {
    "send-tenant-reports-scheduled": {
        "task": "app.tasks.reports.send_tenant_reports",
        "schedule": 60.0,  # Every minute — checks if scheduled_time matches current UTC time
    },
    "check-offline-agents-10min": {
        "task": "app.tasks.reports.check_offline_agents",
        "schedule": 600.0,  # Every 10 minutes
    },
}
