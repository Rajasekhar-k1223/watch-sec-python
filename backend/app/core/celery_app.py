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

from kombu import Queue # type: ignore

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # [v2.1.0] Distributed Task Routing
    task_queues=(
        Queue('default', routing_key='default.#'),
        Queue('high_priority', routing_key='high.#'),
        Queue('heavy_tasks', routing_key='heavy.#'),
    ),
    task_default_queue='default',
    task_routes={
        'app.tasks.security.*': {'queue': 'high_priority'},
        'app.tasks.ocr_tasks.*': {'queue': 'heavy_tasks'},
        'app.tasks.reports.*': {'queue': 'heavy_tasks'},
    }
)

# Auto-discover tasks in packages
celery_app.autodiscover_tasks(["app.tasks.general", "app.tasks.reports", "app.tasks.security", "app.tasks"])

celery_app.conf.beat_schedule = {
    "send-tenant-reports-scheduled": {
        "task": "app.tasks.reports.send_tenant_reports",
        "schedule": 60.0,  # Every minute — checks if scheduled_time matches current UTC time
    },
    "check-offline-agents-10min": {
        "task": "app.tasks.reports.check_offline_agents",
        "schedule": 600.0,  # Every 10 minutes
    },
    "behavioral-analytics-hourly": {
        "task": "app.tasks.behavior_analysis.analyze_workforce_productivity",
        "schedule": 3600.0,  # Every hour
    },
    "agentless-polling": {
        "task": "tasks.agentless.poll_endpoints",
        "schedule": 30.0,  # Every 30 seconds
    },
}
