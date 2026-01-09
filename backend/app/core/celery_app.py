import os
from celery import Celery

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
# We will create app.tasks package
celery_app.autodiscover_tasks(["app.tasks.general", "app.tasks.reports"])
