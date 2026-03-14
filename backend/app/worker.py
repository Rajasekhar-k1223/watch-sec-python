from app.core.celery_app import celery_app # type: ignore
# Import tasks to ensure they are registered with Celery
from app.tasks.security import scan_vulnerabilities_background # type: ignore
from app.tasks.general import analyze_risk_background # type: ignore
from app.tasks.ocr_tasks import process_ocr_background # type: ignore
from app.tasks.reports import send_tenant_reports # type: ignore

# This file serves as the entry point for the Celery worker.
# Run with: celery -A app.worker worker --loglevel=info
