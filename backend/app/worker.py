from app.core.celery_app import celery_app  # type: ignore

# Import all task modules to ensure full registration with Celery
from app.tasks.security import *  # type: ignore
from app.tasks.general import *  # type: ignore
from app.tasks.ocr_tasks import *  # type: ignore
from app.tasks.reports import *  # type: ignore
from app.tasks.compliance_tasks import *  # type: ignore
from app.tasks.agentless import *  # type: ignore
from app.tasks.ai_analysis import *  # type: ignore
from app.tasks.behavior_analysis import *  # type: ignore
from app.tasks.maintenance import *  # type: ignore
from app.tasks.rolling_updates import *  # type: ignore
from app.tasks.pki_lifecycle_tasks import *  # type: ignore

# Entry point for Celery worker and beat
