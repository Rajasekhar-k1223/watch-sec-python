"""
[v4.4.0] Celery Background Tasks for Global Compliance Scans
Executes asynchronous regulatory framework assessments without blocking API workers.
"""
import asyncio
from typing import Optional
from app.core.celery_app import celery_app
from app.db.session import AsyncSessionLocal
from app.compliance.core.engine import compliance_engine


@celery_app.task(name="compliance.run_scan_job")
def run_compliance_scan_job_task(job_id: str, tenant_id: int = 1, framework_id: Optional[str] = None) -> dict:
    async def _execute() -> dict:
        async with AsyncSessionLocal() as session:
            job = compliance_engine.get_scan_job(job_id)
            if not job:
                job = compliance_engine.start_scan_job(tenant_id, framework_id)
                job.job_id = job_id
                compliance_engine._jobs[job_id] = job
            completed = await compliance_engine.execute_scan_job(job_id, session)
            return completed.dict() if completed else {"job_id": job_id, "status": "NOT_FOUND"}

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_execute())
    finally:
        loop.close()

