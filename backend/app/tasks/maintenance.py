import asyncio
from datetime import datetime, timedelta
import logging
from sqlalchemy import delete
from sqlalchemy.future import select

from ..core.celery_app import celery_app
from ..db.session import AsyncSessionLocal
from ..db.models import EventLog, AgentReportEntity, ActivityLog, Tenant

logger = logging.getLogger("MaintenanceWorker")

@celery_app.task(name="app.tasks.maintenance.purge_expired_data")
def purge_expired_data():
    """
    [v2.6.0] Automated Data Retention: Purges telemetry and logs older than the tenant's retention limit.
    Ensures GDPR compliance by not storing data longer than legally required.
    """
    async def _purge():
        async with AsyncSessionLocal() as db:
            try:
                result = await db.execute(select(Tenant))
                tenants = result.scalars().all()
                
                for tenant in tenants:
                    retention_days = tenant.DataRetentionDays or 90
                    cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
                    
                    logger.info(f"Purging data for Tenant {tenant.Id} older than {cutoff_date}")
                    
                    await db.execute(
                        delete(AgentReportEntity)
                        .where(AgentReportEntity.TenantId == tenant.Id)
                        .where(AgentReportEntity.Timestamp < cutoff_date)
                    )
                    
                    await db.execute(
                        delete(ActivityLog)
                        .where(ActivityLog.TenantId == tenant.Id)
                        .where(ActivityLog.Timestamp < cutoff_date)
                    )
                    
                await db.commit()
                logger.info("Maintenance Purge Completed Successfully.")
            except Exception as e:
                logger.error(f"Maintenance Purge Failed: {e}")
                await db.rollback()

    try:
        asyncio.run(_purge())
    except Exception as e:
        logger.error(f"Maintenance Purge execution failed: {e}")

@celery_app.task(name="app.tasks.maintenance.sync_pending_minio_artifacts")
def sync_pending_minio_artifacts():
    """
    [Phase 3A] Forensic Vault Reconciliation Task:
    Sweeps local fallback storage (/app/storage/shadow/pending/), uploads queued artifacts
    to MinIO, validates cryptographic checksums, and purges local copies only after verified
    remote confirmation.
    """
    from ..services.minio_vault import minio_vault
    try:
        result = minio_vault.sync_pending_artifacts()
        logger.info(f"[MinioVault Reconciliation] Sync execution result: {result}")
        return result
    except Exception as e:
        logger.error(f"[MinioVault Reconciliation] Scheduled sync task failed: {e}")
        return {"error": str(e)}
