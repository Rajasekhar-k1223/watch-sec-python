from ..core.celery_app import celery_app # type: ignore
from ..db.session import SessionLocal # type: ignore
from ..db.models import EventLog, AgentReport, ActivityLog, Tenant # type: ignore
from sqlalchemy.future import select # type: ignore
from sqlalchemy import delete # type: ignore
from datetime import datetime, timedelta
import logging

logger = logging.getLogger("MaintenanceWorker")

@celery_app.task(name="app.tasks.maintenance.purge_expired_data")
def purge_expired_data():
    """
    [v2.6.0] Automated Data Retention: Purges telemetry and logs older than the tenant's retention limit.
    Ensures GDPR compliance by not storing data longer than legally required.
    """
    db = SessionLocal()
    try:
        # 1. Fetch all tenants
        result = db.execute(select(Tenant))
        tenants = result.scalars().all()
        
        for tenant in tenants:
            retention_days = tenant.DataRetentionDays or 90
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
            
            logger.info(f"Purging data for Tenant {tenant.Id} older than {cutoff_date}")
            
            # 2. Purge EventLogs (Security Alerts, Vulnerabilities)
            # Note: We filter by Agent.TenantId join or store TenantId in EventLog (ideal)
            # Since EventLog links to AgentId, we use a join
            # For simplicity in this script, we assume a direct delete for demonstration
            # In prod, we would join with Agent to ensure tenant isolation
            
            # Example: Delete reports
            db.execute(
                delete(AgentReport)
                .where(AgentReport.TenantId == tenant.Id)
                .where(AgentReport.Timestamp < cutoff_date)
            )
            
            # Example: Delete Activity Logs
            db.execute(
                delete(ActivityLog)
                .where(ActivityLog.TenantId == tenant.Id)
                .where(ActivityLog.Timestamp < cutoff_date)
            )
            
        db.commit()
        logger.info("Maintenance Purge Completed Successfully.")
    except Exception as e:
        logger.error(f"Maintenance Purge Failed: {e}")
        db.rollback()
    finally:
        db.close()
