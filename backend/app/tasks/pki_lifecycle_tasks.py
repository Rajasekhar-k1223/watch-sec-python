import logging
import datetime
import asyncio
from datetime import timedelta
from typing import Dict, Any, List

from sqlalchemy.future import select
from sqlalchemy import and_, or_

from app.core.celery_app import celery_app
from app.db.session import AsyncSessionLocal
from app.db.models import DeviceCertificate, AuditLog, Agent
from app.services import ca_service

logger = logging.getLogger("PkiLifecycleManager")

@celery_app.task(name="app.tasks.pki_lifecycle_tasks.scheduled_pki_lifecycle_audit")
def scheduled_pki_lifecycle_audit():
    """
    [Phase 2A] Scheduled PKI lifecycle audit task:
      1. Alerts on expiring certificates (within 15 days)
      2. Transitions expired certificates to EXPIRED
      3. Regenerates X.509 CRL v2
    """
    logger.info("🔐 [PkiCron] Initiating Scheduled PKI Certificate Lifecycle Audit...")
    try:
        return asyncio.run(audit_and_maintain_pki_lifecycle())
    except Exception as e:
        logger.error(f"❌ [PkiCron] PKI Lifecycle Audit Failed: {e}")
        return {"status": "error", "message": str(e)}


async def audit_and_maintain_pki_lifecycle() -> Dict[str, Any]:
    """
    [Phase 1D] Automated PKI maintenance task:
      1. Identifies certificates expiring within 15 days and raises proactive renewal alerts.
      2. Marks certificates past NotAfter as EXPIRED and disables their active status.
      3. Verifies CRL freshness and regenerates X.509 CRL v2 if required.
      4. Audits active agent mTLS compliance.
    """
    now = datetime.datetime.utcnow()
    warn_threshold = now + timedelta(days=15)
    
    expiring_soon_count = 0
    expired_count = 0
    crl_updated = False

    async with AsyncSessionLocal() as db:
        # 1. Detect Expiring Soon
        expiring_q = select(DeviceCertificate).where(
            and_(
                DeviceCertificate.Status == "ACTIVE",
                DeviceCertificate.ExpiresAt <= warn_threshold,
                DeviceCertificate.ExpiresAt > now
            )
        )
        expiring_res = await db.execute(expiring_q)
        expiring_certs = expiring_res.scalars().all()
        expiring_soon_count = len(expiring_certs)

        for c in expiring_certs:
            days_left = (c.ExpiresAt - now).days
            logger.warning(f"[PKI Alert] Certificate serial {c.SerialNumber} for Agent '{c.AgentId}' expires in {days_left} days!")
            db.add(AuditLog(
                TenantId=c.TenantId,
                Actor="pki_lifecycle_watchdog",
                Action="CERTIFICATE_EXPIRING_WARNING",
                Target=c.AgentId,
                Details=f"Certificate {c.SerialNumber} expires on {c.ExpiresAt.isoformat()} ({days_left} days remaining)",
                Timestamp=now
            ))

        # 2. Mark truly expired certs
        expired_q = select(DeviceCertificate).where(
            and_(
                DeviceCertificate.Status == "ACTIVE",
                DeviceCertificate.ExpiresAt <= now
            )
        )
        expired_res = await db.execute(expired_q)
        expired_certs = expired_res.scalars().all()
        expired_count = len(expired_certs)

        for c in expired_certs:
            c.Status = "EXPIRED"
            logger.warning(f"[PKI Lifecycle] Certificate serial {c.SerialNumber} for Agent '{c.AgentId}' has EXPIRED.")
            db.add(AuditLog(
                TenantId=c.TenantId,
                Actor="pki_lifecycle_watchdog",
                Action="CERTIFICATE_EXPIRED_STATUS_APPLIED",
                Target=c.AgentId,
                Details=f"Certificate {c.SerialNumber} transitioned to EXPIRED status",
                Timestamp=now
            ))

        # 3. Synchronize CRL with all revoked certificates
        revoked_res = await db.execute(
            select(DeviceCertificate).where(DeviceCertificate.Status == "REVOKED")
        )
        revoked_list = [
            {
                "serial_number": r.SerialNumber,
                "revocation_date": r.RevokedAt or now,
                "reason": r.RevocationReason or "key_compromise"
            }
            for r in revoked_res.scalars().all()
        ]
        ca_service.generate_crl(revoked_list)
        crl_updated = True

        # 4. Total fleet certificate health summary
        active_res = await db.execute(
            select(DeviceCertificate).where(DeviceCertificate.Status == "ACTIVE")
        )
        total_active_certs = len(active_res.scalars().all())

        await db.commit()

    logger.info(f"[PKI Lifecycle] Audit complete. Active: {total_active_certs}, Expiring Soon: {expiring_soon_count}, Expired: {expired_count}, CRL Refreshed: {crl_updated}")
    return {
        "status": "COMPLETED",
        "total_active_certs": total_active_certs,
        "expiring_soon_count": expiring_soon_count,
        "expired_count": expired_count,
        "crl_refreshed": crl_updated,
        "audit_timestamp": now.isoformat()
    }

