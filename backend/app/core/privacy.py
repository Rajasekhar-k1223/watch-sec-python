import logging
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy import delete # type: ignore
from ..db.models import AgentReport, EventLog, ActivityLog, OCRLog
from typing import Dict, Any

logger = logging.getLogger("PrivacyCore")

class PrivacyManager:
    """[v2.6.0] GDPR Privacy & Consent Core."""

    @staticmethod
    async def process_data_subject_request(db: AsyncSession, tenant_id: int, agent_id: str):
        """
        [GDPR] Implements the 'Right to be Forgotten'.
        Permanently removes all telemetry and forensic data associated with an agent/user.
        """
        try:
            logger.warning(f"Executing DSR for Agent {agent_id} in Tenant {tenant_id}")
            
            # 1. Delete Forensic OCR Logs
            await db.execute(delete(OCRLog).where(OCRLog.AgentId == agent_id))
            
            # 2. Delete Telemetry Reports
            await db.execute(delete(AgentReport).where(AgentReport.AgentId == agent_id))
            
            # 3. Delete Activity Logs (Privacy Sensitive)
            await db.execute(delete(ActivityLog).where(ActivityLog.AgentId == agent_id))
            
            # 4. Anonymize EventLogs (Keep the event, remove the source ID if needed)
            # Or delete if policy dictates
            await db.execute(delete(EventLog).where(EventLog.AgentId == agent_id))
            
            await db.commit()
            return {"status": "success", "agentId": agent_id, "actions": ["purged_all_telemetry"]}
        except Exception as e:
            logger.error(f"DSR Failed for {agent_id}: {e}")
            await db.rollback()
            return {"status": "error", "message": str(e)}

    @staticmethod
    def get_privacy_policy(region: str = "EU") -> str:
        """Returns the region-specific privacy policy for agent display."""
        policies = {
            "EU": "Monitorix GDPR Policy: Data is encrypted at rest and purged after 90 days. You have the right to request deletion.",
            "US": "Monitorix Privacy Policy: Data is collected for security monitoring and protected via AES-256 encryption.",
            "Global": "Monitorix Privacy Policy: Standard data protection and encryption applies."
        }
        return policies.get(region, policies["Global"])

# Global singleton
privacy_manager = PrivacyManager()
