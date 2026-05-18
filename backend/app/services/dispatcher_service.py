import logging
import httpx
import json
from typing import Optional, Dict, Any

logger = logging.getLogger("AlertDispatcher")

class DispatcherService:
    """[v2.6.0] Global Alert Dispatcher: Connects Monitorix to Slack, Teams, and SIEMs."""
    
    async def dispatch_critical_alert(self, 
        title: str, 
        message: str, 
        severity: str, 
        agent_id: str,
        cluster_name: Optional[str] = None,
        webhook_url: Optional[str] = None
    ):
        """Sends a high-fidelity alert to external webhooks."""
        if not webhook_url:
            return

        # 1. Construct Slack-format payload (compatible with most webhooks)
        color = "#ef4444" if severity == "Critical" else "#f59e0b"
        payload = {
            "text": f"*Monitorix Enterprise Alert: {title}*",
            "attachments": [
                {
                    "color": color,
                    "fields": [
                        {"title": "Severity", "value": severity, "short": True},
                        {"title": "Cluster", "value": cluster_name or "Standalone", "short": True},
                        {"title": "Asset ID", "value": agent_id, "short": True},
                        {"title": "Details", "value": message, "short": False}
                    ],
                    "footer": "Monitorix Autonomous Security",
                    "ts": json.dumps(int(logging.time.time()))
                }
            ]
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(webhook_url, json=payload, timeout=5.0)
                if response.status_code == 200:
                    logger.info(f"Alert dispatched successfully to webhook for agent {agent_id}")
                else:
                    logger.error(f"Failed to dispatch alert: {response.status_code} - {response.text}")
        except Exception as e:
            logger.error(f"Error in Alert Dispatcher: {e}")

# Global instance
dispatcher = DispatcherService()
