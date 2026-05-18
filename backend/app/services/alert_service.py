import httpx
import logging
import json
from typing import Dict, Any, Optional

logger = logging.getLogger("AlertService")

class AlertService:
    """[v2.4.0] Real-time Multi-Channel Alert Dispatcher (Slack, Teams, Webhooks)."""
    
    @staticmethod
    async def dispatch_alert(tenant_config: Dict[str, Any], alert_data: Dict[str, Any]):
        """Dispatches a high-priority security alert to configured channels."""
        if not tenant_config or not tenant_config.get("enabled"):
            return

        try:
            channel = tenant_config.get("channel", "webhook").lower()
            webhook_url = tenant_config.get("webhook_url")
            
            if not webhook_url:
                return

            # Construct the human-readable message
            severity = alert_data.get("Severity", "Medium").upper()
            title = f"🚨 {severity} SECURITY ALERT: {alert_data.get('Type')}"
            message = (
                f"*Agent:* {alert_data.get('AgentId')}\n"
                f"*Details:* {alert_data.get('Details')}\n"
                f"*Time:* {alert_data.get('Timestamp')}\n"
                f"🔗 [View Incident](https://dashboard.monitorix.enterprise/alerts/{alert_data.get('Id')})"
            )

            async with httpx.AsyncClient(timeout=5.0) as client:
                if channel == "slack":
                    payload = {
                        "text": title,
                        "blocks": [
                            {
                                "type": "section",
                                "text": {"type": "mrkdwn", "text": f"{title}\n{message}"}
                            }
                        ]
                    }
                    await client.post(webhook_url, json=payload)
                elif channel == "teams":
                    payload = {
                        "@type": "MessageCard",
                        "@context": "http://schema.org/extensions",
                        "themeColor": "FF0000" if severity == "CRITICAL" else "FFA500",
                        "summary": title,
                        "sections": [{
                            "activityTitle": title,
                            "text": message
                        }]
                    }
                    await client.post(webhook_url, json=payload)
                else:
                    # Generic Webhook
                    await client.post(webhook_url, json=alert_data)
                
            logger.info(f"Dispatched alert {alert_data.get('Id')} via {channel}.")
        except Exception as e:
            logger.error(f"Alert Dispatch Failed: {e}")

# Global singleton
alert_service = AlertService()
