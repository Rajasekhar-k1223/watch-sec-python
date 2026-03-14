import aiohttp # type: ignore
import json # type: ignore
import logging # type: ignore
from typing import List # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from ..db.models import Webhook # type: ignore

logger = logging.getLogger(__name__)

async def notify_event(tenant_id: int, event_type: str, details: dict, db: AsyncSession):
    """
    Sends a notification to all enabled webhooks and emails for a tenant.
    """
    try:
        from ..db.models import Tenant # type: ignore
        from ..services.email_service import email_service # type: ignore
        
        # 1. Fetch Tenant and Admin Email
        result = await db.execute(select(Tenant).where(Tenant.Id == tenant_id))
        tenant = result.scalar_one_or_none()
        
        if not tenant:
            return

        # 2. Immediate Email Alerts for Critical Events
        critical_events = ["SystemShutdown", "HighThreat", "AgentOffline", "SecurityThreat"]
        if event_type in critical_events and tenant.AdminEmail:
            subject = f"Monitorix CRITICAL ALERT: {event_type} on {details.get('hostname', 'Unknown Agent')}"
            html_content = f"""
            <h2>Monitorix Security Alert</h2>
            <p>A critical event has been detected:</p>
            <ul>
                <li><strong>Event:</strong> {event_type}</li>
                <li><strong>Agent:</strong> {details.get('agent_id', 'N/A')}</li>
                <li><strong>Hostname:</strong> {details.get('hostname', 'N/A')}</li>
                <li><strong>Details:</strong> {details.get('msg', 'N/A')}</li>
                <li><strong>Timestamp:</strong> {details.get('timestamp', 'N/A')}</li>
            </ul>
            <p>Please log in to your dashboard for more details.</p>
            """
            # Run in background to not block webhook delivery
            import asyncio # type: ignore
            asyncio.create_task(email_service.send_email(tenant.AdminEmail, subject, html_content))

        # 3. Webhook Delivery
        query = select(Webhook).where(
            Webhook.TenantId == tenant_id,
            Webhook.IsEnabled == True
        )
        result = await db.execute(query)
        webhooks = result.scalars().all()
        
        for wh in webhooks:
            events = json.loads(wh.EventsJson or "[]")
            if event_type not in events and "all" not in events:
                continue
            await send_webhook(wh, event_type, details)
            
    except Exception as e:
        logger.error(f"Error in notify_event: {e}")

async def send_webhook(webhook: Webhook, event_type: str, details: dict):
    try:
        payload = format_payload(webhook, event_type, details)
        
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook.Url, json=payload, timeout=5) as res:
                if res.status >= 400:
                    logger.error(f"Webhook failed with status {res.status}: {await res.text()}")
                    
    except Exception as e:
        logger.error(f"Failed to send webhook {webhook.Id}: {e}")

def format_payload(webhook: Webhook, event_type: str, details: dict):
    """
    Formats the JSON payload based on webhook type (Slack, Discord, Generic).
    """
    message = f"*Monitorix Alert: {event_type.upper()}*"
    agent_id = details.get("agent_id", "Unknown Agent")
    hostname = details.get("hostname", "Unknown")
    
    if webhook.Type == "slack":
        return {
            "text": message,
            "blocks": [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": message}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Agent:* {agent_id}"},
                        {"type": "mrkdwn", "text": f"*Hostname:* {hostname}"},
                        {"type": "mrkdwn", "text": f"*Details:* {details.get('msg', 'N/A')}"}
                    ]
                }
            ]
        }
    elif webhook.Type == "discord":
        return {
            "content": f"{message}\n**Agent:** {agent_id}\n**Hostname:** {hostname}\n**Reason:** {details.get('msg', 'N/A')}"
        }
    else: # Generic
        return {
            "event": event_type,
            "timestamp": details.get("timestamp"),
            "agent": agent_id,
            "hostname": hostname,
            "data": details
        }
