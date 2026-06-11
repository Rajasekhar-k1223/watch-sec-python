import logging
from ..core.celery_app import celery_app # type: ignore
from ..services.agentless_engine import agentless_engine # type: ignore
from ..db.session import AsyncSessionLocal # type: ignore
import asyncio

logger = logging.getLogger(__name__)

@celery_app.task(name="tasks.agentless.poll_endpoints")
def poll_all_agentless_endpoints():
    """
    [v2.2.0] Background Task: Polls all configured agentless endpoints.
    Runs asynchronously inside Celery.
    """
    logger.info("[v2.2.0] Background Task: Polling Agentless Endpoints...")
    
    async def _run_poll():
        from sqlalchemy.future import select
        from ..db.models import AgentlessEndpoint, AgentlessCredential
        
        endpoints_data = []
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(AgentlessEndpoint))
            for ep in result.scalars().all():
                cred_res = await db.execute(select(AgentlessCredential).where(AgentlessCredential.EndpointId == ep.Id))
                if cred_res.scalars().first(): # Only poll if we have credentials linked
                    endpoints_data.append({"ip": ep.IpAddress, "os": ep.OsType, "cred": "vault-default"})
        
        
        for ep in endpoints_data:
            try:
                if ep["os"] == "Linux":
                    data = await agentless_engine.poll_linux_ssh(ep["ip"], ep["cred"])
                else:
                    data = await agentless_engine.poll_windows_wmi(ep["ip"], ep["cred"])
                
                logger.info(f"[Agentless] Successfully polled {ep['ip']} - found {len(data['processes'])} processes.")
            except Exception as e:
                logger.error(f"[Agentless] Failed to poll {ep['ip']}: {e}")

    loop = asyncio.get_event_loop()
    loop.run_until_complete(_run_poll())
