from fastapi import APIRouter, Request, BackgroundTasks, Depends # type: ignore
from typing import Dict, Any
import logging
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from ...db.session import get_db # type: ignore

logger = logging.getLogger(__name__)

router = APIRouter()

async def process_syslog_payload(payload: dict, db: AsyncSession):
    """Processes incoming native syslog and WEF streams."""
    # In a real system, this maps raw OS logs to the Monitorix Unified Data Model
    logger.debug(f"[Agentless Receiver] Ingested native log event from {payload.get('source_ip')}")

@router.post("/receiver/syslog")
async def receive_syslog_stream(
    request: Request, 
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """
    [v2.3.0] High-Throughput HTTP Syslog Receiver
    Accepts real-time POST streams from Linux rsyslog or Windows WEF.
    """
    payload = await request.json()
    source_ip = request.client.host if request.client else "unknown"
    payload["source_ip"] = source_ip
    
    # Process asynchronously to free up the HTTP connection instantly
    background_tasks.add_task(process_syslog_payload, payload, db)
    
    return {"status": "accepted"}
