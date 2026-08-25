from fastapi import APIRouter, Depends, HTTPException, Header, Query
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
import json

from app.api.deps import get_current_user
from app.db.models import User, Agent, EventLog
from app.db.session import get_db

router = APIRouter()

class EventBusPayload(BaseModel):
    source_platform: str
    event_type: str
    data: dict

class SoarExecutePayload(BaseModel):
    agent_id: str
    playbook_id: int

def verify_federation_auth(current_user: User = Depends(get_current_user)):
    return current_user

@router.post("/event-bus")
async def ingest_federated_event(payload: EventBusPayload, user: User = Depends(verify_federation_auth)):
    print(f"[FEDERATION] Received {payload.event_type} from {payload.source_platform}")
    return {"status": "success", "message": "Event ingested"}

@router.get("/telemetry/stream")
async def stream_telemetry(
    agent_id: Optional[str] = Query(None, description="Filter by specific agent ID"),
    event_type: Optional[str] = Query(None, description="Filter by event type (e.g. 'Vulnerability Alert', 'FIM Alert', 'Network Anomaly')"),
    limit: int = Query(100, le=500),
    user: User = Depends(verify_federation_auth),
    db: AsyncSession = Depends(get_db)
):
    """
    [SDK] Real-time telemetry stream for SIEM & FIM integration.
    Returns the most recent security events (FIM, Network Anomalies, Process Alerts, Vulnerability Alerts)
    across the tenant's fleet. Used by RedRainbow for Detection phase.
    """
    query = select(EventLog).order_by(desc(EventLog.Timestamp))

    # Tenant isolation
    if user.Role != "SuperAdmin":
        agent_subquery = select(Agent.AgentId).where(Agent.TenantId == user.TenantId)
        result = await db.execute(agent_subquery)
        tenant_agent_ids = [row[0] for row in result.all()]
        if not tenant_agent_ids:
            return {"status": "success", "count": 0, "batch": []}
        query = query.where(EventLog.AgentId.in_(tenant_agent_ids))

    # Optional filters
    if agent_id:
        query = query.where(EventLog.AgentId == agent_id)
    if event_type:
        query = query.where(EventLog.Type == event_type)

    query = query.limit(limit)
    result = await db.execute(query)
    events = result.scalars().all()

    batch = []
    for ev in events:
        batch.append({
            "id": ev.Id,
            "agent_id": ev.AgentId,
            "type": ev.Type,
            "details": ev.Details,
            "severity": getattr(ev, "Severity", "Medium"),
            "timestamp": ev.Timestamp.isoformat() if ev.Timestamp else None,
            "is_alert": getattr(ev, "IsAlert", False),
        })

    return {"status": "success", "count": len(batch), "batch": batch}

@router.post("/soar/execute")
async def remote_soar_execute(
    payload: SoarExecutePayload,
    user: User = Depends(verify_federation_auth),
    db: AsyncSession = Depends(get_db)
):
    """
    [SDK] Triggers a SOAR playbook on a specific agent.
    The playbook_id maps to predefined remediation sequences in the portal.
    """
    # Verify agent belongs to the user's tenant
    agent_query = select(Agent).where(Agent.AgentId == payload.agent_id)
    if user.Role != "SuperAdmin":
        agent_query = agent_query.where(Agent.TenantId == user.TenantId)

    result = await db.execute(agent_query)
    agent = result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found or unauthorized")

    # Playbook dispatch map
    PLAYBOOKS = {
        1: {"action": "IsolateNetwork", "params": {}, "name": "Network Isolation"},
        2: {"action": "TriggerIOCScan", "params": {"TargetDirectory": "/", "Hashes": []}, "name": "Full IOC Scan"},
        3: {"action": "UnisolateNetwork", "params": {}, "name": "Network Restoration"},
        4: {"action": "TriggerForensicCollection", "params": {"OutputDirectory": "/tmp/monitorix_forensics"}, "name": "Forensic Collection"},
    }

    playbook = PLAYBOOKS.get(payload.playbook_id)
    if not playbook:
        raise HTTPException(status_code=400, detail=f"Unknown playbook_id {payload.playbook_id}. Valid: {list(PLAYBOOKS.keys())}")

    from app.socket_instance import sio_sync
    import hashlib, hmac
    from datetime import datetime

    timestamp = datetime.utcnow().isoformat()
    action = playbook["action"]
    params = playbook["params"]

    # Sign command
    tenant_result = await db.execute(
        select(__import__('app.db.models', fromlist=['Tenant']).Tenant).where(
            __import__('app.db.models', fromlist=['Tenant']).Tenant.Id == agent.TenantId
        )
    )
    tenant = tenant_result.scalars().first()
    machine_id = agent.MachineId or agent.AgentId
    if tenant:
        key_material = f"{action}|{json.dumps(params, sort_keys=True)}|{timestamp}"
        key = hashlib.sha256(tenant.ApiKey.encode() + machine_id.encode()).digest()
        signature = hmac.new(key, key_material.encode(), hashlib.sha256).hexdigest()
    else:
        signature = ""

    dispatch_payload = {
        "action": action,
        "params": params,
        "timestamp": timestamp,
        "signature": signature,
        "policy_name": playbook["name"]
    }
    sio_sync.emit('Remediation', dispatch_payload, room=payload.agent_id)

    print(f"[FEDERATION] {user.Username} triggered Playbook '{playbook['name']}' on Agent {payload.agent_id}")
    return {
        "status": "success",
        "playbook": playbook["name"],
        "agent_id": payload.agent_id,
        "action": action
    }
