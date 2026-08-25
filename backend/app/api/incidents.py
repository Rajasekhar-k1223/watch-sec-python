import json
import logging
import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from ..db.session import get_db
from ..db.models import EventLog, User, Agent, Incident
from .deps import get_current_active_user

router = APIRouter()
logger = logging.getLogger("IncidentHub")


class CreateIncidentRequest(BaseModel):
    agent_id: str
    title: str
    description: str
    severity: str = "Medium"
    affected_agent_ids: Optional[List[str]] = None  # [v3.2.0] Multi-agent incidents


def _serialize_incident(inc: Incident) -> dict:
    """Serialize an Incident ORM object to a JSON-safe dict, including affected_agent_ids."""
    affected = []
    if inc.AffectedAgentIdsJson:
        try:
            affected = json.loads(inc.AffectedAgentIdsJson)
        except Exception:
            pass
    return {
        "id": inc.Id,
        "agentId": inc.AgentId,
        "affectedAgentIds": affected,
        "tenantId": inc.TenantId,
        "title": inc.Title,
        "description": inc.Description,
        "severity": inc.Severity,
        "status": inc.Status,
        "createdDate": inc.CreatedDate.isoformat() if inc.CreatedDate else None,
        "updateDate": inc.UpdateDate.isoformat() if inc.UpdateDate else None,
        "resolutionNotes": inc.ResolutionNotes,
    }


@router.post("")
async def create_incident(
    req: CreateIncidentRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """
    [v3.2.0] Create a new SOAR Incident linked to one or more agents.
    Pushes a SOARIncident notification to the primary agent via Socket.IO.
    """
    from ..socket_instance import sio_sync

    # Validate primary agent
    query = select(Agent).where(Agent.AgentId == req.agent_id)
    if user.Role != "SuperAdmin":
        query = query.where(Agent.TenantId == user.TenantId)

    result = await db.execute(query)
    agent = result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Primary agent not found")

    # Build affected agent ID list (include primary agent)
    all_affected = list(set([req.agent_id] + (req.affected_agent_ids or [])))

    incident = Incident(
        AgentId=req.agent_id,
        AffectedAgentIdsJson=json.dumps(all_affected),
        TenantId=agent.TenantId,
        Title=req.title,
        Description=req.description,
        Severity=req.severity,
        Status="Open"
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)

    # Push SOARIncident notification to ALL affected agents
    incident_payload = {
        "action": "SOARIncident",
        "params": {
            "IncidentId": incident.Id,
            "Title": req.title,
            "Description": req.description,
            "Severity": req.severity,
            "AffectedAgentIds": all_affected
        },
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "signature": "",
        "policy_name": "SOAR Integration"
    }
    for aid in all_affected:
        sio_sync.emit('Remediation', incident_payload, room=aid)

    logger.info(f"Incident {incident.Id} created for agents: {all_affected}")
    return _serialize_incident(incident)


@router.get("")
async def list_incidents(
    agent_id: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """[v3.2.0] List SOAR Incidents from the Incidents table with full multi-agent data."""
    query = select(Incident).order_by(desc(Incident.CreatedDate))

    if agent_id:
        query = query.where(Incident.AgentId == agent_id)
    if status:
        query = query.where(Incident.Status == status)
    if severity:
        query = query.where(Incident.Severity == severity)

    if user.Role != "SuperAdmin":
        query = query.where(Incident.TenantId == user.TenantId)

    query = query.limit(min(limit, 500)).offset(offset)
    result = await db.execute(query)
    incidents = result.scalars().all()
    return [_serialize_incident(inc) for inc in incidents]


@router.patch("/{incident_id}/resolve")
async def resolve_incident(
    incident_id: int,
    resolution_notes: str,
    status: str = "Resolved",
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """Resolves an Incident with audit notes."""
    query = select(Incident).where(Incident.Id == incident_id)
    if user.Role != "SuperAdmin":
        query = query.where(Incident.TenantId == user.TenantId)

    result = await db.execute(query)
    incident = result.scalar_one_or_none()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.Status = status
    incident.ResolutionNotes = resolution_notes
    await db.commit()
    logger.info(f"Incident {incident_id} marked as {status} by {user.Username}")
    return {"status": "success", "incident_id": incident_id}


@router.get("/summary")
async def get_incident_summary(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """SOC Resilience Summary: High-level incident metrics."""
    base_q = select(func.count(Incident.Id))
    if user.Role != "SuperAdmin":
        base_q = base_q.where(Incident.TenantId == user.TenantId)

    open_crit = await db.execute(base_q.where(Incident.Status == "Open", Incident.Severity == "Critical"))
    total_open = await db.execute(base_q.where(Incident.Status == "Open"))

    return {
        "openCritical": open_crit.scalar() or 0,
        "totalActive": total_open.scalar() or 0,
        "avgResolutionTime": "N/A"
    }
