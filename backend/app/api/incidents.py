import json
import logging
import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Body, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from ..db.session import get_db
from ..db.models import EventLog, User, Agent, Incident, AuditLog
from .deps import get_current_active_user

router = APIRouter()
logger = logging.getLogger("IncidentHub")

# Allowed roles for incident write operations (RBAC)
INCIDENT_WRITE_ROLES = ["SuperAdmin", "Admin", "TenantAdmin", "Analyst"]


class CreateIncidentRequest(BaseModel):
    agent_id: str
    title: str
    description: str
    severity: str = "Medium"
    affected_agent_ids: Optional[List[str]] = None  # [v3.2.0] Multi-agent incidents
    affected_agents: Optional[List[str]] = None     # Alias for frontend callers
    tenant_id: Optional[int] = None                 # Explicitly accepted but overridden for security


class ResolveIncidentRequest(BaseModel):
    resolution_notes: Optional[str] = "Resolved by SOC Analyst"
    status: Optional[str] = "Resolved"


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
        "incident_id": inc.Id,
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


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_incident(
    req: CreateIncidentRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """
    [v3.2.0 Hardened] Create a new SOAR Incident linked to one or more agents.
    Enforces strict RBAC, authenticated user identity, tenant isolation, and audit logging.
    """
    # 1. RBAC Enforcement: Only Analysts and Admins can create incidents
    if user.Role not in INCIDENT_WRITE_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: Incident creation requires one of: {', '.join(INCIDENT_WRITE_ROLES)}"
        )

    # 2. Strict Tenant Isolation: Request body tenant_id CANNOT override user's assigned tenant
    query = select(Agent).where(Agent.AgentId == req.agent_id)
    if user.Role != "SuperAdmin":
        query = query.where(Agent.TenantId == user.TenantId)

    result = await db.execute(query)
    agent = result.scalars().first()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{req.agent_id}' not found or access denied"
        )

    # Enforce user tenant unless SuperAdmin explicitly targeting an agent's tenant
    tenant_id = user.TenantId if user.Role != "SuperAdmin" else (agent.TenantId or user.TenantId or 1)

    # 3. Filter affected agent IDs to preserve tenant boundary
    raw_affected = req.affected_agent_ids or req.affected_agents or []
    all_affected = list(set([req.agent_id] + raw_affected))
    
    if user.Role != "SuperAdmin" and len(all_affected) > 1:
        # Verify all affected agents belong to user's tenant
        valid_affected_q = select(Agent.AgentId).where(
            Agent.AgentId.in_(all_affected),
            Agent.TenantId == user.TenantId
        )
        valid_affected = (await db.execute(valid_affected_q)).scalars().all()
        all_affected = list(set([req.agent_id] + list(valid_affected)))

    # 4. Create Incident Record
    incident = Incident(
        AgentId=req.agent_id,
        AffectedAgentIdsJson=json.dumps(all_affected),
        TenantId=tenant_id,
        Title=req.title,
        Description=req.description,
        Severity=req.severity,
        Status="Open",
        CreatedDate=datetime.datetime.utcnow(),
        UpdateDate=datetime.datetime.utcnow()
    )
    db.add(incident)
    await db.flush()

    # 5. Security Audit Logging (Mandatory)
    audit = AuditLog(
        TenantId=tenant_id,
        Actor=user.Username,
        Action="IncidentCreated",
        Target=f"Incident #{incident.Id}",
        Details=f"Created incident '{incident.Title}' for agent {incident.AgentId} (Severity: {incident.Severity})",
        Timestamp=datetime.datetime.utcnow()
    )
    db.add(audit)
    await db.commit()
    await db.refresh(incident)

    # 6. Push SOAR Notification via Socket.IO
    try:
        from ..socket_instance import sio_sync
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
    except Exception as e:
        logger.warning(f"Failed to push Socket.IO notification for incident {incident.Id}: {e}")

    logger.info(f"Incident {incident.Id} created for agents: {all_affected} by {user.Username}")
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
    """[v3.2.0 Hardened] List SOAR Incidents with strict tenant-level data isolation."""
    query = select(Incident).order_by(desc(Incident.CreatedDate))

    if agent_id:
        query = query.where(Incident.AgentId == agent_id)
    if status:
        query = query.where(Incident.Status == status)
    if severity:
        query = query.where(Incident.Severity == severity)

    # Enforce tenant isolation for non-SuperAdmin
    if user.Role != "SuperAdmin":
        query = query.where(Incident.TenantId == user.TenantId)

    query = query.limit(min(limit, 500)).offset(offset)
    result = await db.execute(query)
    incidents = result.scalars().all()
    return [_serialize_incident(inc) for inc in incidents]


@router.get("/{incident_id}")
async def get_incident(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """[v3.2.0 Hardened] Retrieve single SOAR Incident by ID with tenant isolation."""
    query = select(Incident).where(Incident.Id == incident_id)
    if user.Role != "SuperAdmin":
        query = query.where(Incident.TenantId == user.TenantId)

    result = await db.execute(query)
    incident = result.scalar_one_or_none()

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found or access denied"
        )

    return _serialize_incident(incident)


@router.patch("/{incident_id}/resolve")
async def resolve_incident(
    incident_id: int,
    resolution_notes: Optional[str] = Query(None),
    status: Optional[str] = Query("Resolved"),
    body: Optional[ResolveIncidentRequest] = Body(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """
    [v3.2.0 Hardened] Resolves an Incident with audit notes and strict RBAC/tenant isolation.
    Supports both query parameters (legacy callers) and JSON body payload.
    """
    # 1. RBAC Check: Only Analysts and Admins can resolve incidents
    if user.Role not in INCIDENT_WRITE_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: Incident resolution requires one of: {', '.join(INCIDENT_WRITE_ROLES)}"
        )

    # 2. Strict Tenant Isolation Query
    query = select(Incident).where(Incident.Id == incident_id)
    if user.Role != "SuperAdmin":
        query = query.where(Incident.TenantId == user.TenantId)

    result = await db.execute(query)
    incident = result.scalar_one_or_none()

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found or access denied"
        )

    # Resolve parameters from body if provided, otherwise from query params
    effective_notes = (body.resolution_notes if body and body.resolution_notes else resolution_notes) or "Resolved by SOC Analyst"
    effective_status = (body.status if body and body.status else status) or "Resolved"

    incident.Status = effective_status
    incident.ResolutionNotes = effective_notes
    incident.UpdateDate = datetime.datetime.utcnow()

    # 3. Security Audit Log
    audit = AuditLog(
        TenantId=incident.TenantId,
        Actor=user.Username,
        Action="IncidentResolved",
        Target=f"Incident #{incident_id}",
        Details=f"Marked incident #{incident_id} as {effective_status} with notes: {effective_notes}",
        Timestamp=datetime.datetime.utcnow()
    )
    db.add(audit)
    await db.commit()

    logger.info(f"Incident {incident_id} marked as {effective_status} by {user.Username}")
    return {"status": "success", "incident_id": incident_id, "resolution_status": effective_status}


@router.get("/summary")
async def get_incident_summary(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """SOC Resilience Summary: High-level incident metrics with tenant isolation."""
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
