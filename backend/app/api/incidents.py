import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, desc

from ..db.session import get_db
from ..db.models import EventLog, User, Agent
from .deps import get_current_active_user

router = APIRouter()
logger = logging.getLogger("IncidentHub")

@router.get("")
async def list_incidents(
    status: Optional[str] = "Open",
    severity: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """[v2.6.0] Forensic Incident Stream: Lists managed security cases with pagination and tenant isolation."""
    query = select(EventLog).order_by(desc(EventLog.Timestamp))
    
    if status:
        query = query.where(EventLog.Status == status)
    if severity:
        query = query.where(EventLog.Severity == severity)
        
    if user.Role != "SuperAdmin":
        res_agents = await db.execute(select(Agent.AgentId).where(Agent.TenantId == user.TenantId))
        tenant_agent_ids = [row[0] for row in res_agents.all()]
        if tenant_agent_ids:
            query = query.where(EventLog.AgentId.in_(tenant_agent_ids))
        else:
            return []
        
    query = query.limit(min(limit, 500)).offset(offset)
    result = await db.execute(query)
    return result.scalars().all()

@router.patch("/{incident_id}/resolve")
async def resolve_incident(
    incident_id: int,
    resolution_notes: str,
    status: str = "Resolved",
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """[v2.6.0] Incident Remediation: Resolves a security case with audit notes."""
    query = select(EventLog).where(EventLog.Id == incident_id)
    result = await db.execute(query)
    incident = result.scalar_one_or_none()
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    incident.Status = status
    incident.Details += f"\n\n--- RESOLUTION BY {user.Username} ---\n{resolution_notes}"
    
    await db.commit()
    logger.info(f"Incident {incident_id} marked as {status} by {user.Username}")
    return {"status": "success", "incident_id": incident_id}

@router.get("/summary")
async def get_incident_summary(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """[v2.6.0] SOC Resilience Summary: High-level metrics for the incident hub."""
    from sqlalchemy import func
    
    # Count open critical incidents
    crit_query = select(func.count(EventLog.Id)).where(
        EventLog.Status == "Open",
        EventLog.Severity == "Critical"
    )
    
    if user.Role != "SuperAdmin":
        res_agents = await db.execute(select(Agent.AgentId).where(Agent.TenantId == user.TenantId))
        tenant_agent_ids = [row[0] for row in res_agents.all()]
        if tenant_agent_ids:
            crit_query = crit_query.where(EventLog.AgentId.in_(tenant_agent_ids))
        else:
            return {
                "openCritical": 0,
                "totalActive": 0,
                "avgResolutionTime": "2.4h"
            }
        
    crit_result = await db.execute(crit_query)
    critical_count = crit_result.scalar() or 0
    
    return {
        "openCritical": critical_count,
        "totalActive": 0, # Placeholder for more complex aggregation
        "avgResolutionTime": "2.4h" # Simulated for UI
    }
