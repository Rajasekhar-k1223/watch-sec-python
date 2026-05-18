from fastapi import APIRouter, Depends, HTTPException, Query # type: ignore
from typing import List, Optional # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from sqlalchemy import desc, union_all, literal_column # type: ignore
from datetime import datetime # type: ignore

from ..db.session import get_db # type: ignore
from ..db.models import AuditLog, EventLog, Agent, User # type: ignore
from .deps import get_current_user # type: ignore

router = APIRouter()

@router.get("")
@router.get("/")
async def get_audit_logs(
    tenantId: Optional[int] = None,
    limit: int = 100,
    include_agents: bool = Query(False),
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    date_range: Optional[str] = None,
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    # RBAC & Filtering
    target_tenant_id = None
    if current_user.Role == "SuperAdmin":
        target_tenant_id = tenantId
    elif current_user.Role == "TenantAdmin":
        target_tenant_id = current_user.TenantId
    else:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # [NEW] Handle Date Range
    from datetime import timedelta # type: ignore
    if date_range:
        now = datetime.utcnow()
        if date_range == "24h":
            start_date = (now - timedelta(hours=24)).isoformat()
        elif date_range == "7d":
            start_date = (now - timedelta(days=7)).isoformat()
        elif date_range == "30d":
            start_date = (now - timedelta(days=30)).isoformat()

    # [FIX] Parse Dates
    start_dt = None
    end_dt = None
    if start_date:
        try:
            start_dt = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
        except:
             pass
    if end_date:
        try:
            end_dt = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
        except:
             pass

    if not include_agents:
        # Standard Admin Audit Logs
        query = select(AuditLog)
        if target_tenant_id:
            query = query.where(AuditLog.TenantId == target_tenant_id)
        if start_dt:
            query = query.where(AuditLog.Timestamp >= start_dt)
        if end_dt:
            query = query.where(AuditLog.Timestamp <= end_dt)

        query = query.order_by(desc(AuditLog.Timestamp)).limit(limit)
        result = await db.execute(query)
        return result.scalars().all()
    else:
        # UNIFIED VIEW (AuditLog + EventLog)
        # Note: EventLog doesn't have TenantId, we must join with Agents
        
        # 1. Admin Logs
        q_admin = select(
            AuditLog.Id.label("Id"),
            literal_column("'User'").label("ActorType"),
            AuditLog.Actor.label("Actor"),
            AuditLog.Action.label("Action"),
            AuditLog.Details.label("Details"),
            AuditLog.Timestamp.label("Timestamp")
        )
        if target_tenant_id:
            q_admin = q_admin.where(AuditLog.TenantId == target_tenant_id)
        if start_dt:
            q_admin = q_admin.where(AuditLog.Timestamp >= start_dt)
        if end_dt:
            q_admin = q_admin.where(AuditLog.Timestamp <= end_dt)

        # 2. Agent Logs (EventLog)
        q_agent = select(
            EventLog.Id.label("Id"),
            literal_column("'Agent'").label("ActorType"),
            EventLog.AgentId.label("Actor"),
            EventLog.Type.label("Action"),
            EventLog.Details.label("Details"),
            EventLog.Timestamp.label("Timestamp")
        ).join(Agent, Agent.AgentId == EventLog.AgentId)
        
        if target_tenant_id:
            q_agent = q_agent.where(Agent.TenantId == target_tenant_id)
        if start_dt:
            q_agent = q_agent.where(EventLog.Timestamp >= start_dt)
        if end_dt:
            q_agent = q_agent.where(EventLog.Timestamp <= end_dt)

        # Combine
        combined_query = q_admin.union_all(q_agent).order_by(desc(literal_column("Timestamp"))).limit(limit)
        
        result = await db.execute(combined_query)
        # Return as list of dicts for union
        return [dict(row._mapping) for row in result.all()]
