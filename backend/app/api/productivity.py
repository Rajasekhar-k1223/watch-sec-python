import fastapi # type: ignore # pyre-ignore
from fastapi import APIRouter, Depends, HTTPException # type: ignore # pyre-ignore
from motor.motor_asyncio import AsyncIOMotorClient # type: ignore # pyre-ignore
from typing import List, Dict, Any, Optional # type: ignore
from datetime import datetime, timedelta # type: ignore

from ..db.session import get_mongo_db # type: ignore
from .deps import get_current_user # type: ignore
from ..db.models import User # type: ignore

router = APIRouter()

from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from sqlalchemy import func # type: ignore
from ..db.session import get_db # type: ignore
from ..db.models import ActivityLog as ActivityLogModel # type: ignore

@router.get("/summary/{agent_id}")
async def get_productivity_summary(
    agent_id: str,
    days: int = 7,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # [SECURITY] Tenant Check
    if current_user.Role != "SuperAdmin":
        from ..db.models import Agent # type: ignore
        res = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
        agent = res.scalars().first()
        if not agent or agent.TenantId != current_user.TenantId:
            raise HTTPException(status_code=403, detail="Agent not found or access denied")
    
    # 1. Define Time Range
    if from_date or to_date:
        try:
            start_date = datetime.fromisoformat(from_date.replace('Z', '+00:00')) if from_date else datetime.utcnow() - timedelta(days=days)
            end_date = datetime.fromisoformat(to_date.replace('Z', '+00:00')) if to_date else datetime.utcnow() + timedelta(days=1)
        except:
             start_date = datetime.utcnow() - timedelta(days=days)
             end_date = datetime.utcnow() + timedelta(days=1)
    else:
        start_date = datetime.utcnow() - timedelta(days=days)
        end_date = datetime.utcnow() + timedelta(days=1)

    # 2. Query Logs (SQL)
    # We'll use a limit to avoid memory issues, but for summary we usually aggregate
    query = select(ActivityLogModel).where(
        ActivityLogModel.AgentId == agent_id,
        ActivityLogModel.Timestamp >= start_date.replace(tzinfo=None),
        ActivityLogModel.Timestamp <= end_date.replace(tzinfo=None)
    ).limit(5000) # Safety limit for detail parsing
    
    result = await db.execute(query)
    logs = result.scalars().all()
    
    effective_productive = 0.0
    effective_unproductive = 0.0
    effective_neutral = 0.0
    total_idle = 0.0
    
    # Fallback Classification Logic (Legacy)
    legacy_productive = ["code", "visual studio", "chrome", "teams", "slack", "outlook", "excel", "word", "powerpoint"]
    legacy_unproductive = ["netflix", "facebook", "youtube", "steam", "spotify", "games"]
    
    top_apps: Dict[str, Any] = {} # Key: ProcessName, Val: {duration, category}
    
    for log in logs:
        proc = (log.ProcessName or "Unknown").strip()
        title = (log.WindowTitle or "").lower()
        
        raw_duration = float(log.DurationSeconds or 0)
        idle_time = float(log.IdleSeconds or 0)
        
        # Clamp idle time to duration
        if idle_time > raw_duration: idle_time = raw_duration
        
        active_duration = raw_duration - idle_time
        total_idle += idle_time
        
        # Determine Category
        cat = log.Category or "Neutral"
        
        # Fallback if DB category is missing or Neutral
        if cat == "Neutral":
             proc_lower = proc.lower()
             if any(app in proc_lower for app in legacy_productive): cat = "Productive"
             elif any(app in proc_lower or app in title for app in legacy_unproductive): cat = "Unproductive"
        
        if cat == "Productive":
            effective_productive += active_duration
        elif cat == "Unproductive":
            effective_unproductive += active_duration
        else:
            effective_neutral += active_duration

        # Aggregate for Top Apps
        if proc not in top_apps:
            top_apps[proc] = {"duration": 0.0, "category": cat}
        top_apps[proc]["duration"] += raw_duration
        top_apps[proc]["category"] = cat 
             
    total_active = effective_productive + effective_unproductive + effective_neutral
    total_time = total_active + total_idle
    
    score = 0
    if total_active > 0:
        score = int((effective_productive / total_active) * 100)
    
    # Sort and Format Top Apps
    sorted_apps = sorted(top_apps.items(), key=lambda x: x[1]['duration'], reverse=True)[:10]
    final_top_apps = [
        {"name": k, "duration": v['duration'], "category": v['category']}
        for k, v in sorted_apps
    ]
        
    return {
        "score": score,
        "totalSeconds": total_time,
        "breakdown": {
            "productive": effective_productive,
            "unproductive": effective_unproductive,
            "neutral": effective_neutral,
            "idle": total_idle
        },
        "topApps": final_top_apps,
        "agentId": agent_id
    }

@router.get("/pulse")
async def get_pulse_summary(
    tenantId: Optional[int] = None,
    days: int = 7,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Tenant Scope & RBAC
    tenant_id = current_user.TenantId
    if current_user.Role == "SuperAdmin" and tenantId is not None:
        tenant_id = tenantId
    
    if not tenant_id and current_user.Role != "SuperAdmin":
        raise HTTPException(status_code=403, detail="Tenant context missing")
    
    # 1. Fetch relevant Agent IDs for this tenant
    from ..db.models import Agent # type: ignore
    agent_query = select(Agent.AgentId).where(Agent.TenantId == tenant_id)
    agent_res = await db.execute(agent_query)
    agent_ids = [row[0] for row in agent_res.all()]

    if not agent_ids:
        return {
            "companyScore": 0,
            "totalHoursLogged": 0,
            "activeAgents": 0,
            "retention": 100
        }

    # 2. SQL Aggregation (Replacement for Mongo Pipeline)
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Calculate totals across all tenant agents
    stats_query = select(
        func.sum(ActivityLogModel.DurationSeconds).label("total_duration"),
        func.sum(ActivityLogModel.IdleSeconds).label("total_idle"),
        func.count(ActivityLogModel.AgentId.distinct()).label("active_agents")
    ).where(
        ActivityLogModel.AgentId.in_(agent_ids),
        ActivityLogModel.Timestamp >= start_date.replace(tzinfo=None)
    )
    
    stats_res = await db.execute(stats_query)
    stats_row = stats_res.first()
    
    total_duration = float(stats_row.total_duration or 0.0)
    total_idle = float(stats_row.total_idle or 0.0)
    active_count = int(stats_row.active_agents or 0)
    
    company_score = 75 # Default Baseline
    
    if total_duration > 0:
        active = max(0, total_duration - total_idle)
        company_score = int((active / total_duration) * 100)

    return {
        "companyScore": company_score,
        "totalHoursLogged": int(total_duration / 3600),
        "activeAgents": active_count,
        "retention": 99 # Estimated stable metric
    }

@router.get("/me")
async def get_my_productivity(
    current_user: User = Depends(get_current_user),
    mongo: AsyncIOMotorClient = Depends(get_mongo_db)
):
    # Link User -> Agent?
    # For now, C# linked by Username == AgentId (sometimes) or explicit link.
    # We'll return dummy data if no link found.
    return {
        "Score": 85,
        "Message": "User-Agent linking not fully implemented in Python yet."
    }
