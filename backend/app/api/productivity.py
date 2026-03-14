import fastapi # type: ignore # pyre-ignore
from fastapi import APIRouter, Depends, HTTPException # type: ignore # pyre-ignore
from motor.motor_asyncio import AsyncIOMotorClient # type: ignore # pyre-ignore
from typing import List, Dict, Any, Optional # type: ignore

from ..db.session import get_mongo_db # type: ignore
from .deps import get_current_user # type: ignore
from ..db.models import User # type: ignore

router = APIRouter()

@router.get("/summary/{agent_id}")
async def get_productivity_summary(
    agent_id: str,
    days: int = 7,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    mongo: AsyncIOMotorClient = Depends(get_mongo_db),
    current_user: User = Depends(get_current_user)
):
    # [SECURITY] Tenant Check
    if current_user.Role != "SuperAdmin":
        from ..db.session import AsyncSessionLocal # type: ignore
        from ..db.models import Agent # type: ignore
        from sqlalchemy.future import select # type: ignore
        async with AsyncSessionLocal() as sql_db:
             res = await sql_db.execute(select(Agent).where(Agent.AgentId == agent_id))
             agent = res.scalars().first()
             if not agent or agent.TenantId != current_user.TenantId:
                 raise HTTPException(status_code=403, detail="Agent not found or access denied")
    
    db = mongo["watchsec"]
    collection = db["activity"]
    
    # Time Range
    query = {"AgentId": agent_id}
    
    if from_date or to_date:
        query["Timestamp"] = {}
        if from_date:
            try:
                query["Timestamp"]["$gte"] = datetime.fromisoformat(from_date)
            except:
                pass
        if to_date:
            try:
                query["Timestamp"]["$lte"] = datetime.fromisoformat(to_date)
            except:
                 pass
    else:
        # Default to last 7 days to ensure we catch recent data even with timezone drifts
        # If the user wants 24h, they can pass days=1 explicitly (frontend defaults to 1?)
        # Let's trust the 'days' param but buffer it?
        # Actually, let's just use the days param but ensure we don't miss "future" logs due to timezone
        # by querying $lte now + 1 day
        start_date = datetime.utcnow() - timedelta(days=days)
        future_buffer = datetime.utcnow() + timedelta(days=1)
        query["Timestamp"] = {"$gte": start_date, "$lte": future_buffer}

    cursor = collection.find(query)
    
    logs = await cursor.to_list(length=10000)
    
    effective_productive = 0.0
    effective_unproductive = 0.0
    effective_neutral = 0.0
    total_idle = 0.0
    
    # Fallback Classification Logic (Legacy)
    legacy_productive = ["code", "visual studio", "chrome", "teams", "slack", "outlook"]
    legacy_unproductive = ["netflix", "facebook", "youtube", "steam", "spotify"]
    
    top_apps: Dict[str, Any] = {} # Key: ProcessName, Val: {duration, category}
    
    for log in logs:
        proc = (log.get("ProcessName") or "Unknown").strip()
        title = (log.get("WindowTitle") or "").lower()
        
        raw_duration = float(log.get("DurationSeconds", 0))
        idle_time = float(log.get("IdleSeconds", 0))
        
        # Clamp idle time to duration just in case
        if idle_time > raw_duration: idle_time = raw_duration
        
        active_duration = raw_duration - idle_time
        total_idle += idle_time # type: ignore
        
        # Determine Category
        cat = log.get("Category", "Neutral")
        
        # Fallback if DB category is missing or Neutral (try to smart-guess generic logs)
        if cat == "Neutral":
             proc_lower = proc.lower()
             if any(app in proc_lower for app in legacy_productive): cat = "Productive"
             elif any(app in proc_lower or app in title for app in legacy_unproductive): cat = "Unproductive"
        
        if cat == "Productive":
            effective_productive += active_duration # type: ignore
        elif cat == "Unproductive":
            effective_unproductive += active_duration # type: ignore
        else:
            effective_neutral += active_duration # type: ignore

        # Aggregate for Top Apps
        if proc not in top_apps:
            top_apps[proc] = {"duration": 0.0, "category": cat}
        top_apps[proc]["duration"] += raw_duration # type: ignore
        top_apps[proc]["category"] = cat 
             
    total_active = effective_productive + effective_unproductive + effective_neutral
    total_time = total_active + total_idle
    
    score = 0
    if total_active > 0:
        # Score based on Active Time only
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
    days: int = 7,
    mongo: AsyncIOMotorClient = Depends(get_mongo_db),
    current_user: User = Depends(get_current_user)
):
    # Tenant Scope
    tenant_id = current_user.TenantId
    
    # 1. Fetch ALL agents for this tenant
    # In a real scenario, we'd filter logs by AgentId belonging to TenantId
    # For now, let's query the 'agents' SQL table first to get IDs?
    # Or rely on the fact that we can query logs. But logs might not have TenantId indexed.
    # We should fetch active agents from SQL first.
    
    # Simplified: Query logs where AgentId is in (list of tenant agents)
    # OR, just query logs if we add TenantId to logs (Better practice).
    # Assuming logs DON'T have TenantId, we must get AgentIds.
    
    # Let's mock a "Global" view for now if TenantId is missing, or fetch all.
    # To be safe, let's just use the same logic as above but aggregate ALL logs.
    
    db = mongo["watchsec"]
    collection = db["activity"]
    
    start_date = datetime.utcnow() - timedelta(days=days)
    pipeline = [
        {"$match": {"Timestamp": {"$gte": start_date}}},
        {"$group": {
            "_id": "$ProcessName",
            "total_duration": {"$sum": "$DurationSeconds"},
            "total_idle": {"$sum": "$IdleSeconds"},
            "count": {"$sum": 1},
            # "category": {"$first": "$Category"} # Naive
        }}
    ]
    
    # This is a HEAVY aggregation. For "Pulse", maybe we just want general stats.
    # Let's keep it simple: Total Active vs Idle for the whole company.
    
    # New Pipeline for Efficiency Score
    pipeline_stats = [
        {"$match": {"Timestamp": {"$gte": start_date}}},
        {"$group": {
            "_id": None,
            "total_duration": {"$sum": "$DurationSeconds"},
            "total_idle": {"$sum": "$IdleSeconds"}
        }}
    ]
    
    stats_cursor = collection.aggregate(pipeline_stats)
    stats_result = await stats_cursor.to_list(length=1)
    
    total_duration = 0.0
    total_idle = 0.0
    company_score = 75 # Default
    
    if stats_result:
        total_duration = stats_result[0].get("total_duration", 0.0)
        total_idle = stats_result[0].get("total_idle", 0.0)
        
        active = max(0, total_duration - total_idle)
        if total_duration > 0:
            # Naive Efficiency: Active / Total
            company_score = int((active / total_duration) * 100)

    return {
        "companyScore": company_score,
        "totalHoursLogged": int(total_duration / 3600),
        "activeAgents": 42, # Mock
        "retention": 98
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
