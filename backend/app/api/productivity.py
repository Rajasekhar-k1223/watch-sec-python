from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorClient
from typing import List, Dict, Any
from datetime import datetime, timedelta

from ..db.session import get_mongo_db
from .deps import get_current_user
from ..db.models import User

router = APIRouter()

@router.get("/summary/{agent_id}")
async def get_productivity_summary(
    agent_id: str,
    days: int = 1,
    mongo: AsyncIOMotorClient = Depends(get_mongo_db),
    current_user: User = Depends(get_current_user)
):
    # TODO: Tenant Check
    
    db = mongo["watchsec"]
    collection = db["activity"]
    
    # Time Range
    start_date = datetime.utcnow() - timedelta(days=days)
    
    cursor = collection.find({
        "AgentId": agent_id,
        "Timestamp": {"$gte": start_date}
    })
    
    logs = await cursor.to_list(length=10000)
    
    productive_seconds = 0.0
    unproductive_seconds = 0.0
    neutral_seconds = 0.0
    
    # Basic Classification Logic (Mock)
    productive_apps = ["code", "visual studio", "chrome", "teams", "slack", "outlook"]
    unproductive_apps = ["netflix", "facebook", "youtube", "steam", "spotify"]
    
    top_apps = {} # Key: ProcessName, Val: {duration, category}
    
    for log in logs:
        proc = (log.get("ProcessName") or "Unknown").strip()
        title = (log.get("WindowTitle") or "").lower()
        duration = float(log.get("DurationSeconds", 0))
        
        # Categorize
        cat = "Neutral"
        proc_lower = proc.lower()
        
        is_prod = any(app in proc_lower for app in productive_apps)
        is_unprod = any(app in proc_lower or app in title for app in unproductive_apps)
        
        if is_prod:
            cat = "Productive"
            productive_seconds += duration
        elif is_unprod:
            cat = "Unproductive"
            unproductive_seconds += duration
        else:
            cat = "Neutral"
            neutral_seconds += duration

        # Aggregate for Top Apps
        if proc not in top_apps:
            top_apps[proc] = {"duration": 0.0, "category": cat}
        top_apps[proc]["duration"] += duration
        # Update category if it changes (simple heuristic: allow overwrite or stick to first? stick to calc)
        top_apps[proc]["category"] = cat 
             
    total = productive_seconds + unproductive_seconds + neutral_seconds
    score = 0
    if total > 0:
        score = int((productive_seconds / total) * 100)
        
    # Sort and Format Top Apps
    sorted_apps = sorted(top_apps.items(), key=lambda x: x[1]['duration'], reverse=True)[:10]
    final_top_apps = [
        {"name": k, "duration": v['duration'], "category": v['category']}
        for k, v in sorted_apps
    ]
        
    return {
        "score": score,
        "totalSeconds": total,
        "breakdown": {
            "productive": productive_seconds,
            "unproductive": unproductive_seconds,
            "neutral": neutral_seconds
        },
        "topApps": final_top_apps,
        "agentId": agent_id
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
