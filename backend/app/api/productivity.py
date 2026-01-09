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
    
    effective_productive = 0.0
    effective_unproductive = 0.0
    effective_neutral = 0.0
    total_idle = 0.0
    
    # Fallback Classification Logic (Legacy)
    legacy_productive = ["code", "visual studio", "chrome", "teams", "slack", "outlook"]
    legacy_unproductive = ["netflix", "facebook", "youtube", "steam", "spotify"]
    
    top_apps = {} # Key: ProcessName, Val: {duration, category}
    
    for log in logs:
        proc = (log.get("ProcessName") or "Unknown").strip()
        title = (log.get("WindowTitle") or "").lower()
        
        raw_duration = float(log.get("DurationSeconds", 0))
        idle_time = float(log.get("IdleSeconds", 0))
        
        # Clamp idle time to duration just in case
        if idle_time > raw_duration: idle_time = raw_duration
        
        active_duration = raw_duration - idle_time
        total_idle += idle_time
        
        # Determine Category
        cat = log.get("Category", "Neutral")
        
        # Fallback if DB category is missing or Neutral (try to smart-guess generic logs)
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
        top_apps[proc]["duration"] += raw_duration # Use RAW duration for "Time Open"
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
