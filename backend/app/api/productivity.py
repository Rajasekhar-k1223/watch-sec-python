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
    
    for log in logs:
        proc = (log.get("ProcessName") or "").lower()
        title = (log.get("WindowTitle") or "").lower()
        duration = float(log.get("DurationSeconds", 0))
        
        is_prod = any(app in proc for app in productive_apps)
        is_unprod = any(app in proc or app in title for app in unproductive_apps)
        
        if is_prod:
            productive_seconds += duration
        elif is_unprod:
            unproductive_seconds += duration
        else:
             neutral_seconds += duration
             
    total = productive_seconds + unproductive_seconds + neutral_seconds
    score = 0
    if total > 0:
        score = int((productive_seconds / total) * 100)
        
    return {
        "AgentId": agent_id,
        "Score": score,
        "ProductiveSeconds": productive_seconds,
        "UnproductiveSeconds": unproductive_seconds,
        "NeutralSeconds": neutral_seconds,
        "TotalSeconds": total
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
