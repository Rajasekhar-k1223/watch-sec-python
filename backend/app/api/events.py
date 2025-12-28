from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from datetime import datetime
from motor.motor_asyncio import AsyncIOMotorClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ..db.session import get_db, get_mongo_db
from ..db.models import Tenant
from ..schemas import SecurityEventLog, ActivityLog, ActivityLogDto
from .deps import get_current_user
from ..db.models import User

router = APIRouter()

from ..socket_instance import sio

# --- Security Events ---

@router.get("/{agent_id}", response_model=List[SecurityEventLog])
async def get_security_events(
    agent_id: str,
    mongo: AsyncIOMotorClient = Depends(get_mongo_db),
    current_user: User = Depends(get_current_user)
):
    # TODO: Add Tenant Scoping check here (Agent belongs to Tenant)
    
    db = mongo["watchsec"]
    collection = db["events"]
    
    cursor = collection.find({"AgentId": agent_id}).sort("Timestamp", -1).limit(100)
    events = await cursor.to_list(length=100)
    return events

@router.post("/simulate/{agent_id}")
async def simulate_event(
    agent_id: str,
    mongo: AsyncIOMotorClient = Depends(get_mongo_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.Role not in ["SuperAdmin", "TenantAdmin"]:
        raise HTTPException(status_code=403, detail="Not authorized")

    db = mongo["watchsec"]
    collection = db["events"]
    
    event = {
        "AgentId": agent_id,
        "Type": "Simulated Threat",
        "Details": "This is a test event triggered from the Python Backend.",
        "Timestamp": datetime.utcnow()
    }
    
    await collection.insert_one(event)
    return {"message": "Event Simulated"}

# --- Activity Logs ---

@router.get("/activity/{agent_id}", response_model=List[ActivityLog])
async def get_activity_logs(
    agent_id: str,
    mongo: AsyncIOMotorClient = Depends(get_mongo_db),
    current_user: User = Depends(get_current_user)
):
    db = mongo["watchsec"]
    collection = db["activity"]
    
    cursor = collection.find({"AgentId": agent_id}).sort("Timestamp", -1).limit(500)
    logs = await cursor.to_list(length=500)
    return logs

@router.post("/activity")
async def log_activity(
    dto: ActivityLogDto,
    db_sql: AsyncSession = Depends(get_db),
    mongo: AsyncIOMotorClient = Depends(get_mongo_db)
):
    # 1. Validate Tenant
    result = await db_sql.execute(select(Tenant).where(Tenant.ApiKey == dto.TenantApiKey))
    tenant = result.scalars().first()
    
    if not tenant:
        raise HTTPException(status_code=401, detail="Unauthorized Tenant")

    db_mongo = mongo["watchsec"]
    collection = db_mongo["activity"]

    log_entry = {
        "AgentId": dto.AgentId,
        "TenantId": tenant.Id,
        "ActivityType": dto.ActivityType,
        "WindowTitle": dto.WindowTitle,
        "ProcessName": dto.ProcessName,
        "Url": dto.Url,
        "DurationSeconds": dto.DurationSeconds,
        "Timestamp": dto.Timestamp
    }

    # AI Sentiment Analysis (Placeholder for future hook)
    # ...

    await collection.insert_one(log_entry)

    # Broadcast via Socket.IO
    await sio.emit('ReceiveEvent', {
        'agentId': dto.AgentId,
        'title': dto.ActivityType, # e.g. "Process Started", "File Modified"
        'details': f"{dto.ProcessName or ''} {dto.WindowTitle or dto.Url or ''}".strip(),
        'timestamp': dto.Timestamp.isoformat()
    })

    return {"status": "Logged"}
