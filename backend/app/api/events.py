from fastapi import APIRouter, Depends, HTTPException, status
from ..tasks.general import analyze_risk_background
from typing import List
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ..db.session import get_db, get_mongo_db
from ..db.models import Tenant, EventLog, ActivityLog as ActivityLogModel
from ..schemas import SecurityEventLog, ActivityLog, ActivityLogDto
from .deps import get_current_user
from ..db.models import User
from ..db.models import User
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel

router = APIRouter()

from ..socket_instance import sio

# --- Security Events ---

@router.get("/{agent_id}", response_model=List[SecurityEventLog])
async def get_security_events(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(EventLog).where(EventLog.AgentId == agent_id).order_by(EventLog.Timestamp.desc()).limit(100)
    result = await db.execute(query)
    events = result.scalars().all()
    
    # Map to schema
    return [
        {
            "AgentId": e.AgentId,
            "Type": e.Type,
            "Details": e.Details,
            "Timestamp": e.Timestamp        }
        for e in events
    ]

@router.post("/simulate/{agent_id}")
async def simulate_event(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.Role not in ["SuperAdmin", "TenantAdmin"]:
        raise HTTPException(status_code=403, detail="Not authorized")

    event = EventLog(
        AgentId=agent_id,
        Type="Simulated Threat",
        Details="This is a test event triggered from the Python Backend.",
        Timestamp=datetime.utcnow()
    )
    
    db.add(event)
    await db.commit()
    return {"message": "Event Simulated"}

# --- Generic Event Reporting (USB, Network, Etc) ---
class SecurityEventDto(BaseModel):
    AgentId: str
    TenantApiKey: str
    Type: str
    Details: str
    Timestamp: datetime

@router.post("/report")
async def report_event(
    dto: SecurityEventDto,
    db: AsyncSession = Depends(get_db)
):
    # 1. Validate Tenant
    result = await db.execute(select(Tenant).where(Tenant.ApiKey == dto.TenantApiKey))
    tenant = result.scalars().first()
    
    if not tenant:
        raise HTTPException(status_code=401, detail="Unauthorized Tenant")

    # 2. Log to SQL
    event = EventLog(
        AgentId=dto.AgentId,
        Type=dto.Type,
        Details=dto.Details,
        Timestamp=dto.Timestamp
    )
    db.add(event)
    await db.commit()
    
    # 3. Realtime Alert via Socket
    # Broadcast to specific Tenant Room
    if tenant:
        await sio.emit('ReceiveEvent', {
            'agentId': dto.AgentId,
            'type': dto.Type, 
            'details': dto.Details,
            'timestamp': dto.Timestamp.isoformat()
        }, room=f"tenant_{tenant.Id}")
    
    return {"status": "Logged"}

# --- Activity Logs ---

@router.get("/activity/{agent_id}", response_model=List[ActivityLogDto])
async def get_activity_logs(
    agent_id: str,
    mongo: AsyncIOMotorClient = Depends(get_mongo_db),
    current_user: User = Depends(get_current_user)
):
    try:
        db = mongo["watchsec"]
        collection = db["activity"]
        
        cursor = collection.find({"AgentId": agent_id}).sort("Timestamp", -1).limit(500)
        logs = await cursor.to_list(length=500)
        
        return [
            {
                "AgentId": l.get("AgentId"),
                "TenantId": l.get("TenantId"),
                "ActivityType": l.get("ActivityType"),
                "ProcessName": l.get("ProcessName"),
                "WindowTitle": l.get("WindowTitle"),
                "Url": l.get("Url"),
                "DurationSeconds": l.get("DurationSeconds", 0),
                "RiskScore": l.get("RiskScore", 0),
                "RiskLevel": l.get("RiskLevel", "Normal"),
                "Timestamp": l.get("Timestamp")
            }
            for l in logs
        ]
    except Exception as e:
        print(f"Error fetching logs from Mongo: {e}")
        return []

def analyze_risk(title: str, process: str, url: str):
    score = 0
    level = "Normal"
    
    text = (f"{title} {process} {url}").lower()
    
    high_risk = ["terminal", "powershell", "cmd", "nmap", "wireshark", "tor browser", "metasploit"]
    if any(k in text for k in high_risk):
        score = 80
        level = "High"
    
    unproductive = ["youtube", "facebook", "netflix", "instagram", "tiktok", "steam"]
    if any(k in text for k in unproductive):
        score = 10
        level = "Unproductive"
        
    return score, level

@router.post("/activity")
async def log_activity(
    dto: ActivityLogDto,
    db: AsyncSession = Depends(get_db)
):
    # 1. Validate Tenant
    result = await db.execute(select(Tenant).where(Tenant.ApiKey == dto.TenantApiKey))
    tenant = result.scalars().first()
    
    if not tenant:
        raise HTTPException(status_code=401, detail="Unauthorized Tenant")

    # Perform Analysis
    risk_score, risk_level = analyze_risk(dto.WindowTitle, dto.ProcessName, dto.Url or "")
    
    # Insert Record
    # Insert Record (MongoDB)
    try:
        from ..db.session import mongo_client
        db_mongo = mongo_client["watchsec"]
        collection = db_mongo["activity"]
        
        log_entry = dto.model_dump()
        log_entry["TenantId"] = tenant.Id
        log_entry["RiskScore"] = risk_score
        log_entry["RiskLevel"] = risk_level
        # Ensure Timestamp is handled correctly if needed by Mongo driver
        
        await collection.insert_one(log_entry)
        
        # Optionally trigger Celery Analysis here passing str(inserted_id)
        # analyze_risk_background.delay(str(res.inserted_id), ...)
        
    except Exception as e:
        print(f"Error logging activity to Mongo: {e}")
        raise HTTPException(status_code=500, detail="Log Error")

    # Broadcast via Socket.IO -> TENANT ROOM
    if tenant:
        room_name = f"tenant_{tenant.Id}"
        
        await sio.emit('ReceiveEvent', {
            'agentId': dto.AgentId,
            'title': dto.ActivityType,
            'details': f"{dto.ProcessName or ''} {dto.WindowTitle or dto.Url or ''}".strip(),
            'timestamp': dto.Timestamp.isoformat()
        }, room=room_name)
        
        # Broadcast Detailed Activity for Realtime Logs
        await sio.emit('new_client_activity', {
            'AgentId': dto.AgentId,
            'ActivityType': dto.ActivityType,
            'ProcessName': dto.ProcessName,
            'WindowTitle': dto.WindowTitle,
            'Url': dto.Url,
            'DurationSeconds': dto.DurationSeconds,
            'RiskLevel': risk_level,
            'Timestamp': dto.Timestamp.isoformat()
        }, room=room_name)

    return {"status": "Logged"}
