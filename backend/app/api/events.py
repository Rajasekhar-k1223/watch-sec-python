from fastapi import APIRouter, Depends, HTTPException, status
from ..tasks.general import analyze_risk_background
from typing import List
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ..db.session import get_db
from ..db.models import Tenant, EventLog, ActivityLog as ActivityLogModel
from ..schemas import SecurityEventLog, ActivityLog, ActivityLogDto
from .deps import get_current_user
from ..db.models import User

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

# --- Activity Logs ---

@router.get("/activity/{agent_id}", response_model=List[ActivityLog])
async def get_activity_logs(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(ActivityLogModel).where(ActivityLogModel.AgentId == agent_id).order_by(ActivityLogModel.Timestamp.desc()).limit(500)
    result = await db.execute(query)
    logs = result.scalars().all()
    
    # Map manually to match schema ActivityLog
    return [
        {
            "AgentId": l.AgentId,
            "TenantId": l.TenantId,
            "ActivityType": l.ActivityType,
            "ProcessName": l.ProcessName,
            "WindowTitle": l.WindowTitle,
            "Url": l.Url,
            "DurationSeconds": l.DurationSeconds,
            "RiskScore": l.RiskScore,
            "RiskLevel": l.RiskLevel,
            "Timestamp": l.Timestamp
        }
        for l in logs
    ]

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
    new_log = ActivityLogModel(
        AgentId=dto.AgentId,
        TenantId=tenant.Id,
        ActivityType=dto.ActivityType,
        WindowTitle=dto.WindowTitle,
        ProcessName=dto.ProcessName,
        Url=dto.Url,
        DurationSeconds=dto.DurationSeconds,
        RiskScore=risk_score,
        RiskLevel=risk_level,
        Timestamp=dto.Timestamp
    )
    
    db.add(new_log)
    await db.commit()

    # Broadcast via Socket.IO
    await sio.emit('ReceiveEvent', {
        'agentId': dto.AgentId,
        'title': dto.ActivityType,
        'details': f"{dto.ProcessName or ''} {dto.WindowTitle or dto.Url or ''}".strip(),
        'timestamp': dto.Timestamp.isoformat()
    })
    
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
    })

    return {"status": "Logged"}
