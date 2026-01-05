from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
import csv
import io
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseModel
from datetime import datetime
from typing import Optional
import json

from ..db.session import get_db
from ..db.models import Agent, AgentReportEntity, Tenant, User, ActivityLog as ActivityLogModel
from ..socket_instance import sio # Import Socket.IO server instance
from .deps import get_current_user

router = APIRouter()

# --- History Endpoint ---
@router.get("/history/{agent_id}")
async def get_agent_history(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: "User" = Depends(get_current_user)
):
    query = select(AgentReportEntity).where(AgentReportEntity.AgentId == agent_id).order_by(AgentReportEntity.Timestamp.desc()).limit(100)
    result = await db.execute(query)
    history = result.scalars().all()
    return history


# DTO (Pydantic Model)
class AgentReportDto(BaseModel):
    AgentId: str
    Status: str
    CpuUsage: float
    MemoryUsage: float
    Timestamp: datetime
    TenantApiKey: str
    Hostname: Optional[str] = None
    InstalledSoftwareJson: Optional[str] = None
    LocalIp: Optional[str] = None
    Gateway: Optional[str] = None

@router.post("/report")
async def receive_report(dto: AgentReportDto, request: Request, db: AsyncSession = Depends(get_db)):
    print(f"[API] Received Report from {dto.AgentId}")

    # 1. Authenticate Tenant
    result = await db.execute(select(Tenant).where(Tenant.ApiKey == dto.TenantApiKey))
    tenant = result.scalars().first()

    if not tenant:
        print(f"[API] Unauthorized Tenant Key: {dto.TenantApiKey}")
        raise HTTPException(status_code=401, detail="Unauthorized Tenant")

    # 2. Insert Report History
    new_report = AgentReportEntity(
        AgentId=dto.AgentId,
        TenantId=tenant.Id,
        Status=dto.Status,
        CpuUsage=dto.CpuUsage,
        MemoryUsage=dto.MemoryUsage,
        Timestamp=dto.Timestamp
    )
    db.add(new_report)

    # 3. Sync Agent Config (Persistent Entity)
    result = await db.execute(select(Agent).where(Agent.AgentId == dto.AgentId))
    agent = result.scalars().first()

    # Extract Public IP
    client_ip = request.client.host if request.client else "Unknown"

    status_msg = "Updated"

    if not agent:
        # Check Agent Limit (Plan Enforcement)
        from sqlalchemy import func
        limit_res = await db.execute(select(func.count()).select_from(Agent).where(Agent.TenantId == tenant.Id))
        current_count = limit_res.scalar()
        
        if current_count >= tenant.AgentLimit:
            print(f"[API] Agent Limit Reached for Tenant {tenant.Name} ({current_count}/{tenant.AgentLimit})")
            raise HTTPException(status_code=403, detail=f"Agent Limit Reached ({tenant.AgentLimit}). Contact Admin to upgrade.")

        # New Agent
        agent = Agent(
            AgentId=dto.AgentId,
            TenantId=tenant.Id,
            ScreenshotsEnabled=False,
            LastSeen=datetime.utcnow(),
            Hostname=dto.Hostname or "Unknown",
            LocalIp=dto.LocalIp or "0.0.0.0",
            PublicIp=client_ip,
            Gateway=dto.Gateway or "Unknown",
            InstalledSoftwareJson=dto.InstalledSoftwareJson or "[]"
        )
        db.add(agent)
        status_msg = "Registered"
    else:
        # Update Existing
        status_msg = "Already Registered" # Per user request "already exit and registrater", maybe imply "Updated" but acknowledge existence.
        agent.LastSeen = datetime.utcnow()
        agent.TenantId = tenant.Id
        agent.PublicIp = client_ip
        if dto.Hostname:
            agent.Hostname = dto.Hostname
        if dto.InstalledSoftwareJson:
            agent.InstalledSoftwareJson = dto.InstalledSoftwareJson
        if dto.LocalIp:
            agent.LocalIp = dto.LocalIp
        if dto.Gateway:
            agent.Gateway = dto.Gateway
    
    await db.commit()

    # 4. Broadcast via Socket.IO
    details = f"Status: {dto.Status} | CPU: {dto.CpuUsage:.1f}% | MEM: {dto.MemoryUsage:.1f}MB"
    await sio.emit('ReceiveEvent', {
        'agentId': dto.AgentId,
        'title': 'System Heartbeat',
        'details': details,
        'timestamp': dto.Timestamp.isoformat()
    })

    # 5. Trigger Vulnerability Scan (Background)
    if dto.InstalledSoftwareJson and len(dto.InstalledSoftwareJson) > 10:
        try:
            from ..tasks.security import scan_vulnerabilities_background
            # Pass AgentId and JSON string
            scan_vulnerabilities_background.delay(dto.AgentId, dto.InstalledSoftwareJson)
        except Exception as e:
            print(f"[API] Failed to trigger sec scan: {e}")

    
    # Send Real-time Update via Socket.IO
    await sio.emit('agent_update', {
        'AgentId': agent.AgentId,
        'Status': dto.Status,
        'CpuUsage': dto.CpuUsage,
        'MemoryUsage': dto.MemoryUsage,
        'LastSeen': agent.LastSeen.isoformat(),
        'Hostname': agent.Hostname,
        'PublicIp': agent.PublicIp
    }, room=str(tenant.Id)) # Unicast to Room

    return {
        "status": "success", 
        "message": status_msg,
        "config": {
            "ScreenshotsEnabled": agent.ScreenshotsEnabled,
            "ScreenshotQuality": agent.ScreenshotQuality or 80,
            "ScreenshotResolution": agent.ScreenshotResolution or "Original",
            "MaxScreenshotSize": agent.MaxScreenshotSize or 0
        }
    }

# --- Export Activity Logs ---
# --- Export Activity Logs ---
@router.get("/export/activity/{agent_id}")
async def export_activity_logs(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: "User" = Depends(get_current_user)
):
    # 1. Fetch Logs
    query = select(ActivityLogModel).where(ActivityLogModel.AgentId == agent_id).order_by(ActivityLogModel.Timestamp.desc()).limit(1000)
    result = await db.execute(query)
    logs = result.scalars().all()

    # 2. Generate CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(["Timestamp", "Activity Type", "Process Name", "Window Title", "URL", "Duration (s)", "Risk Level", "Risk Score"])
    
    for log in logs:
        writer.writerow([
            log.Timestamp,
            log.ActivityType,
            log.ProcessName,
            log.WindowTitle,
            log.Url,
            log.DurationSeconds,
            log.RiskLevel,
            log.RiskScore
        ])
    
    output.seek(0)
    
    # 3. Stream Response
    filename = f"ActivityReport_{agent_id}_{datetime.now().strftime('%Y%m%d')}.csv"
    
    def iterfile():
        yield output.getvalue()
        
    return StreamingResponse(
        iterfile(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
