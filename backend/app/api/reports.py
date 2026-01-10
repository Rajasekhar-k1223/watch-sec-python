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

class ReportDto(BaseModel):
    id: int
    title: str
    date: datetime
    status: str
    url: str

@router.get("/reports", response_model=list[ReportDto])
async def list_reports():
    # Mock response for now
    return []

@router.post("/reports/generate")
async def generate_report():
    return {"status": "success", "message": "Report generation started"}

# --- History Endpoint ---
@router.get("/history/{agent_id}")
async def get_agent_history(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: "User" = Depends(get_current_user)
):
    # [SECURITY] Validate Agent Ownership
    agent_res = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = agent_res.scalars().first()
    
    if not agent:
        # Return empty or 404? 404 is cleaner but empty list might be safer for UI
        # User asked for "strict validation", so 404/403 is better
        raise HTTPException(status_code=404, detail="Agent not found")
        
    if current_user.Role != "SuperAdmin":
        if not current_user.TenantId or agent.TenantId != current_user.TenantId:
             raise HTTPException(status_code=403, detail="Access Denied")

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
    # [NEW] Agent-Reported Location
    Latitude: Optional[float] = 0.0
    Longitude: Optional[float] = 0.0
    Latitude: Optional[float] = 0.0
    Longitude: Optional[float] = 0.0
    Country: Optional[str] = None
    PowerStatus: Optional[dict] = None # [NEW] Battery Data

@router.post("/agent/heartbeat")
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

    # Extract Public IP (Robust Proxy Support)
    forwarded_for = request.headers.get("X-Forwarded-For")
    real_ip = request.headers.get("X-Real-IP")
    
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    elif real_ip:
        client_ip = real_ip
    else:
        client_ip = request.client.host if request.client else "Unknown"

    if client_ip not in ["127.0.0.1", "localhost", "::1", "Unknown"]:
        # [SECURITY] Strict IP One-Entity-Per-IP Rule
        
        # 1. Check if IP used by a Tenant
        ip_tenant = await db.execute(select(Tenant).where(Tenant.RegistrationIp == client_ip))
        if ip_tenant.scalars().first():
             # If exact match found in Tenants table, BLOCK Agent.
             print(f"[API] Blocked Agent Registration from Tenant IP: {client_ip}")
             raise HTTPException(status_code=400, detail="IP Address restriction: This IP is already associated with a Tenant account.")

        # 2. Check if IP used by ANOTHER Agent (Optional: "one agent per ip"?)
        # User said "filter agents and tenant if ipaddress already exit".
        # This implies cross-checking. Let's enforce strict unique IP across the board?
        # Or maybe just "Don't mismatch".
        # Let's enforce: If IP is used by an Agent of ANOTHER Tenant? No, that's complex (NAT).
        # Let's start with just blocking if Tenant exists.
        pass

    # [LOCATION] Geolocation Logic 
    # Check Toggle First (User Consent)
    if agent.LocationTrackingEnabled:
        lat, lon, country = 0.0, 0.0, "Unknown"
        
        # 1. Check Agent Report
        if dto.Latitude and dto.Latitude != 0.0:
            lat = dto.Latitude
            lon = dto.Longitude
            country = dto.Country or "Unknown"
        
        # 2. Fallback to Backend IP Lookup
        else:
            should_geolocate = False
            if not agent:
                should_geolocate = True
            elif agent.PublicIp != client_ip:
                should_geolocate = True
                
            if should_geolocate and client_ip not in ["127.0.0.1", "localhost", "::1", "Unknown"]:
                try:
                     import requests
                     import asyncio
                     geo_resp = await asyncio.to_thread(
                         requests.get, 
                         f"http://ip-api.com/json/{client_ip}?fields=status,country,lat,lon", 
                         timeout=3
                     )
                     if geo_resp.status_code == 200:
                         geo_data = geo_resp.json()
                         if geo_data.get("status") == "success":
                             lat = geo_data.get("lat", 0.0)
                             lon = geo_data.get("lon", 0.0)
                             country = geo_data.get("country", "Unknown")
                             print(f"[API] Geolocated {client_ip} -> {country} ({lat}, {lon})")
                except Exception as e:
                    print(f"[API] Geolocation Failed: {e}")
        
        # Apply Updates if we have data
        if lat != 0.0:
            agent.Latitude = lat
            agent.Longitude = lon
            agent.Country = country
            # print(f"[API] Updated Location for {agent.AgentId}")

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
            Latitude=lat,
            Longitude=lon,
            Country=country,
            Gateway=dto.Gateway or "Unknown",
            InstalledSoftwareJson=dto.InstalledSoftwareJson or "[]"
        )
        db.add(agent)
        status_msg = "Registered"
    else:
        # Update Existing
        status_msg = "Already Registered" 
        agent.LastSeen = datetime.utcnow()
        agent.TenantId = tenant.Id
        
        # Only update location if we actually fetched it (don't overwrite with 0.0 if fetch failed)
        if should_geolocate and lat != 0.0:
            agent.Latitude = lat
            agent.Longitude = lon
            agent.Country = country
            print(f"[API] Updated Location for {agent.AgentId}")

        agent.PublicIp = client_ip
        if dto.Hostname:
            agent.Hostname = dto.Hostname
        if dto.InstalledSoftwareJson:
            agent.InstalledSoftwareJson = dto.InstalledSoftwareJson
        if dto.LocalIp:
            agent.LocalIp = dto.LocalIp
        if dto.Gateway:
            agent.Gateway = dto.Gateway
        if dto.PowerStatus:
            agent.PowerStatusJson = json.dumps(dto.PowerStatus)
    
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
            "LocationTrackingEnabled": agent.LocationTrackingEnabled,
            "UsbBlockingEnabled": agent.UsbBlockingEnabled, # [FIX] Sync DLP Config
            "NetworkMonitoringEnabled": agent.NetworkMonitoringEnabled, # [FIX] Sync DLP Config
            "FileDlpEnabled": agent.FileDlpEnabled, # [FIX] Sync DLP Config
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
    # [SECURITY] Validate Agent Ownership
    agent_res = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = agent_res.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    if current_user.Role != "SuperAdmin":
        if not current_user.TenantId or agent.TenantId != current_user.TenantId:
             raise HTTPException(status_code=403, detail="Access Denied")

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
