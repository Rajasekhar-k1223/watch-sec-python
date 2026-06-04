from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query # type: ignore
from fastapi.responses import StreamingResponse # type: ignore
import csv # type: ignore
import io # type: ignore
import os # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy import update # type: ignore
from sqlalchemy.future import select # type: ignore
from pydantic import BaseModel # type: ignore
from datetime import datetime # type: ignore
from typing import Optional, List # type: ignore
import json # type: ignore
import asyncio # type: ignore

from ..db.session import get_db # type: ignore
from ..db.models import Agent, AgentReportEntity, Tenant, User, ActivityLog as ActivityLogModel, EventLog, ReportFile # type: ignore
from ..socket_instance import sio # type: ignore
from .deps import get_current_user # type: ignore
from ..core.constants import FEATURE_TIERS, PLAN_LEVELS # type: ignore

router = APIRouter()

REPORT_STORAGE_DIR = "/app/storage/reports"

# ─────────────────────────────────────────────
# DTOs for Report Scheduling
# ─────────────────────────────────────────────
class ReportSettingsDto(BaseModel):
    auto_enabled: bool = False
    frequency: str = "weekly"          # daily | weekly | 15days | monthly
    scheduled_time: str = "08:00"      # HH:MM in UTC
    emails: List[str] = []             # list of recipient emails

class SendNowDto(BaseModel):
    frequency: str = "weekly"          # daily | weekly | monthly
    emails: List[str] = []             # specific emails to send to manually

# ─────────────────────────────────────────────
# GET /api/reports/settings
# ─────────────────────────────────────────────
@router.get("/reports/settings")
async def get_report_settings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    tenant_res = await db.execute(select(Tenant).where(Tenant.Id == current_user.TenantId))
    tenant = tenant_res.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    cfg = tenant.ReportingConfigJson or {}
    return {
        "auto_enabled": cfg.get("auto_enabled", False),
        "frequency":     cfg.get("frequency", "weekly"),
        "scheduled_time": cfg.get("scheduled_time", "08:00"),
        "emails":        cfg.get("emails", [tenant.AdminEmail] if tenant.AdminEmail else []),
        "last_sent":     cfg.get("last_sent"),
    }

# ─────────────────────────────────────────────
# PUT /api/reports/settings
# ─────────────────────────────────────────────
@router.put("/reports/settings")
async def update_report_settings(
    body: ReportSettingsDto,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    tenant_res = await db.execute(select(Tenant).where(Tenant.Id == current_user.TenantId))
    tenant = tenant_res.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    existing = dict(tenant.ReportingConfigJson or {})
    existing.update({
        "auto_enabled":    body.auto_enabled,
        "frequency":       body.frequency,
        "scheduled_time":  body.scheduled_time,
        "emails":          body.emails,
    })
    await db.execute(
        update(Tenant).where(Tenant.Id == tenant.Id).values(ReportingConfigJson=existing)
    )
    await db.commit()
    return {"status": "saved", "config": existing}

# ─────────────────────────────────────────────
# POST /api/reports/send-now
# ─────────────────────────────────────────────
@router.post("/reports/send-now")
async def send_report_now(
    body: SendNowDto,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Manually trigger an immediate report for the current tenant."""
    tenant_res = await db.execute(select(Tenant).where(Tenant.Id == current_user.TenantId))
    tenant = tenant_res.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    cfg = tenant.ReportingConfigJson or {}
    emails = body.emails if body.emails else cfg.get("emails", [tenant.AdminEmail] if tenant.AdminEmail else [])
    if not emails:
        raise HTTPException(status_code=400, detail="No recipient emails provided. Add emails first.")

    days_map = {"daily": 1, "weekly": 7, "15days": 15, "monthly": 30}
    days = days_map.get(body.frequency, 7)

    background_tasks.add_task(_run_manual_report, tenant.Id, days, body.frequency.capitalize(), emails)
    return {"status": "queued", "message": f"Report is being generated and will be sent to {len(emails)} recipient(s)"}

async def _run_manual_report(tenant_id: int, days: int, label: str, emails: list):
    """Background task to generate and send a report."""
    try:
        from ..tasks.reports import _process_tenant_report_for_emails # type: ignore
        from ..db.session import AsyncSessionLocal # type: ignore
        async with AsyncSessionLocal() as db:
            tenant_res = await db.execute(select(Tenant).where(Tenant.Id == tenant_id))
            tenant = tenant_res.scalar_one_or_none()
            if tenant:
                await _process_tenant_report_for_emails(db, tenant, days=days, timeframe_label=label, emails=emails)
    except Exception as e:
        print(f"[ReportNow] Error: {e}")

# ─────────────────────────────────────────────
# GET /api/reports/history
# ─────────────────────────────────────────────
@router.get("/reports/history")
async def get_report_history(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0)
):
    """[OPTIMIZED] List generated reports using the metadata index."""
    query = select(ReportFile).where(ReportFile.TenantId == current_user.TenantId)\
        .order_by(ReportFile.GeneratedAt.desc())\
        .limit(limit).offset(offset)
    
    result = await db.execute(query)
    files = result.scalars().all()
    
    return [
        {
            "filename": f.Filename,
            "size_kb": round(f.Size / 1024, 1),
            "generated_at": f.GeneratedAt.isoformat(),
            "download_url": f.DownloadUrl
        } for f in files
    ]

class ReportDto(BaseModel):
    id: int
    title: str
    date: datetime
    status: str
    url: str

@router.get("/reports", response_model=list[ReportDto])
async def list_reports():
    return []

# [LEGACY]
@router.get("/report")
async def legacy_report_check():
    return {"status": "ok", "message": "Legacy endpoint. Please upgrade agent."}

@router.post("/reports/generate")
async def generate_report():
    return {"status": "success", "message": "Report generation started"}

# --- History Endpoint ---
@router.get("/history/{agent_id}")
async def get_agent_history(
    agent_id: str,
    start_date: str = None,
    end_date: str = None,
    db: AsyncSession = Depends(get_db),
    current_user: "User" = Depends(get_current_user),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
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
             print(f"[Auth-Debug] 403 DENIED. Access blocked for cross-tenant access attempt on Agent: {agent.AgentId}")
             raise HTTPException(status_code=403, detail="Access Denied")

    query = select(AgentReportEntity).where(AgentReportEntity.AgentId == agent_id)
    
    if start_date or end_date:
        if start_date:
            try:
                dt_start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            except ValueError:
                dt_start = start_date
            query = query.where(AgentReportEntity.Timestamp >= dt_start)
        if end_date:
            try:
                dt_end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            except ValueError:
                dt_end = end_date
            query = query.where(AgentReportEntity.Timestamp <= dt_end)
            
    query = query.order_by(AgentReportEntity.Timestamp.desc())
    query = query.limit(limit).offset(offset)
    
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
    Country: Optional[str] = None
    PowerStatus: Optional[dict] = None 
    Hardware: Optional[dict] = None # [NEW] System Specs

@router.post("/agent/heartbeat_legacy")
async def receive_report_legacy():
    return {"status": "error", "message": "This endpoint is deprecated. Use /api/agent/heartbeat."}

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
