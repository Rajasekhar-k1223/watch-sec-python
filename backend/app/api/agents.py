import fastapi # type: ignore # pyre-ignore
from fastapi import APIRouter, Depends, HTTPException, status, Response, Query # type: ignore
from fastapi.responses import FileResponse, JSONResponse # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from pydantic import BaseModel # type: ignore
from typing import Optional, List, Any # type: ignore
import os # type: ignore
import asyncio # type: ignore
import hashlib # type: ignore
import hmac # type: ignore
import json # type: ignore
from datetime import datetime, timedelta # type: ignore

# --- Policy Cache (TTL=60s): avoids a DB query on every 30s heartbeat ---
_policy_cache: dict = {}  # key: PolicyId, value: (policy_obj, cached_at)

from ..db.session import get_db # type: ignore
from ..db.models import Agent, User, ShadowedFile, EventLog, Policy, Tenant, AuditLog # type: ignore
from .deps import get_current_user, get_tenant_by_key, get_current_user_flexible, check_role, get_current_active_user # type: ignore
from ..socket_instance import sio # type: ignore
from ..schemas import AgentUpdateFailedRequest, AgentHeartbeat, AgentSettingsUpdate # type: ignore

router = APIRouter()

from ..core.constants import FEATURE_TIERS, PLAN_LEVELS, LATEST_AGENT_VERSION # type: ignore
from ..core import trial_manager # type: ignore
from ..tasks.security import scan_vulnerabilities_background # type: ignore
from ..tasks.general import staggered_bulk_patch # type: ignore

def verify_feature_access(tenant_plan: str, feature_key: str):
    plan_level = PLAN_LEVELS.get(tenant_plan, 1) # Default to Starter
    required_level = FEATURE_TIERS.get(feature_key, 3) # Default to Enterprise if unknown
    
    if plan_level < required_level:
        raise HTTPException(
            status_code=403, 
            detail=f"Feature '{feature_key}' requires {get_plan_name(required_level)} Plan. Current: {tenant_plan}"
        )

async def verify_feature_access_with_trial(
    db: AsyncSession,
    tenant_id: int,
    tenant_plan: str,
    feature_key: str
) -> dict:
    """
    Verify if tenant has access to a feature via plan or active trial.
    
    Returns:
        {
            "has_access": bool,
            "access_type": "plan" | "trial" | None,
            "trial": FeatureTrial or None
        }
    """
    plan_level = PLAN_LEVELS.get(tenant_plan, 1)
    required_level = FEATURE_TIERS.get(feature_key, 3)
    
    # Check if tenant has access via their plan
    if plan_level >= required_level:
        return {
            "has_access": True,
            "access_type": "plan",
            "trial": None
        }
    
    # Check if tenant has an active trial for this feature
    active_trial = await trial_manager.get_active_trial(
        db=db,
        tenant_id=tenant_id,
        feature_name=feature_key
    )
    
    if active_trial:
        return {
            "has_access": True,
            "access_type": "trial",
            "trial": active_trial
        }
    
    # No access
    return {
        "has_access": False,
        "access_type": None,
        "trial": None
    }

def get_plan_name(level):
    for k, v in PLAN_LEVELS.items():
        if v == level: return k
    return "Enterprise"

@router.get("/config/versions")
async def get_system_versions():
    return {
        "latest": LATEST_AGENT_VERSION
    }

from fastapi import APIRouter, Depends, HTTPException, status, Response, Query # type: ignore
@router.get("")
@router.get("/", include_in_schema=False)
async def get_agents(
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db),
    tenantId: Optional[int] = Query(None), # [NEW] Support explicit tenant filtering
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    try:
        query = select(Agent)
        
        # [ROBUSTNESS] Handle missing IsPendingUninstall column if migration hasn't run yet
        try:
            query = query.where(Agent.IsPendingUninstall == False)
        except Exception:
            print("[Agents] WARNING: IsPendingUninstall column missing. Skipping filter.")

        # Filter by Tenant for non-SuperAdmin or if tenantId provided
        effective_tenant_id = current_user.TenantId
        if current_user.Role == "SuperAdmin" and tenantId is not None:
            effective_tenant_id = tenantId

        if effective_tenant_id:
            query = query.where(Agent.TenantId == effective_tenant_id)
        elif current_user.Role != "SuperAdmin":
            return [] # Non-SuperAdmin with no tenant access
        
        query = query.order_by(Agent.LastSeen.desc())
        query = query.limit(limit).offset(offset)
            
        result = await db.execute(query)
        agents = result.scalars().all()
        
        # [FIX] Compute dynamic status for each agent
        from datetime import datetime, timedelta # type: ignore
        now = datetime.utcnow()
        
        response = []
        for a in agents:
            status = "Offline"
            if a.LastSeen and (now - a.LastSeen).total_seconds() < 120:
                status = "Online"
            
            # [SAFE ACCESS] Use getattr to handle potentially missing columns before migration
            # This prevents 500 errors if the code is deployed before the DB schema update
            def get_safe(obj, attr, default=None):
                try:
                    return getattr(obj, attr, default)
                except Exception:
                    return default

            # Merge model with dynamic fields
            response.append({
                "id": a.Id,
                "agentId": a.AgentId,
                "tenantId": a.TenantId,
                "hostname": a.Hostname,
                "status": status,
                "cpuUsage": a.CpuUsage,
                "memoryUsage": a.MemoryUsage,
                "lastSeen": a.LastSeen.isoformat() if a.LastSeen else None,
                # Network / Location fields
                "publicIp": get_safe(a, "PublicIp"),
                "localIp": get_safe(a, "LocalIp"),
                "gateway": get_safe(a, "Gateway"),
                "latitude": get_safe(a, "Latitude"),
                "longitude": get_safe(a, "Longitude"),
                "country": get_safe(a, "Country"),
                # Feature flags (Legacy)
                "screenshotsEnabled": a.ScreenshotsEnabled,
                "locationTrackingEnabled": getattr(a, "GeolocationEnabled", getattr(a, "LocationTrackingEnabled", False)),
                "usbBlockingEnabled": a.UsbBlockingEnabled,
                "networkMonitoringEnabled": a.NetworkMonitoringEnabled,
                "fileDlpEnabled": a.FileDlpEnabled,
                "activityMonitorEnabled": a.ActivityMonitorEnabled,
                "keyloggerEnabled": a.KeyloggerEnabled,
                "clipboardMonitorEnabled": a.ClipboardMonitorEnabled,
                "appBlockerEnabled": a.AppBlockerEnabled,
                "browserEnforcerEnabled": a.BrowserComplianceEnabled, # Corrected
                "printerMonitorEnabled": a.PrinterMonitorEnabled,
                "shadowMonitorEnabled": a.ShadowMonitorEnabled,
                "liveStreamEnabled": a.LiveStreamEnabled,
                "remoteShellEnabled": a.RemoteShellEnabled,
                "mailMonitorEnabled": a.MailMonitorEnabled,
                
                # Professional Terminology [v2.0]
                "visualActivityEnabled": a.VisualActivityEnabled,
                "locationAuditEnabled": a.LocationAuditEnabled,
                "usbComplianceEnabled": a.UsbComplianceEnabled,
                "networkAuditEnabled": a.NetworkAuditEnabled,
                "dataLossPreventionEnabled": a.DataLossPreventionEnabled,
                "inputAuditEnabled": a.InputAuditEnabled,
                "clipboardAuditEnabled": a.ClipboardAuditEnabled,
                "appEnforcementEnabled": a.AppEnforcementEnabled,
                "browserComplianceEnabled": a.BrowserComplianceEnabled,
                "printAuditEnabled": a.PrintAuditEnabled,
                "shadowAuditEnabled": a.ShadowAuditEnabled,
                "sessionForensicEnabled": a.SessionForensicEnabled,
                "remoteRemediationEnabled": a.RemoteRemediationEnabled,
                "mailIntelligenceEnabled": a.MailIntelligenceEnabled,
                "voiceIntelligenceEnabled": a.VoiceIntelligenceEnabled,
                "monitoringConsentRequired": a.MonitoringConsentRequired,
                "powerStatusJson": a.PowerStatusJson,
                "hardwareJson": a.HardwareJson,
                "version": a.Version,
                "targetVersion": a.TargetVersion,
                "updateStatus": get_safe(a, "UpdateStatus"),
                "updateFailureReason": get_safe(a, "UpdateFailureReason"),
                "lastUpdateAttempt": a.LastUpdateAttempt.isoformat() if get_safe(a, "LastUpdateAttempt") else None,
                "policyId": get_safe(a, "PolicyId"),
                "behavioralMetadataJson": get_safe(a, "BehavioralMetadataJson"),
                "screenshotInterval": get_safe(a, "ScreenshotInterval", 60),
            })
            
        return response
    except Exception as e:
        import traceback # type: ignore
        traceback.print_exc()
        return JSONResponse(
            status_code=500, 
            content={
                "detail": f"Internal Server Error: {str(e)}", 
                "trace": traceback.format_exc()
            }
        )

class AgentUpdateLogRequest(BaseModel):
    AgentId: str
    Log: str

from ..core.rate_limit import RateLimiter # type: ignore

@router.post("/{agent_id}/update-log")
async def report_update_log(
    agent_id: str,
    payload: AgentUpdateLogRequest,
    db: AsyncSession = Depends(get_db),
    tenant: Tenant = Depends(get_tenant_by_key)
):
    # [SECURITY] Ownership check
    agent_res = await db.execute(select(Agent).where(Agent.AgentId == agent_id, Agent.TenantId == tenant.Id))
    if not agent_res.scalars().first():
         raise HTTPException(status_code=403, detail="Access denied")
    # [SECURITY] [v1.8.36] Path Traversal Protection
    # Strictly validate agent_id to prevent directory traversal payloads (../../)
    import re
    if not re.match(r"^[a-zA-Z0-9\-]+$", agent_id):
         print(f"[SECURITY ALERT] Prevented Path Traversal attempt via agent_id: {agent_id}")
         raise HTTPException(status_code=403, detail="Invalid Agent ID format")

    # Save log to storage
    file_dir = os.path.dirname(os.path.abspath(__file__))
    log_dir = os.path.abspath(os.path.join(file_dir, "..", "..", "..", "storage", "logs", "updates"))
    os.makedirs(log_dir, exist_ok=True)
    
    # Ensure filename is safe using basename
    safe_filename = os.path.basename(f"{agent_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.log")
    log_path = os.path.join(log_dir, safe_filename)
    with open(log_path, "w", encoding='utf-8') as f:
        f.write(payload.Log)
        
    return {"status": "recorded"}

@router.post("/{agent_id}/update-failed")
async def report_update_failure(
    agent_id: str,
    payload: AgentUpdateFailedRequest,
    db: AsyncSession = Depends(get_db),
    tenant: Tenant = Depends(get_tenant_by_key)
):
    # [SECURITY] Ownership check
    agent_res = await db.execute(select(Agent).where(Agent.AgentId == agent_id, Agent.TenantId == tenant.Id))
    agent = agent_res.scalars().first()
    if not agent:
         raise HTTPException(status_code=403, detail="Access denied")
    # Log the failure in EventLogs
    event = EventLog(
        AgentId=agent_id,
        Type="UpdateFailed",
        Details=payload.Reason,
        Timestamp=datetime.utcnow()
    )
    db.add(event)
    
    # Update Agent Status
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = result.scalars().first()
    if agent:
        agent.UpdateStatus = "failed"
        agent.UpdateFailureReason = payload.Reason
        agent.LastUpdateAttempt = datetime.utcnow()
        
        # [v1.8.2] Notify Webhooks
        from ..core.notifications import notify_event # type: ignore
        await notify_event(
            tenant_id=agent.TenantId,
            event_type="agent_rollback",
            details={
                "agent_id": agent.AgentId,
                "hostname": agent.Hostname,
                "msg": payload.Reason
            },
            db=db
        )
    await db.commit()
    return {"status": "recorded"}

@router.post("/{agent_id}/update")
async def trigger_agent_update(
    agent_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    _ = Depends(RateLimiter(times=10, seconds=60)) # [v1.7.0] Rate Limit: 10/min
):
    # Find agent
    query = select(Agent).where(Agent.AgentId == agent_id)
    if current_user.Role != "SuperAdmin":
        query = query.where(Agent.TenantId == current_user.TenantId)
        
    result = await db.execute(query)
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    # For now, we set it to our latest build version (v1.5.0).
    # [v1.8.2] Set Update Status
    agent.TargetVersion = LATEST_AGENT_VERSION
    agent.UpdateStatus = "pending"
    agent.UpdateFailureReason = None
    agent.LastUpdateAttempt = datetime.utcnow()
    await db.commit()
    
    # [REAL-TIME] Notify Frontend
    await sio.emit('agent_list_update', {
        'agentId': agent.AgentId,
        'targetVersion': agent.TargetVersion,
        'updatePending': True
    }, room=f"tenant_{agent.TenantId}")
    
    return {"status": "success", "message": f"Target version set to {agent.TargetVersion}"}

@router.post("/{agent_id}/lockdown")
async def trigger_sovereign_lockdown(
    agent_id: str,
    payload: dict, # { "unlock_key": "..." }
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Find agent
    query = select(Agent).where(Agent.AgentId == agent_id)
    if current_user.Role != "SuperAdmin":
        query = query.where(Agent.TenantId == current_user.TenantId)
        
    result = await db.execute(query)
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    unlock_key = payload.get("unlock_key")
    reason = payload.get("reason", "No reason provided")
    
    if not unlock_key or len(unlock_key) < 6:
        raise HTTPException(status_code=400, detail="Unlock key must be at least 6 characters")
    
    # [v2.6.8] Sovereign Governance Audit
    new_event = EventLog(
        AgentId=agent_id,
        TenantId=agent.TenantId,
        EventType="SOVEREIGN_GOVERNANCE",
        Severity="CRITICAL",
        Description=f"INDIVIDUAL LOCKDOWN: Node {agent.Hostname or agent_id} neutralized by {current_user.Username}. Reason: {reason}",
        Timestamp=datetime.utcnow()
    )
    db.add(new_event)
    
    # Hash the key (SHA256) for the agent to use
    unlock_hash = hashlib.sha256(unlock_key.encode()).hexdigest()
    
    # [v1.8.37] Command Sovereignty: Signature Generation
    timestamp = datetime.utcnow().isoformat()
    action = "SOVEREIGN_LOCKDOWN"
    params = {"unlock_hash": unlock_hash}
    
    # Derive HMAC Key (Same logic as agent)
    msg_parts = [action, json.dumps(params, sort_keys=True), timestamp]
    message = "|".join(msg_parts).encode('utf-8')
    
    # We need the tenant to get the api_key for signing
    tenant_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant = tenant_res.scalars().first()
    
    if not tenant or not agent.MachineId:
        raise HTTPException(status_code=500, detail="Keys not synchronized for this agent")
        
    key = hashlib.sha256(tenant.ApiKey.encode() + agent.MachineId).digest()
    signature = hmac.new(key, message, hashlib.sha256).hexdigest()
    
    command_data = {
        "action": action,
        "params": params,
        "policy_name": "Administrative Lockdown",
        "timestamp": timestamp,
        "signature": signature
    }
    
    # [REAL-TIME] Push to Agent
    await sio.emit('RemediationCommand', command_data, room=agent.AgentId)
    
    # [AUDIT]
    audit = AuditLog(
        TenantId=agent.TenantId,
        Actor=current_user.Username,
        Action="Sovereign Lockdown",
        Target=agent.Hostname,
        Details="Emergency system lockdown triggered remotely.",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    await db.commit()
    
    return {"status": "success", "message": "Sovereign Lockdown command dispatched."}

@router.get("/{agent_id}/software")
async def get_agent_software(
    agent_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    query = select(Agent).where(Agent.AgentId == agent_id)
    if current_user.Role != "SuperAdmin":
        query = query.where(Agent.TenantId == current_user.TenantId)
    
    agent_result = await db.execute(query)
    agent = agent_result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    # [v2.6.0] Use relational AgentSoftware table
    from ..db.models import AgentSoftware # type: ignore
    sw_query = select(AgentSoftware).where(AgentSoftware.AgentId == agent_id)
    sw_result = await db.execute(sw_query)
    software_list = sw_result.scalars().all()
    
    return [
        {
            "Name": s.Name,
            "Version": s.Version,
            "Type": s.Type,
            "LastSeen": s.LastSeen.isoformat() if s.LastSeen else None
        } for s in software_list
    ]

@router.get("/{agent_id}/shadow-vault")
async def get_shadow_vault(
    agent_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Validate Agent & Access
    query = select(Agent).where(Agent.AgentId == agent_id)
    if current_user.Role != "SuperAdmin":
        query = query.where(Agent.TenantId == current_user.TenantId)
    
    agent_result = await db.execute(query)
    if not agent_result.scalars().first():
        raise HTTPException(status_code=404, detail="Agent not found")

    # Fetch Shadowed Files
    files_query = select(ShadowedFile).where(ShadowedFile.AgentId == agent_id).order_by(ShadowedFile.Timestamp.desc())
    result = await db.execute(files_query)
    files = result.scalars().all()
    
    return files

@router.get("/{agent_id}/shadow-vault/{file_id}/download")
async def download_shadow_file(
    agent_id: str,
    file_id: int,
    current_user: User = Depends(get_current_user_flexible),
    db: AsyncSession = Depends(get_db)
):
    # Fetch File Info
    query = select(ShadowedFile).where(ShadowedFile.Id == file_id, ShadowedFile.AgentId == agent_id)
    result = await db.execute(query)
    file_info = result.scalars().first()
    
    if not file_info:
        raise HTTPException(status_code=404, detail="File not found")
        
    # [SECURITY] Check Tenant Ownership
    agent_res = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = agent_res.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    if current_user.Role != "SuperAdmin" and agent.TenantId != current_user.TenantId:
        raise HTTPException(status_code=403, detail="Access denied")
        
    if not os.path.exists(file_info.StoragePath):
        raise HTTPException(status_code=404, detail="File not found on disk")
        
    return FileResponse(
        path=file_info.StoragePath,
        filename=file_info.FileName,
        media_type='application/octet-stream'
    )

# --- Agent Side Router (Mounted at /api/agent) ---
agent_router = APIRouter()


class AgentEvent(BaseModel):
    EventType: str
    Message: str
    TenantApiKey: Optional[str] = None # Support backward compatibility
    Timestamp: Optional[str] = None


class RelayStreamRequest(BaseModel):
    width: int = 1280
    quality: int = 80
    agentId: str


@agent_router.post("/internal/relay-stream/{agent_id}")
async def internal_relay_stream(
    agent_id: str,
    payload: RelayStreamRequest,
    db: AsyncSession = Depends(get_db)
):
    """Internal Bridge: Emits StartStream directly to current gateway clients."""
    print(f"[RELAY_RECEIVED] Internal signal for {agent_id}. Data: {payload}")
    try:
        # 1. Emit StartStream directly to the room
        await sio.emit('StartStream', payload.dict(), room=agent_id)
        return {"status": "relayed"}
    except Exception as e:
        print(f"[RELAY_ERROR] {e}")
        raise HTTPException(status_code=500, detail=str(e))



def is_in_maintenance_window(tenant_obj) -> bool:
    """Checks if the current UTC time is within the allowed update window."""
    import json # type: ignore
    from datetime import datetime # type: ignore
    try:
        if not tenant_obj.MaintenanceWindowJson:
            return True # Default: Always allow if not configured
            
        data = json.loads(tenant_obj.MaintenanceWindowJson)
        if not data or not data.get("enabled", False):
            return True # Always allow if scheduling is disabled
            
        mode = data.get("mode", "automatic")
        now = datetime.utcnow()
        day_of_week = now.weekday() # 0=Monday, 6=Sunday
        current_date_str = now.strftime("%Y-%m-%d")
        
        # [v1.8.40] One-Time Date Override
        one_time_enabled = data.get("oneTimeEnabled", False)
        one_time_date = data.get("oneTimeDate")
        
        is_scheduled_day = False
        if mode == "manual":
            # In Manual mode, we ONLY allow if oneTimeDate matches today
            if one_time_enabled and one_time_date == current_date_str:
                is_scheduled_day = True
            else:
                return False # Manual mode requires a specific date trigger
        else:
            # Automatic Mode: Recurring Day Check
            allowed_days = data.get("days", [0, 1, 2, 3, 4, 5, 6])
            if day_of_week in allowed_days:
                is_scheduled_day = True
            
            # Also allow if one-time date is set for today (Manual override in Auto mode)
            if one_time_enabled and one_time_date == current_date_str:
                is_scheduled_day = True

        if not is_scheduled_day:
            return False
            
        # 2. Time Check (HH:MM)
        current_time_str = now.strftime("%H:%M")
        start_time = data.get("startTime", "00:00")
        end_time = data.get("endTime", "23:59")
        
        if start_time <= end_time:
            return start_time <= current_time_str <= end_time
        else:
            # Overnight window (e.g. 23:00 to 03:00)
            return current_time_str >= start_time or current_time_str <= end_time
            
    except Exception as e:
        print(f"[Maintenance] ERROR: {e}")
        return True # Fail-open to avoid blocking critical updates if logic bugs out

@agent_router.post("/heartbeat")
async def agent_heartbeat(
    payload: AgentHeartbeat,
    db: AsyncSession = Depends(get_db),
    tenant: Tenant = Depends(get_tenant_by_key)
):
    print(f"[HEARTBEAT] Received from {payload.AgentId} (JustStarted={payload.JustStarted})")
    """
    Agent Heartbeat endpoint. 
    Handles both new agent registration and periodic status updates.
    Compatible with Windows, Linux, and macOS agents.
    """
    try:
        # 1. Backward Compatibility for API Key
        if not tenant:
            # Fallback to payload's TenantApiKey if header is missing
            result_tenant = await db.execute(select(Tenant).where(Tenant.ApiKey == payload.TenantApiKey))
            tenant = result_tenant.scalars().first()
            if not tenant:
                raise HTTPException(status_code=401, detail="Invalid API Key")

        # 2. Find Agent
        result_agent = await db.execute(select(Agent).where(Agent.AgentId == payload.AgentId))
        agent = result_agent.scalars().first()
        print(f"[DEBUG] Heartbeat lookup for {payload.AgentId}: {'FOUND' if agent else 'NOT FOUND'}")
        if agent:
             print(f"[DEBUG] Agent {agent.AgentId} current LastSeen: {agent.LastSeen}")

        # [SECURITY FIX] v1.8.28 - Verify Agent belongs to this Tenant
        if agent and agent.TenantId != tenant.Id:
             from .audit import AuditLog # type: ignore
             print(f"[SECURITY ALERT] Tenant {tenant.Id} attempted to spoof Agent {payload.AgentId} (owned by {agent.TenantId})")
             raise HTTPException(status_code=403, detail="Unauthorized Agent access")

        # [RECOVERY] Revival Logic - Clear pending uninstall if agent reports back online
        # NOTE: No early commit here — deferred to the single final commit below.
        if agent and (payload.JustStarted or "Online" in payload.Status):
            if agent.IsPendingUninstall:
                agent.IsPendingUninstall = False
        
        import json # type: ignore
        from datetime import datetime # type: ignore
        
        if not agent:
            # Create New Agent if not found
            # Check Agent Limit for Tenant
            from sqlalchemy import func # type: ignore
            limit_res = await db.execute(select(func.count()).select_from(Agent).where(Agent.TenantId == tenant.Id))
            current_count = limit_res.scalar()
            
            if tenant.AgentLimit != -1 and current_count >= tenant.AgentLimit:
                 raise HTTPException(status_code=403, detail="Agent Limit Reached")
            
            # Helper to check feature tier vs tenant plan
            plan_level = PLAN_LEVELS.get(tenant.Plan, 1)
            def check_feat(key, default_val):
                req_level = FEATURE_TIERS.get(key, 3)
                return default_val if plan_level >= req_level else False
            
            # [v1.8.16] Truncate software inventory to 64KB for safety
            safe_software = payload.InstalledSoftwareJson
            if safe_software and len(safe_software) > 64000:
                safe_software = safe_software[:64000] + "]"

            # Initialize New Agent object
            agent = Agent(
                AgentId=payload.AgentId,
                TenantId=tenant.Id,
                Hostname=payload.Hostname,
                LocalIp=payload.LocalIp or "0.0.0.0",
                Gateway=payload.Gateway or "Unknown",
                InstalledSoftwareJson=safe_software,
                LastSeen=datetime.utcnow(),
                ScreenshotsEnabled=check_feat("ScreenshotsEnabled", False),
                UsbBlockingEnabled=check_feat("UsbBlockingEnabled", True),
                NetworkMonitoringEnabled=check_feat("NetworkMonitoringEnabled", True),
                FileDlpEnabled=check_feat("FileDlpEnabled", True),
                ActivityMonitorEnabled=check_feat("ActivityMonitorEnabled", True),
                KeyloggerEnabled=check_feat("KeyloggerEnabled", True),
                ClipboardMonitorEnabled=check_feat("ClipboardMonitorEnabled", True),
                AppBlockerEnabled=check_feat("AppBlockerEnabled", True),
                BrowserEnforcerEnabled=check_feat("BrowserEnforcerEnabled", True),
                PrinterMonitorEnabled=check_feat("PrinterMonitorEnabled", True),
                ShadowMonitorEnabled=check_feat("ShadowMonitorEnabled", True),
                LiveStreamEnabled=check_feat("LiveStreamEnabled", True),
                RemoteShellEnabled=check_feat("RemoteShellEnabled", True),
                MailMonitorEnabled=check_feat("MailMonitorEnabled", True),
                LocationTrackingEnabled=check_feat("LocationTrackingEnabled", True),
                SpeechMonitorEnabled=check_feat("SpeechMonitorEnabled", True),
                VulnerabilityIntelligenceEnabled=check_feat("VulnerabilityIntelligenceEnabled", True),
                Version=payload.Version or "v1.3.0",
                TargetVersion=payload.Version or "v1.3.0",
                PublicIp=payload.PublicIp,
                Longitude=payload.Longitude if payload.Longitude != 0 else None,
                Latitude=payload.Latitude if payload.Latitude != 0 else None,
                Country=payload.Country if payload.Country != "Unknown" else None,
                MachineId=payload.MachineSecret # [NEW] v1.8.37
            )
            db.add(agent)
            try:
                await db.commit()
                await db.refresh(agent)
            except Exception as e:
                await db.rollback()
                print(f"[HEARTBEAT] New Agent Commit Failed: {e}")
                # Retry with minimal fields
                agent.InstalledSoftwareJson = None
                await db.commit()
                await db.refresh(agent)
        else:
            # Update Existing Agent
            agent.LastSeen = datetime.utcnow()
            agent.Hostname = payload.Hostname
            agent.LocalIp = payload.LocalIp
            agent.Gateway = payload.Gateway
            
            if payload.Latitude and payload.Latitude != 0:
                agent.Latitude = payload.Latitude
            if payload.Longitude and payload.Longitude != 0:
                agent.Longitude = payload.Longitude
            if payload.Country and payload.Country != "Unknown":
                agent.Country = payload.Country
            
            if payload.PublicIp:
                agent.PublicIp = payload.PublicIp
            
            # Version & Update Status Tracking
            if payload.Version:
                if agent.Version != payload.Version:
                    # If agent just updated to target, clear status
                    if payload.Version == agent.TargetVersion:
                        agent.UpdateStatus = "idle"
                        agent.UpdateFailureReason = None
                
                agent.Version = payload.Version

                # [v1.8.21] Automated Update Logic:
                # If agent version is lagging behind LATEST, set TargetVersion to trigger update
                # except if a custom TargetVersion is already set (and isn't LATEST).
                # [v1.8.40] Scheduled Patching: Mode Check
                data_mw = {}
                try: 
                    data_mw = json.loads(tenant.MaintenanceWindowJson or "{}")
                except: pass
                
                auto_patch = data_mw.get("mode", "automatic") == "automatic"
                print(f"[DEBUG] Auto-patch mode: {auto_patch}")
                
                if agent.Version != LATEST_AGENT_VERSION:
                    if agent.TargetVersion != LATEST_AGENT_VERSION:
                        # Only auto-target if not already in a custom update state AND in Auto-Patch mode
                        if (not agent.TargetVersion or agent.TargetVersion == agent.Version) and auto_patch:
                            agent.TargetVersion = LATEST_AGENT_VERSION
                else:
                    # If already at latest, ensure TargetVersion matches
                    if agent.TargetVersion != LATEST_AGENT_VERSION:
                        agent.TargetVersion = LATEST_AGENT_VERSION
                        agent.UpdateStatus = "idle"
            
            # [v1.8.37] Cryptographic Sync: Ensure MachineId is recorded
            if payload.MachineSecret:
                agent.MachineId = payload.MachineSecret
                # [v1.8.38] Intermediate Commit: Ensure MachineId is visible to /activity flushes immediately
                try:
                    await db.commit()
                    await db.refresh(agent)
                except:
                    await db.rollback()

            # [v1.8.38] Inventory Stats:
            if payload.InstalledSoftwareJson:
                try:
                    software_list = json.loads(payload.InstalledSoftwareJson)
                    agent.SoftwareCount = len(software_list)
                except:
                    pass

            # [v1.8.37] Strict Tenant-Agent Pinning:
            if agent.TenantId != tenant.Id:
                 print(f"[SECURITY ALERT] Tenant Conflict: Agent {agent.AgentId} claimed Tenant {agent.TenantId} but API Key is for {tenant.Id}")
                 raise HTTPException(status_code=403, detail="Agent does not belong to this tenant")
            
            print(f"[DEBUG] Tenant check passed for {agent.AgentId}")
            
            # Inventory & Vulnerability Scanning
            if payload.InstalledSoftwareJson and len(payload.InstalledSoftwareJson) > 2:
                # [v1.8.16] Aggressive truncation to 64KB for safety (fits in all TEXT types)
                safe_json = payload.InstalledSoftwareJson
                if len(safe_json) > 64000:
                    safe_json = safe_json[:64000] + "]"
                
                agent.InstalledSoftwareJson = safe_json
                try:
                    import asyncio
                    from ..core.celery_app import celery_app
                    from ..tasks.security import scan_vulnerabilities_background
                    
                    # Asyncify the synchronous kombu/celery connection attempt
                    print(f"[DEBUG] Triggering Celery task for {agent.AgentId}")
                    # Use to_thread to offload the potentially blocking .delay() call
                    # [v1.8.42] Respect Maintenance Window for Scans
                    if is_in_maintenance_window(tenant):
                        print(f"[HEARTBEAT] Triggering vulnerability scan for {agent.AgentId}")
                        await asyncio.to_thread(scan_vulnerabilities_background.delay, agent.AgentId, safe_json)
                    else:
                        print(f"[HEARTBEAT] Skipping vulnerability scan for {agent.AgentId} - Outside Maintenance Window")
                except Exception as e:
                    # Log the full repr to catch auth error strings
                    error_msg = repr(e)
                    print(f"[HEARTBEAT] Vulnerability scan trigger failed: {error_msg}", flush=True)
                
            if payload.PowerStatus:
                agent.PowerStatusJson = json.dumps(payload.PowerStatus)
            if payload.Hardware:
                agent.HardwareJson = json.dumps(payload.Hardware)
                
            agent.CpuUsage = payload.CpuUsage
            agent.MemoryUsage = payload.MemoryUsage
            agent.NetworkInMbps = payload.NetworkInMbps
            agent.NetworkOutMbps = payload.NetworkOutMbps
            # NOTE: No commit here — merged with AgentReportEntity insert below for 1 round-trip

        # --- CRITICAL: Ensure agent is not None before proceeding ---
        if not agent:
             raise HTTPException(status_code=500, detail="Internal Error: Failed to retrieve or create agent record.")

        print(f"[DEBUG] Proceeding to policy lookup for {agent.AgentId}")

        # 3. Resolve Configuration (Bandwidth & Screenshot Interval)
        bandwidth_config = tenant.bandwidth_config or {}
        screenshot_interval = agent.ScreenshotInterval
        geolocation_enabled = getattr(agent, 'GeolocationEnabled', True)
        
        # Check for Policy-specific overrides — cached to avoid a DB hit every heartbeat
        if hasattr(agent, 'PolicyId') and agent.PolicyId:
            policy_id = agent.PolicyId
            now_ts = datetime.utcnow()
            cached = _policy_cache.get(policy_id)
            policy = None
            if cached:
                cached_pol, cached_at = cached
                if (now_ts - cached_at).total_seconds() < 60:  # 60s TTL
                    policy = cached_pol
            if policy is None:
                p_res = await db.execute(select(Policy).where(Policy.Id == policy_id))
                policy = p_res.scalars().first()
                _policy_cache[policy_id] = (policy, now_ts)
            if policy:
                if policy.BandwidthJson:
                    try:
                        pol_bw = json.loads(policy.BandwidthJson)
                        if pol_bw: bandwidth_config = pol_bw
                    except: pass
                if policy.ScreenshotInterval is not None:
                    screenshot_interval = policy.ScreenshotInterval
                if hasattr(policy, 'GeolocationEnabled') and policy.GeolocationEnabled is not None:
                    geolocation_enabled = policy.GeolocationEnabled

        # 4. Check for Remote Updates
        update_required = False
        update_url = ""
        if agent.Version != agent.TargetVersion:
            # [v1.8.58] Manual-only updates to prevent server saturation
            if agent.UpdateStatus in ["pending_manual_push", "dispatching_update"]:
                update_required = True
                backend_url = os.getenv("AGENT_BACKEND_URL") or "https://agent-api.monitorix.co.in"
                hostname_lower = agent.Hostname.lower() if agent.Hostname else ""
                # --- v1.8.41: Precision Architecture Detection ---
                os_type = "windows"
                arch = "x64"
                
                if agent.HardwareJson:
                    try:
                        hw = json.loads(agent.HardwareJson)
                        os_sys = hw.get("OsSystem", "").lower()
                        if "linux" in os_sys: os_type = "linux"
                        elif "darwin" in os_sys or "mac" in os_sys: os_type = "mac"
                        
                        model = hw.get("CpuModel", "").lower() + hw.get("Arch", "").lower()
                        if "arm" in model or "apple" in model or "m1" in model or "m2" in model:
                            arch = "arm64"
                    except: pass
                else:
                    # Fallback to hostname-based detection [Legacy]
                    hostname_lower = agent.Hostname.lower()
                    if "linux" in hostname_lower or "ubuntu" in hostname_lower:
                        os_type = "linux"
                    elif "mac" in hostname_lower or "darwin" in hostname_lower:
                        os_type = "macos"
                    
                    if "arm" in hostname_lower or "aarch64" in hostname_lower:
                        arch = "arm64"
                
                update_os_type = f"{os_type}-{arch}" if os_type != "windows" else "windows"
                update_url = f"{backend_url.rstrip('/')}/api/downloads/public/payload?key={tenant.ApiKey}&os_type={update_os_type}"
                
                # Simple arch detection from hostname or hardware JSON if available
                if "arm" in hostname_lower or "aarch64" in hostname_lower:
                    arch = "arm64"
                
                if agent.HardwareJson:
                    try:
                        hw = json.loads(agent.HardwareJson)
                        model = hw.get("CpuModel", "").lower()
                        if "arm" in model or "apple" in model or "m1" in model or "m2" in model:
                            arch = "arm64"
                    except: pass
                
                update_os_type = f"{os_type}-{arch}" if os_type != "windows" else "windows"
                update_url = f"{backend_url.rstrip('/')}/api/downloads/public/payload?key={tenant.ApiKey}&os_type={update_os_type}"
                
                # --- v1.8.41: HMAC Update Handshake ---
                update_hash = ""
                update_signature = ""
                
                try:
                    # 1. Locate Binary in AgentTemplate
                    template_map = {
                        "linux-x64": "linux-x64", "linux-arm64": "linux-arm64",
                        "mac-arm64": "osx-arm64", "mac-x64": "osx-x64", "windows": "win-x64"
                    }
                    folder = template_map.get(update_os_type, "win-x64")
                    file_dir = os.path.dirname(os.path.abspath(__file__))
                    base_path = os.path.normpath(os.path.join(file_dir, "..", "..", "storage", "AgentTemplate", folder))
                    
                    # Target correct filename (Consistent with downloads.py)
                    fname = "monitorix.zip"
                    if "linux" in update_os_type: fname = "monitorix-agent-linux"
                    elif "mac" in update_os_type: fname = "monitorix-agent-mac"
                    
                    bin_path = os.path.join(base_path, fname)
                    if os.path.exists(bin_path):
                        # 2. Calculate Binary SHA256
                        sha_calc = hashlib.sha256()
                        with open(bin_path, "rb") as f:
                            for chunk in iter(lambda: f.read(8192), b""): 
                                sha_calc.update(chunk)
                        update_hash = sha_calc.hexdigest()
                        
                        # 3. Generate Ed25519 Asymmetric Signature [v2.0.0]
                        try:
                            from app.core.security import sign_payload_asymmetric
                            msg = f"{agent.TargetVersion}|{update_hash or ''}".encode()
                            update_signature = sign_payload_asymmetric(msg)
                            print(f"[PATCH] Generated Ed25519 signature: {update_signature} for version: {agent.TargetVersion}")
                            
                            # [v1.8.59] De-duplication: Move to dispatching state to avoid re-calculation
                            agent.UpdateStatus = "dispatching_update"
                        except Exception as sig_err:
                            print(f"[PATCH] Ed25519 signature calculation failed: {sig_err}")
                    else:
                        print(f"[PATCH] Binary not found at {bin_path}. Handshake will fail on agent.")
                except Exception as e:
                    print(f"[PATCH] Signature error: {e}")

        # 5. Create Periodic Status Report (for Resource History)
        from ..db.models import AgentReportEntity # type: ignore
        report_ts = datetime.utcnow()
        if payload.Timestamp:
            try:
                if isinstance(payload.Timestamp, datetime):
                    report_ts = payload.Timestamp
                else:
                    # Clean timestamp string and parse
                    ts_str = str(payload.Timestamp).replace("Z", "+00:00")
                    report_ts = datetime.fromisoformat(ts_str)
            except Exception as e:
                print(f"[HEARTBEAT] Timestamp parse error: {e}")
        
        # Ensure naive UTC for database
        if report_ts.tzinfo is not None:
            report_ts = report_ts.astimezone(None).replace(tzinfo=None)

        # [EXTRACT] Telemetry from Payload
        disk_usage = 0.0
        if payload.Hardware:
            try:
                # Calculate Disk % if stats are there
                total = payload.Hardware.get("DiskTotalGB", 1)
                free = payload.Hardware.get("DiskFreeGB", 0)
                disk_usage = round(((total - free) / total) * 100, 1)
            except: pass
        
        # [NEW] Capture Top Processes if sent
        top_proc = None
        if hasattr(payload, "TopProcessesJson"):
            top_proc = getattr(payload, "TopProcessesJson")

        new_report = AgentReportEntity(
            AgentId=agent.AgentId,
            TenantId=tenant.Id,
            Status=payload.Status,
            CpuUsage=payload.CpuUsage,
            MemoryUsage=payload.MemoryUsage,
            DiskUsage=disk_usage,
            NetworkInMbps=payload.NetworkInMbps,
            NetworkOutMbps=payload.NetworkOutMbps,
            TopProcessesJson=top_proc,
            Timestamp=report_ts
        )
        db.add(new_report)
        # SINGLE COMMIT: agent update + report insert + IsPendingUninstall clear in one round-trip
        try:
            print(f"[DEBUG] Attempting final commit for {agent.AgentId}...")
            await db.commit()
            print(f"[DEBUG] Final commit SUCCESS for {agent.AgentId}")
        except Exception as e:
            print(f"[DEBUG] Final commit FAILED for {agent.AgentId}: {e}")
            await db.rollback()
            # Non-blocking crash log write
            error_log = f"[HEARTBEAT RETRY] Data truncation issue for {agent.AgentId}: {e}\n"
            asyncio.create_task(asyncio.to_thread(lambda: open('heartbeat_crash.log','a').write(error_log)))
            # RECOVERY: clear heavy fields, retry
            agent.InstalledSoftwareJson = None
            agent.HardwareJson = None
            db.add(new_report)
            await db.commit()
        
        # 6. Real-time Dashboard Updates (Socket.IO)
        try:
            ts_str = report_ts.strftime("%H:%M")
            await sio.emit('dashboard_stats_update', {
                'type': 'resource',
                'data': {'time': ts_str, 'cpu': payload.CpuUsage, 'mem': payload.MemoryUsage, 'full_date': report_ts.isoformat()}
            }, room=f"tenant_{tenant.Id}")

            await sio.emit('agent_list_update', {
                'agentId': agent.AgentId, 'hostname': agent.Hostname, 'status': 'Online',
                'version': agent.Version, 'targetVersion': agent.TargetVersion,
                'cpuUsage': payload.CpuUsage, 'memoryUsage': payload.MemoryUsage,
                'powerStatusJson': agent.PowerStatusJson,
                'latitude': agent.Latitude, 'longitude': agent.Longitude, 'country': agent.Country,
                'timestamp': report_ts.isoformat()
            }, room=f"tenant_{tenant.Id}")
        except: pass
        
        if agent.IsPendingUninstall:
            return {"status": "uninstall", "Uninstall": True}

        # 7. Prepare Response with updated Configuration
        plan_level = PLAN_LEVELS.get(tenant.Plan, 1)
        def check_feat_final(key, db_val):
            req_level = FEATURE_TIERS.get(key, 3)
            return db_val if plan_level >= req_level else False

        # 6. [v2.6.0] Sovereign Lockdown Enforcement (Scenario B: Ejected Tenants)
        sovereign_payload = None
        if tenant.IsLocked:
            # Construct a signed lockdown command for this agent
            action = "SOVEREIGN_LOCKDOWN"
            params = {"unlock_hash": tenant.UnlockKeyHash}
            timestamp = datetime.utcnow().isoformat()
            
            # Sign the Command (SHA256(ApiKey + MachineId))
            machine_id = agent.MachineId or agent.AgentId
            key = hashlib.sha256(tenant.ApiKey.encode() + machine_id.encode()).digest()
            msg_parts = [str(action), json.dumps(params, sort_keys=True), str(timestamp)]
            message = "|".join(msg_parts).encode('utf-8')
            signature = hmac.new(key, message, hashlib.sha256).hexdigest()
            
            sovereign_payload = {
                "action": action,
                "params": params,
                "timestamp": timestamp,
                "signature": signature,
                "policy_name": "Sovereign Lockdown (Tenant-Wide Enforcement)"
            }

        return {
            "status": "ok",
            "SovereignLockdown": sovereign_payload,
            "UpdateRequired": update_required,
            "UpdateUrl": update_url,
            "UpdateHash": update_hash if update_required else "",
            "UpdateSignature": update_signature if update_required else "",
            "TargetVersion": agent.TargetVersion,
            "config": {
                # Legacy Support
                "ScreenshotsEnabled": check_feat_final("ScreenshotsEnabled", agent.ScreenshotsEnabled),
                "UsbBlockingEnabled": check_feat_final("UsbBlockingEnabled", agent.UsbBlockingEnabled),
                "NetworkMonitoringEnabled": check_feat_final("NetworkMonitoringEnabled", agent.NetworkMonitoringEnabled),
                "FileDlpEnabled": check_feat_final("FileDlpEnabled", agent.FileDlpEnabled),
                "ActivityMonitorEnabled": check_feat_final("ActivityMonitorEnabled", agent.ActivityMonitorEnabled),
                "KeyloggerEnabled": check_feat_final("KeyloggerEnabled", agent.KeyloggerEnabled),
                "ClipboardMonitorEnabled": check_feat_final("ClipboardMonitorEnabled", agent.ClipboardMonitorEnabled),
                "AppBlockerEnabled": check_feat_final("AppBlockerEnabled", agent.AppBlockerEnabled),
                "BrowserEnforcerEnabled": check_feat_final("BrowserEnforcerEnabled", agent.BrowserEnforcerEnabled),
                "PrinterMonitorEnabled": check_feat_final("PrinterMonitorEnabled", agent.PrinterMonitorEnabled),
                "ShadowMonitorEnabled": check_feat_final("ShadowMonitorEnabled", agent.ShadowMonitorEnabled),
                "LiveStreamEnabled": check_feat_final("LiveStreamEnabled", agent.LiveStreamEnabled),
                "RemoteShellEnabled": check_feat_final("RemoteShellEnabled", agent.RemoteShellEnabled),
                "MailMonitorEnabled": check_feat_final("MailMonitorEnabled", agent.MailMonitorEnabled),
                "LocationTrackingEnabled": check_feat_final("LocationTrackingEnabled", agent.LocationTrackingEnabled),
                "SpeechMonitorEnabled": check_feat_final("SpeechMonitorEnabled", agent.SpeechMonitorEnabled),
                "GeolocationEnabled": geolocation_enabled,
                
                # Professional Terminology [v2.0]
                "VisualActivityEnabled": check_feat_final("ScreenshotsEnabled", agent.VisualActivityEnabled),
                "UsbComplianceEnabled": check_feat_final("UsbBlockingEnabled", agent.UsbComplianceEnabled),
                "NetworkAuditEnabled": check_feat_final("NetworkMonitoringEnabled", agent.NetworkAuditEnabled),
                "DataLossPreventionEnabled": check_feat_final("FileDlpEnabled", agent.DataLossPreventionEnabled),
                "InputAuditEnabled": check_feat_final("KeyloggerEnabled", agent.InputAuditEnabled),
                "ClipboardAuditEnabled": check_feat_final("ClipboardMonitorEnabled", agent.ClipboardAuditEnabled),
                "AppEnforcementEnabled": check_feat_final("AppBlockerEnabled", agent.AppEnforcementEnabled),
                "BrowserComplianceEnabled": check_feat_final("BrowserEnforcerEnabled", agent.BrowserComplianceEnabled),
                "PrintAuditEnabled": check_feat_final("PrinterMonitorEnabled", agent.PrintAuditEnabled),
                "ShadowAuditEnabled": check_feat_final("ShadowMonitorEnabled", agent.ShadowAuditEnabled),
                "SessionForensicEnabled": check_feat_final("LiveStreamEnabled", agent.SessionForensicEnabled),
                "RemoteRemediationEnabled": check_feat_final("RemoteShellEnabled", agent.RemoteRemediationEnabled),
                "MailIntelligenceEnabled": check_feat_final("MailMonitorEnabled", agent.MailIntelligenceEnabled),
                "VoiceIntelligenceEnabled": check_feat_final("SpeechMonitorEnabled", agent.VoiceIntelligenceEnabled),
                "LocationAuditEnabled": check_feat_final("LocationTrackingEnabled", agent.LocationAuditEnabled),
                "MonitoringConsentRequired": agent.MonitoringConsentRequired,
                "VulnerabilityIntelligenceEnabled": check_feat_final("VulnerabilityIntelligenceEnabled", agent.VulnerabilityIntelligenceEnabled),
                
                # Common Settings
                "TenantName": tenant.Name,
                "ScreenshotQuality": agent.ScreenshotQuality,
                "ScreenshotResolution": agent.ScreenshotResolution,
                "MaxScreenshotSize": agent.MaxScreenshotSize,
                "ScreenshotInterval": screenshot_interval,
                "BlockedApps": agent.BlockedAppsJson or "[]",
                "ShadowPaths": agent.ShadowPathsJson or "[]",
                "BandwidthConfig": bandwidth_config
            }
        }

    except Exception as e:
        import traceback # type: ignore
        error_msg = f"[HEARTBEAT ERROR] {type(e).__name__}: {str(e)}\n{traceback.format_exc()}"
        print(error_msg)
        # Non-blocking crash log write (don't block the event loop on disk I/O)
        try:
            asyncio.create_task(asyncio.to_thread(lambda: open('heartbeat_crash.log','a').write(error_msg + '\n')))
        except: pass
        
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Internal Server Error during heartbeat processing")

@router.post("/{agent_id}/events")
async def report_agent_event(
    agent_id: str,
    payload: AgentEvent,
    db: AsyncSession = Depends(get_db),
    tenant: Tenant = Depends(get_tenant_by_key)
):
    # Backward Compatibility for API Key
    if not tenant:
        if not payload.TenantApiKey:
             raise HTTPException(status_code=401, detail="API Key required")
        result_tenant = await db.execute(select(Tenant).where(Tenant.ApiKey == payload.TenantApiKey))
        tenant = result_tenant.scalars().first()
        if not tenant:
            raise HTTPException(status_code=401, detail="Invalid API Key")

    # 1. Find Agent & Verify Tenant Ownership
    result = await db.execute(
        select(Agent).where(Agent.AgentId == agent_id, Agent.TenantId == tenant.Id)
    )
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    # 2. Log to Audit
    from ..db.models import AuditLog # type: ignore
    from datetime import datetime # type: ignore
    
    print(f"[EVENT] Agent {agent_id}: {payload.EventType} - {payload.Message}")
    
    audit = AuditLog(
        TenantId=agent.TenantId,
        Actor="System (Agent)",
        Action=payload.EventType,
        Target=f"{agent.Hostname} ({agent.AgentId})",
        Details=payload.Message,
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    
    # [v1.8.2] Real-time Alerts
    from ..core.notifications import notify_event # type: ignore
    await notify_event(
        tenant_id=agent.TenantId,
        event_type=payload.EventType,
        details={
            "agent_id": agent.AgentId,
            "hostname": agent.Hostname,
            "msg": payload.Message,
            "timestamp": datetime.utcnow().isoformat()
        },
        db=db
    )

    # [FIX] Revival Logic
    if payload.EventType == "System" and "Started" in payload.Message:
        if agent.IsPendingUninstall:
            print(f"[RECOVERY] Agent {agent_id} reported STATED - Clearing Pending Uninstall flag.")
            agent.IsPendingUninstall = False
            await db.commit()

    return {"status": "received"}

@router.delete("/{agent_identifier}")
async def delete_agent(
    agent_identifier: str, # Accepts Database ID (int) OR Agent ID (string)
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    if current_user.Role != "SuperAdmin" and current_user.Role != "TenantAdmin":
         raise HTTPException(status_code=403, detail="Not authorized")

    # Try to resolve agent
    agent = None
    
    # 1. Try as Integer Database ID
    if agent_identifier.isdigit():
        result = await db.execute(select(Agent).where(Agent.Id == int(agent_identifier)))
        agent = result.scalars().first()
    
    # 2. If not found or not integer, try as String Agent ID
    if not agent:
        result = await db.execute(select(Agent).where(Agent.AgentId == agent_identifier))
        agent = result.scalars().first()

    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found by ID or String ID")
        
    # Check Tenant Scoping
    if current_user.Role == "TenantAdmin" and agent.TenantId != current_user.TenantId:
        raise HTTPException(status_code=404, detail="Agent not found") # Hide cross-tenant data

    # [FIX] Soft Delete to trigger remote uninstall
    # await db.delete(agent)
    agent.IsPendingUninstall = True
    
    # [AUDIT] Log Deletion
    from ..db.models import AuditLog # type: ignore
    from datetime import datetime # type: ignore
    
    audit = AuditLog(
        TenantId=current_user.TenantId if current_user.TenantId else (agent.TenantId or 1),
        Actor=current_user.Username,
        Action="Delete Agent",
        Target=f"{agent.Hostname} ({agent.AgentId})",
        Details="Agent deleted via API",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    
    await db.commit()
    
    return status.HTTP_204_NO_CONTENT

@router.post("/{agent_string_id}/toggle-screenshots")
async def toggle_screenshots(
    agent_string_id: str, # String ID (e.g. "DEVICE-123")
    enabled: bool,
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    # Find Agent
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_string_id))
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Check Tenant Scoping
    if current_user.Role != "SuperAdmin":
        if not current_user.TenantId or agent.TenantId != current_user.TenantId:
             raise HTTPException(status_code=403, detail="Not authorized")

    agent.ScreenshotsEnabled = enabled

    # [NEW] Verify Plan
    # Optimization: We check AFTER finding agent (for Tenant access) but BEFORE commit.
    if enabled:
        # Fetch Tenant Plan
        from ..db.models import Tenant # type: ignore
        t_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
        tenant = t_res.scalars().first()
        if tenant:
             verify_feature_access(tenant.Plan, "ScreenshotsEnabled")
    
    # [AUDIT]
    from datetime import datetime # type: ignore
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action="Toggle Screenshots",
        Target=f"{agent.Hostname} ({agent.AgentId})",
        Details=f"Screenshots {'Enabled' if enabled else 'Disabled'}",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    
    await db.commit()
    
    # Notify Agent
    await sio.emit('UpdateConfig', {'ScreenshotsEnabled': enabled}, room=agent_string_id)
    
    return {"AgentId": agent.AgentId, "ScreenshotsEnabled": agent.ScreenshotsEnabled}

@router.post("/{agent_id}/screenshot-settings")
async def update_screenshot_settings(
    agent_id: str,
    payload: AgentSettingsUpdate,
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    # Find Agent
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Check Tenant Scoping
    if current_user.Role != "SuperAdmin":
        if not current_user.TenantId or agent.TenantId != current_user.TenantId:
             raise HTTPException(status_code=403, detail="Not authorized")

    # Update Fields
    if payload.ScreenshotQuality is not None:
        agent.ScreenshotQuality = payload.ScreenshotQuality
    if payload.ScreenshotInterval is not None:
        agent.ScreenshotInterval = payload.ScreenshotInterval
    if payload.ScreenshotResolution is not None:
        agent.ScreenshotResolution = payload.ScreenshotResolution
    if payload.MaxScreenshotSize is not None:
        agent.MaxScreenshotSize = payload.MaxScreenshotSize
        
    # [AUDIT]
    from datetime import datetime # type: ignore
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action="Update Screenshot Settings",
        Target=f"{agent.Hostname} ({agent.AgentId})",
        Details=f"Interval: {agent.ScreenshotInterval}, Quality: {agent.ScreenshotQuality}",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    
    await db.commit()
    
    # [REAL-TIME SYNC]
    await sio.emit('UpdateConfig', {
        'ScreenshotInterval': agent.ScreenshotInterval,
        'ScreenshotQuality': agent.ScreenshotQuality,
        'ScreenshotResolution': agent.ScreenshotResolution,
        'MaxScreenshotSize': agent.MaxScreenshotSize
    }, room=agent.AgentId)
    
    return {
        "AgentId": agent.AgentId, 
        "ScreenshotInterval": agent.ScreenshotInterval,
        "ScreenshotQuality": agent.ScreenshotQuality
    }

@router.post("/{agent_string_id}/toggle-location")
async def toggle_location(
    agent_string_id: str,
    enabled: bool,
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    # Find Agent
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_string_id))
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Check Tenant Scoping
    if current_user.Role != "SuperAdmin":
        if not current_user.TenantId or agent.TenantId != current_user.TenantId:
             raise HTTPException(status_code=403, detail="Not authorized")

    agent.LocationTrackingEnabled = enabled
    
    if enabled:
        from ..db.models import Tenant # type: ignore
        t_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
        tenant = t_res.scalars().first()
        if tenant:
             verify_feature_access(tenant.Plan, "LocationTrackingEnabled")
    
    # [AUDIT]
    from datetime import datetime # type: ignore
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action="Toggle Location",
        Target=f"{agent.Hostname} ({agent.AgentId})",
        Details=f"Location Tracking {'Enabled' if enabled else 'Disabled'}",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    
    await db.commit()
    
    # Notify Agent (reuse UpdateConfig event)
    await sio.emit('UpdateConfig', {'LocationTrackingEnabled': enabled}, room=agent_string_id)
    
    return {"AgentId": agent.AgentId, "LocationTrackingEnabled": agent.LocationTrackingEnabled}

@router.post("/{agent_string_id}/toggle-usb")
async def toggle_usb(
    agent_string_id: str,
    enabled: bool,
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    # Find Agent
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_string_id))
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Check Tenant Scoping
    if current_user.Role != "SuperAdmin":
        if not current_user.TenantId or agent.TenantId != current_user.TenantId:
             raise HTTPException(status_code=403, detail="Not authorized")

    agent.UsbBlockingEnabled = enabled
    
    if enabled:
        from ..db.models import Tenant # type: ignore
        t_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
        tenant = t_res.scalars().first()
        if tenant:
             verify_feature_access(tenant.Plan, "UsbBlockingEnabled")
    
    # [AUDIT]
    from datetime import datetime # type: ignore
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action="Toggle USB Blocking",
        Target=f"{agent.Hostname} ({agent.AgentId})",
        Details=f"USB Blocking {'Enabled' if enabled else 'Disabled'}",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    
    await db.commit()
    
    # Notify Agent
    await sio.emit('UpdateConfig', {'UsbBlockingEnabled': enabled}, room=agent_string_id)
    
    return {"AgentId": agent.AgentId, "UsbBlockingEnabled": agent.UsbBlockingEnabled}

@router.post("/{agent_id}/policy")
async def assign_policy(
    agent_id: str,
    payload: dict, # { "policyId": 123 } or { "policyId": null }
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    """Assign or Unassign a Policy to an Agent"""
    
    # 1. Find Agent
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    if current_user.Role != "SuperAdmin" and agent.TenantId != current_user.TenantId:
         raise HTTPException(status_code=403, detail="Not authorized")

    policy_id = payload.get("policyId")
    
    if policy_id:
        # Verify Policy Exists and belongs to Tenant
        p_res = await db.execute(select(Policy).where(Policy.Id == policy_id))
        policy = p_res.scalars().first()
        
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
            
        if current_user.Role != "SuperAdmin" and policy.TenantId != current_user.TenantId:
            raise HTTPException(status_code=403, detail="Policy belongs to another tenant")
            
        agent.PolicyId = policy_id
        
        # [OPTIONAL] Apply Policy Rules flags immediately?
        # For now, we rely on next heartbeat to sync, OR (Better) we trigger an update.
        # But policies are complex objects. Let's trigger a config update command.
        # However, we need to resolve the policy to flags first.
        # STARTUP sync is safest. 
        # But we can notify the agent that "Config Updated" to trigger an immediate heartbeat/pull.
        
    else:
        agent.PolicyId = None
        
    await db.commit()
    
    # Notify Agent to pull new config
    # We send an empty UpdateConfig to force a re-eval or just a specific command
    await sio.emit('UpdateConfig', {'_ForceRefresh': True}, room=agent.AgentId)
    
    return {"status": "assigned", "policyId": agent.PolicyId}


@router.post("/{agent_string_id}/toggle-network")
async def toggle_network(
    agent_string_id: str,
    enabled: bool,
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    # Find Agent
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_string_id))
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Check Tenant Scoping
    if current_user.Role != "SuperAdmin":
        if not current_user.TenantId or agent.TenantId != current_user.TenantId:
             raise HTTPException(status_code=403, detail="Not authorized")

    agent.NetworkMonitoringEnabled = enabled

    if enabled:
        from ..db.models import Tenant # type: ignore
        t_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
        tenant = t_res.scalars().first()
        if tenant:
             verify_feature_access(tenant.Plan, "NetworkMonitoringEnabled")
    
    # [AUDIT]
    from datetime import datetime # type: ignore
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action="Toggle Network Monitoring",
        Target=f"{agent.Hostname} ({agent.AgentId})",
        Details=f"Network Monitoring {'Enabled' if enabled else 'Disabled'}",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    
    await db.commit()
    
    # Notify Agent
    await sio.emit('UpdateConfig', {'NetworkMonitoringEnabled': enabled}, room=agent_string_id)
    
    return {"AgentId": agent.AgentId, "NetworkMonitoringEnabled": agent.NetworkMonitoringEnabled}

@router.post("/{agent_string_id}/toggle-file-dlp")
async def toggle_file_dlp(
    agent_string_id: str,
    enabled: bool,
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    # Find Agent
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_string_id))
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Check Tenant Scoping
    if current_user.Role != "SuperAdmin":
        if not current_user.TenantId or agent.TenantId != current_user.TenantId:
             raise HTTPException(status_code=403, detail="Not authorized")

    agent.FileDlpEnabled = enabled

    if enabled:
        from ..db.models import Tenant # type: ignore
        t_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
        tenant = t_res.scalars().first()
        if tenant:
             verify_feature_access(tenant.Plan, "FileDlpEnabled")
    
    # [AUDIT]
    from datetime import datetime # type: ignore
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action="Toggle File DLP",
        Target=f"{agent.Hostname} ({agent.AgentId})",
        Details=f"File DLP {'Enabled' if enabled else 'Disabled'}",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    
    await db.commit()
    
    # Notify Agent
    await sio.emit('UpdateConfig', {'FileDlpEnabled': enabled}, room=agent_string_id)
    
    return {"AgentId": agent.AgentId, "FileDlpEnabled": agent.FileDlpEnabled}

@router.post("/{agent_string_id}/toggle-feature")
async def toggle_agent_feature(
    agent_string_id: str,
    feature: str,
    enabled: bool,
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    # Find Agent
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_string_id))
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Check Tenant Scoping & Role
    if current_user.Role != "SuperAdmin":
        if not current_user.TenantId or agent.TenantId != current_user.TenantId:
             raise HTTPException(status_code=403, detail="Not authorized")
        
        if current_user.Role != "TenantAdmin":
             raise HTTPException(status_code=403, detail="Permission Denied: Only TenantAdmins can toggle features.")


    # Map feature string to column
    feature_map = {
        "activity": "ActivityMonitorEnabled",
        "keylogger": "KeyloggerEnabled",
        "clipboard": "ClipboardMonitorEnabled",
        "app_blocker": "AppBlockerEnabled",
        "browser": "BrowserEnforcerEnabled",
        "printer": "PrinterMonitorEnabled",
        "shadow": "ShadowMonitorEnabled",
        "live_stream": "LiveStreamEnabled",
        "remote_shell": "RemoteShellEnabled",
        "mail": "MailMonitorEnabled",
        "screenshots": "ScreenshotsEnabled",
        "location": "GeolocationEnabled",
        "usb": "UsbBlockingEnabled",
        "network": "NetworkMonitoringEnabled",
        "file_dlp": "FileDlpEnabled",
        "speech": "SpeechMonitorEnabled",
        "vuln": "VulnerabilityIntelligenceEnabled"
    }

    if feature not in feature_map:
        raise HTTPException(status_code=400, detail="Invalid feature name")

    col_name = feature_map[feature]
    
    if enabled:
        from ..db.models import Tenant # type: ignore
        t_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
        tenant = t_res.scalars().first()
        if tenant:
             verify_feature_access(tenant.Plan, col_name)

    setattr(agent, col_name, enabled)
    
    # [AUDIT]
    from datetime import datetime # type: ignore
    from ..db.models import AuditLog # type: ignore
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action=f"Toggle {feature}",
        Target=f"{agent.Hostname} ({agent.AgentId})",
        Details=f"Feature '{feature}' {'Enabled' if enabled else 'Disabled'}",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    await db.commit()
    
    # Notify Agent
    # Many features use their own keys in config, but we can send a bulk UpdateConfig
    # The agent main loop will handle individual flags.
    await sio.emit('UpdateConfig', {col_name: enabled}, room=agent_string_id)
    
    return {"AgentId": agent.AgentId, "feature": feature, "enabled": enabled}

@router.post("/{agent_string_id}/take-screenshot")
async def take_screenshot(
    agent_string_id: str,
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    try:
        # Local import to avoid circular dependencies
        # from ..socket_instance import sio

        # Find Agent
        result = await db.execute(select(Agent).where(Agent.AgentId == agent_string_id))
        agent = result.scalars().first()
        
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Check Tenant Scoping
        if current_user.Role != "SuperAdmin":
            if not current_user.TenantId or agent.TenantId != current_user.TenantId:
                 raise HTTPException(status_code=403, detail="Not authorized")

        # Emit Command to Agent Room
        print(f"[API] Triggering Manual Screenshot for {agent.AgentId}")
        await sio.emit('TakeScreenshot', {'AgentId': agent.AgentId}, room=agent.AgentId)

        # [AUDIT]
        from datetime import datetime # type: ignore
        audit = AuditLog(
            TenantId=current_user.TenantId or 0,
            Actor=current_user.Username,
            Action="Trigger Screenshot",
            Target=f"{agent.Hostname} ({agent.AgentId})",
            Details="Manual screenshot requested via Dashboard",
            Timestamp=datetime.utcnow()
        )
        db.add(audit)
        await db.commit()

        return {"status": "triggered", "agentId": agent.AgentId}
    except Exception as e:
        import traceback # type: ignore
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Internal Error: {str(e)}")

@router.post("/{agent_id}/sbom")
async def update_agent_sbom(
    agent_id: str,
    payload: list, # List of { "name": "...", "version": "...", "type": "..." }
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """[v2.6.0] Updates the Software Bill of Materials for an agent."""
    from ..db.models import AgentSoftware # type: ignore
    from sqlalchemy import delete # type: ignore
    
    # 1. Clear old inventory for this agent
    await db.execute(delete(AgentSoftware).where(AgentSoftware.AgentId == agent_id))
    
    # 2. Bulk insert new inventory
    new_items = [
        AgentSoftware(
            AgentId=agent_id,
            Name=item.get("name"),
            Version=item.get("version"),
            Type=item.get("type", "OS"),
            LastSeen=datetime.utcnow()
        ) for item in payload
    ]
    
    db.add_all(new_items)
    await db.commit()
    return {"status": "success", "count": len(new_items)}

def validate_shadow_paths(paths: List[str]):
    """
    Prevents administrators from configuring agents to shadow (steal) 
    sensitive OS-level files or browser credentials.
    """
    if not paths: return
    
    blacklist = [
        # Windows
        "C:\\Windows", "C:\\System Volume Information", "C:\\Users\\All Users",
        "System32", "SysWOW64", "config\\SAM",
        # Linux
        "/etc", "/root", "/boot", "/dev", "/proc", "/sys", "/var/lib/docker",
        # App/Browser Data (Universal)
        ".ssh", ".gnupg", ".aws", "Cookies", "Login Data", "Local Storage",
        "Web Data", "History", "Passwords"
    ]
    
    for path in paths:
        normalized = str(path).replace("/", "\\").upper()
        for blocked in blacklist:
            if blocked.upper() in normalized:
                 raise HTTPException(
                     status_code=403, 
                     detail=f"Security Restriction: Monitoring of system-critical path '{path}' is prohibited."
                 )

from ..schemas import AgentSettingsUpdate # type: ignore

@router.post("/{agent_string_id}/settings")
async def update_settings(
    agent_string_id: str,
    settings: AgentSettingsUpdate,
    current_user: User = Depends(check_role(["SuperAdmin", "TenantAdmin"])),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_string_id))
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    if current_user.Role != "SuperAdmin":
        if not current_user.TenantId or agent.TenantId != current_user.TenantId:
             raise HTTPException(status_code=403, detail="Not authorized")

    # Partial Updates: only change fields if they are explicitly sent
    if settings.ScreenshotQuality is not None:
        agent.ScreenshotQuality = settings.ScreenshotQuality
    if settings.ScreenshotResolution is not None:
        agent.ScreenshotResolution = settings.ScreenshotResolution
    if settings.MaxScreenshotSize is not None:
        agent.MaxScreenshotSize = settings.MaxScreenshotSize
    if settings.ScreenshotInterval is not None:
        agent.ScreenshotInterval = settings.ScreenshotInterval
    
    # Toggle Mapping for Professional Terminology [v2.0]
    toggle_map = {
        "VisualActivityEnabled": "VisualActivityEnabled",
        "InputAuditEnabled": "InputAuditEnabled",
        "ClipboardAuditEnabled": "ClipboardAuditEnabled",
        "AppEnforcementEnabled": "AppEnforcementEnabled",
        "BrowserComplianceEnabled": "BrowserComplianceEnabled",
        "PrintAuditEnabled": "PrintAuditEnabled",
        "ShadowAuditEnabled": "ShadowAuditEnabled",
        "SessionForensicEnabled": "SessionForensicEnabled",
        "RemoteRemediationEnabled": "RemoteRemediationEnabled",
        "MailIntelligenceEnabled": "MailIntelligenceEnabled",
        "VoiceIntelligenceEnabled": "VoiceIntelligenceEnabled",
        "LocationAuditEnabled": "LocationAuditEnabled",
        "UsbComplianceEnabled": "UsbComplianceEnabled",
        "NetworkAuditEnabled": "NetworkAuditEnabled",
        "DataLossPreventionEnabled": "DataLossPreventionEnabled",
        "VulnerabilityIntelligenceEnabled": "VulnerabilityIntelligenceEnabled",
        "MonitoringConsentRequired": "MonitoringConsentRequired"
    }
    
    changed_features = []
    for schema_key, db_attr in toggle_map.items():
        val = getattr(settings, schema_key, None)
        if val is not None:
            old_val = getattr(agent, db_attr)
            if old_val != val:
                setattr(agent, db_attr, val)
                changed_features.append(f"{schema_key}: {val}")

    # [NEW] Enforce Plan Limits
    from ..db.models import Tenant # type: ignore
    t_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant = t_res.scalars().first()

    
    if settings.BlockedApps is not None:
         # Check Plan
         if tenant: verify_feature_access(tenant.Plan, "AppBlockerEnabled")
         import json # type: ignore
         agent.BlockedAppsJson = json.dumps(settings.BlockedApps)
    
    if settings.ShadowPaths is not None:
         # Check Plan
         if tenant: verify_feature_access(tenant.Plan, "ShadowMonitorEnabled")
         
         # [SECURITY] Prevent OS exfiltration
         validate_shadow_paths(settings.ShadowPaths)
         
         import json # type: ignore
         agent.ShadowPathsJson = json.dumps(settings.ShadowPaths)

    # [AUDIT]
    from datetime import datetime # type: ignore
    details = f"Quality: {settings.ScreenshotQuality}, Interval: {settings.ScreenshotInterval}s"
    if changed_features:
        details += f" | Toggles: {', '.join(changed_features)}"
    if settings.BlockedApps is not None:
        details += f" | Blocked: {len(settings.BlockedApps)}"
        
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action="Update Security Policy",
        Target=f"{agent.Hostname} ({agent.AgentId})",
        Details=details,
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    
    await db.commit()
    
    # Notify Agent
    await sio.emit('UpdateConfig', {
        'ScreenshotQuality': agent.ScreenshotQuality,
        'ScreenshotResolution': agent.ScreenshotResolution,
        'MaxScreenshotSize': agent.MaxScreenshotSize,
        'ScreenshotInterval': agent.ScreenshotInterval,
        'BlockedApps': settings.BlockedApps if settings.BlockedApps is not None else json.loads(agent.BlockedAppsJson),
        'ShadowPaths': settings.ShadowPaths if settings.ShadowPaths is not None else json.loads(agent.ShadowPathsJson)
    }, room=agent_string_id)

    
    return {"status": "Updated", "settings": settings}

@router.post("/{agent_string_id}/blocked-apps")
async def update_blocked_apps(
    agent_string_id: str,
    apps: List[str], # Body: ["steam.exe", "spotify.exe"]
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    # Find Agent
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_string_id))
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    if current_user.Role != "SuperAdmin":
        if not current_user.TenantId or agent.TenantId != current_user.TenantId:
             raise HTTPException(status_code=403, detail="Not authorized")
             
    # [NEW] Enforce Plan
    from ..db.models import Tenant # type: ignore
    t_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant = t_res.scalars().first()
    if tenant:
         verify_feature_access(tenant.Plan, "AppBlockerEnabled")
             
    import json # type: ignore
    agent.BlockedAppsJson = json.dumps(apps)
    
    # Audit
    from datetime import datetime # type: ignore
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action="Update Blocked Apps",
        Target=f"{agent.Hostname} ({agent.AgentId})",
        Details=f"Blocked: {', '.join(apps[:5])}...", # type: ignore
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    
    await db.commit()
    
    # Notify Agent
    await sio.emit('UpdateConfig', {'BlockedApps': apps}, room=agent_string_id)
    
    return {"AgentId": agent.AgentId, "BlockedApps": apps}

@router.post("/{agent_string_id}/patch-now")
async def patch_now(
    agent_string_id: str,
    target_version: Optional[str] = None,
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    """Administrator Override: Force an immediately available update regardless of maintenance window."""
    if current_user.Role not in ["SuperAdmin", "TenantAdmin"]:
         raise HTTPException(status_code=403, detail="Not authorized")
         
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_string_id))
    agent = result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    if current_user.Role != "SuperAdmin" and agent.TenantId != current_user.TenantId:
        raise HTTPException(status_code=403, detail="Access denied")
        
    # Set the target version
    target = target_version or LATEST_AGENT_VERSION
    agent.TargetVersion = target
    agent.UpdateStatus = "pending_manual_push"
    
    # [AUDIT]
    audit = AuditLog(
        TenantId=agent.TenantId,
        Actor=current_user.Username,
        Action="Push Manual Patch",
        Target=f"{agent.Hostname} ({agent.AgentId})",
        Details=f"Forcing immediate patch to {target}",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    await db.commit()
    
    return {"status": "success", "TargetVersion": target, "Message": "Agent will update on next heartbeat."}

@router.post("/patch-batch")
async def patch_agents_batch(
    agent_ids: List[str],
    batch_size: int = 10,
    delay: int = 60,
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    """
    Administrator Utility: Triggers a staggered rolling update for a list of agents.
    Useful for larger deployments (300+ agents) to avoid bandwidth spikes.
    """
    if current_user.Role not in ["SuperAdmin", "TenantAdmin"]:
         raise HTTPException(status_code=403, detail="Not authorized")

    if not agent_ids:
         raise HTTPException(status_code=400, detail="No Agent IDs provided.")

    # [v1.8.60] Sovereignty Check: Ensure user only patches their own agents
    if current_user.Role != "SuperAdmin":
        check_query = select(Agent.AgentId).where(
            Agent.AgentId.in_(agent_ids),
            Agent.TenantId != current_user.TenantId
        )
        res = await db.execute(check_query)
        unauthorized = res.scalars().all()
        if unauthorized:
             raise HTTPException(
                 status_code=403, 
                 detail=f"Security Violation: Cross-tenant batch patch blocked for {len(unauthorized)} IDs."
             )

    # Launch Celery Background Task
    staggered_bulk_patch.delay(agent_ids, batch_size=batch_size, delay=delay)
    
    return {
        "status": "success", 
        "message": f"Staggered rolling update for {len(agent_ids)} agents dispatched to background worker.",
        "parameters": {"batch_size": batch_size, "delay_seconds": delay}
    }
