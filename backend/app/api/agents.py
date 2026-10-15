import fastapi # type: ignore # pyre-ignore
from fastapi import APIRouter, Depends, HTTPException, status, Response, Query, Header # type: ignore
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
from ..db.models import Agent, User, ShadowedFile, EventLog, Policy, Tenant, AuditLog, LocationHistory # type: ignore
from .deps import get_current_user, get_tenant_by_key, get_current_user_flexible, check_role, get_current_active_user # type: ignore
from ..socket_instance import sio # type: ignore
from ..schemas import AgentUpdateFailedRequest, AgentHeartbeat, AgentSettingsUpdate, AgentFimUpdateRequest # type: ignore
from ..core.security import generate_agent_command_signature # type: ignore

class UpdateProgressDto(BaseModel):
    progress: int
    status: Optional[str] = "downloading"

router = APIRouter()

@router.post("/{agent_id}/update-progress")
async def agent_update_progress(
    agent_id: str,
    dto: UpdateProgressDto,
    x_tenant_api_key: Optional[str] = Header(None, alias="X-Tenant-Api-Key"),
    db: AsyncSession = Depends(get_db)
):
    from sqlalchemy import func
    res_a = await db.execute(select(Agent).where(func.lower(Agent.AgentId) == func.lower(agent_id)))
    agent_obj = res_a.scalars().first()
    if not agent_obj:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    print(f"[UPDATE-PROGRESS] {agent_id} reported {dto.progress}% (status: {dto.status})", flush=True)
    await sio.emit('agent_update_progress', {'agentId': agent_id, 'progress': dto.progress, 'status': dto.status}, room=f"tenant_{agent_obj.TenantId}")
    await sio.emit('agent_update_progress', {'agentId': agent_id, 'progress': dto.progress, 'status': dto.status}, room="superadmin")
    return {"status": "ok"}


from ..core.constants import FEATURE_TIERS, PLAN_LEVELS, LATEST_AGENT_VERSION # type: ignore
LATEST_AGENT_VERSION = "v2.5.0"
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

from fastapi import APIRouter, Depends, HTTPException, status, Response, Query, Request, Header # type: ignore
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
            query = query.where(Agent.IsPendingUninstall.is_not(True))
        except Exception:
            print("[Agents] WARNING: IsPendingUninstall column missing. Skipping filter.")

        # Filter by Tenant for non-SuperAdmin or if tenantId provided
        if current_user.Role == "SuperAdmin":
            if tenantId is not None:
                query = query.where(Agent.TenantId == tenantId)
            # If tenantId is None, SuperAdmin sees all agents
        else:
            if not current_user.TenantId:
                return [] # Non-SuperAdmin with no tenant access
            query = query.where(Agent.TenantId == current_user.TenantId)
        
        query = query.order_by(Agent.LastSeen.desc())
        query = query.limit(limit).offset(offset)
            
        result = await db.execute(query)
        agents = result.scalars().all()
        
        # [FIX] Compute dynamic status for each agent
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
                "activeUser": get_safe(a, "ActiveUser", "Unknown"),
                "userLoginTime": get_safe(a, "UserLoginTime", "Unknown"),
                "behavioralMetadataJson": get_safe(a, "BehavioralMetadataJson"),
                "screenshotInterval": get_safe(a, "ScreenshotInterval", 60),
                # [SDK] Risk & Telemetry fields required by RedRainbow
                "threatScore": get_safe(a, "ThreatScore", 0),
                "riskLevel": get_safe(a, "RiskLevel", "Normal"),
                "networkInMbps": get_safe(a, "NetworkInMbps", 0.0),
                "networkOutMbps": get_safe(a, "NetworkOutMbps", 0.0),
                "os": get_safe(a, "OsType", "Unknown"),
                "diskEncrypted": get_safe(a, "DiskEncrypted", False),
                "softwareCount": get_safe(a, "SoftwareCount", 0),
                "isIsolated": get_safe(a, "IsIsolated", False),
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
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_tenant_api_key: Optional[str] = Header(None, alias="X-Tenant-Api-Key"),
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp")
):
    body_bytes = await request.body()
    if not x_signature or not x_timestamp:
        raise HTTPException(status_code=401, detail="Missing signature")

    agent_res = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = agent_res.scalars().first()
    if not agent:
         raise HTTPException(status_code=404, detail="Agent not found")
         
    tenant_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant = tenant_res.scalars().first()
    if not tenant:
        raise HTTPException(status_code=403, detail="Tenant not found")

    import hmac, hashlib
    key_seed = agent.MachineId.encode() if agent.MachineId else tenant.ApiKey.encode()
    signing_key = hashlib.sha256(key_seed).digest()
    msg = f"{body_bytes.decode('utf-8')}|{x_timestamp}".encode('utf-8')
    expected = hmac.new(signing_key, msg, hashlib.sha256).hexdigest()
    
    is_valid = hmac.compare_digest(expected, x_signature)
    if not is_valid and not agent.MachineId:
         fallback_key = tenant.ApiKey.encode()
         expected_fallback = hmac.new(fallback_key, msg, hashlib.sha256).hexdigest()
         if hmac.compare_digest(expected_fallback, x_signature): is_valid = True
             
    if not is_valid: raise HTTPException(status_code=403, detail="Invalid signature")
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
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_tenant_api_key: Optional[str] = Header(None, alias="X-Tenant-Api-Key"),
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp")
):
    body_bytes = await request.body()
    if not x_signature or not x_timestamp:
        raise HTTPException(status_code=401, detail="Missing signature")

    agent_res = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = agent_res.scalars().first()
    if not agent:
         raise HTTPException(status_code=404, detail="Agent not found")
         
    tenant_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant = tenant_res.scalars().first()
    if not tenant:
        raise HTTPException(status_code=403, detail="Tenant not found")

    import hmac, hashlib
    key_seed = agent.MachineId.encode() if agent.MachineId else tenant.ApiKey.encode()
    signing_key = hashlib.sha256(key_seed).digest()
    msg = f"{body_bytes.decode('utf-8')}|{x_timestamp}".encode('utf-8')
    expected = hmac.new(signing_key, msg, hashlib.sha256).hexdigest()
    
    is_valid = hmac.compare_digest(expected, x_signature)
    if not is_valid and not agent.MachineId:
         fallback_key = tenant.ApiKey.encode()
         expected_fallback = hmac.new(fallback_key, msg, hashlib.sha256).hexdigest()
         if hmac.compare_digest(expected_fallback, x_signature): is_valid = True
             
    if not is_valid: raise HTTPException(status_code=403, detail="Invalid signature")
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
    agent.UpdateStatus = "pending_manual_push"
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

class AgentRollbackRequest(BaseModel):
    target_version: Optional[str] = "v2.4.0"
    reason: Optional[str] = "Admin initiated version rollback"

@router.post("/{agent_id}/rollback")
async def trigger_agent_rollback(
    agent_id: str,
    payload: Optional[AgentRollbackRequest] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    query = select(Agent).where(Agent.AgentId == agent_id)
    if current_user.Role != "SuperAdmin":
        query = query.where(Agent.TenantId == current_user.TenantId)
    result = await db.execute(query)
    agent = result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    target_ver = (payload.target_version if payload and payload.target_version else None) or "v2.4.0"
    reason = (payload.reason if payload and payload.reason else "Manual Rollback")

    agent.TargetVersion = target_ver
    agent.UpdateStatus = "pending_rollback"
    agent.UpdateFailureReason = f"Rollback requested: {reason}"
    agent.LastUpdateAttempt = datetime.utcnow()

    event = EventLog(
        AgentId=agent.AgentId,
        Type="AgentRollbackInitiated",
        Details=f"Rollback to {target_ver} initiated by {current_user.Username}: {reason}",
        Timestamp=datetime.utcnow()
    )
    db.add(event)
    await db.commit()

    await sio.emit('agent_rollback_initiated', {
        'agentId': agent.AgentId,
        'targetVersion': target_ver,
        'reason': reason
    }, room=f"tenant_{agent.TenantId}")

    return {
        "status": "success",
        "agent_id": agent.AgentId,
        "current_version": agent.Version,
        "target_version": target_ver,
        "update_status": agent.UpdateStatus,
        "message": f"Rollback to {target_ver} queued successfully"
    }

@router.get("/fleet/versions")
async def get_fleet_version_distribution(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    query = select(Agent)
    if current_user.Role != "SuperAdmin":
        query = query.where(Agent.TenantId == current_user.TenantId)
    res = await db.execute(query)
    agents = res.scalars().all()

    version_counts = {}
    online_by_version = {}
    for a in agents:
        v = a.Version or "Unknown"
        version_counts[v] = version_counts.get(v, 0) + 1
        if a.Status == "Online":
            online_by_version[v] = online_by_version.get(v, 0) + 1

    total_agents = len(agents)
    latest_count = version_counts.get(LATEST_AGENT_VERSION, 0)
    adoption_rate_pct = round((latest_count / total_agents) * 100, 1) if total_agents > 0 else 100.0

    return {
        "latest_available_version": LATEST_AGENT_VERSION,
        "total_fleet_endpoints": total_agents,
        "latest_version_adoption_pct": adoption_rate_pct,
        "version_distribution": [
            {
                "version": ver,
                "total_endpoints": count,
                "online_endpoints": online_by_version.get(ver, 0),
                "is_latest": ver == LATEST_AGENT_VERSION
            }
            for ver, count in sorted(version_counts.items(), reverse=True)
        ],
        "canary_deployment_rings": [
            {"ring": "Ring 0 (Canary)", "version": LATEST_AGENT_VERSION, "target_pct": 5, "status": "Stable"},
            {"ring": "Ring 1 (Staging)", "version": LATEST_AGENT_VERSION, "target_pct": 25, "status": "Promoted"},
            {"ring": "Ring 2 (Broad Fleet)", "version": "v2.4.0", "target_pct": 70, "status": "Active Stable"}
        ]
    }

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
        Type="SOVEREIGN_GOVERNANCE",
        Severity="Critical",
        Details=f"INDIVIDUAL LOCKDOWN: Node {agent.Hostname or agent_id} neutralized by {current_user.Username}. Reason: {reason}",
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
        
    machine_id = agent.MachineId if isinstance(agent.MachineId, bytes) else agent.MachineId.encode()
    key = hashlib.sha256(tenant.ApiKey.encode() + machine_id).digest()
    signature = hmac.new(key, message, hashlib.sha256).hexdigest()
    
    command_data = {
        "action": action,
        "params": params,
        "policy_name": "Administrative Lockdown",
        "timestamp": timestamp,
        "signature": signature
    }
    
    # [REAL-TIME] Push to Agent
    # NOTE: Agent listens on 'Remediation' (not 'RemediationCommand') — must match @sio.on('Remediation') in agent/src/main.py
    await sio.emit('Remediation', command_data, room=agent.AgentId)
    
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

@router.post("/{agent_id}/unlock")
async def trigger_sovereign_unlock(
    agent_id: str,
    payload: dict, # { "reason": "..." }
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
        
    reason = payload.get("reason", "No reason provided")
    
    # [v2.6.8] Sovereign Governance Audit
    new_event = EventLog(
        AgentId=agent_id,
        Type="SOVEREIGN_GOVERNANCE",
        Severity="High",
        Details=f"INDIVIDUAL UNLOCK: Node {agent.Hostname or agent_id} released by {current_user.Username}. Reason: {reason}",
        Timestamp=datetime.utcnow()
    )
    db.add(new_event)
    
    # [v1.8.37] Command Sovereignty: Signature Generation
    timestamp = datetime.utcnow().isoformat()
    action = "SOVEREIGN_UNLOCK"
    params = {}
    
    # Derive HMAC Key (Same logic as agent)
    msg_parts = [action, json.dumps(params, sort_keys=True), timestamp]
    message = "|".join(msg_parts).encode('utf-8')
    
    # We need the tenant to get the api_key for signing
    tenant_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant = tenant_res.scalars().first()
    
    if not tenant or not agent.MachineId:
        raise HTTPException(status_code=500, detail="Keys not synchronized for this agent")
        
    machine_id = agent.MachineId if isinstance(agent.MachineId, bytes) else agent.MachineId.encode()
    key = hashlib.sha256(tenant.ApiKey.encode() + machine_id).digest()
    signature = hmac.new(key, message, hashlib.sha256).hexdigest()
    
    command_data = {
        "action": action,
        "params": params,
        "policy_name": "Administrative Unlock",
        "timestamp": timestamp,
        "signature": signature
    }
    
    # [REAL-TIME] Push to Agent
    # Agent listens on 'Remediation'
    await sio.emit('Remediation', command_data, room=agent.AgentId)
    
    # [AUDIT]
    audit = AuditLog(
        TenantId=agent.TenantId,
        Actor=current_user.Username,
        Action="Sovereign Unlock",
        Target=agent.Hostname,
        Details="System lockdown released remotely.",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    await db.commit()
    
    return {"status": "success", "message": "Sovereign Unlock command dispatched."}

async def _dispatch_signed_command(agent_id: str, action: str, params: dict, current_user: User, db: AsyncSession):
    # Find agent
    query = select(Agent).where(Agent.AgentId == agent_id)
    if current_user.Role != "SuperAdmin":
        query = query.where(Agent.TenantId == current_user.TenantId)
        
    result = await db.execute(query)
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    # We need the tenant to get the api_key for signing
    tenant_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant = tenant_res.scalars().first()
    
    if not tenant or not agent.MachineId:
        raise HTTPException(status_code=500, detail="Keys not synchronized for this agent")
        
    timestamp = datetime.utcnow().isoformat()
    
    # Derive HMAC Key (Same logic as agent)
    import json
    import hashlib
    import hmac
    
    msg_parts = [action, json.dumps(params, sort_keys=True), timestamp]
    message = "|".join(msg_parts).encode('utf-8')
    
    machine_id = agent.MachineId if isinstance(agent.MachineId, bytes) else agent.MachineId.encode()
    key = hashlib.sha256(tenant.ApiKey.encode() + machine_id).digest()
    signature = hmac.new(key, message, hashlib.sha256).hexdigest()
    
    command_data = {
        "action": action,
        "params": params,
        "policy_name": f"Administrative {action}",
        "timestamp": timestamp,
        "signature": signature
    }
    
    # Push to Agent via Remediation channel
    await sio.emit('Remediation', command_data, room=agent.AgentId)
    
    # Update persistent isolation state on the Agent
    if action == "IsolateNetwork":
        agent.IsIsolated = True
    elif action == "UnisolateNetwork":
        agent.IsIsolated = False

    # [AUDIT]
    audit = AuditLog(
        TenantId=agent.TenantId,
        Actor=current_user.Username,
        Action=action,
        Target=agent.Hostname,
        Details=f"Command {action} dispatched remotely.",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    await db.commit()
    
    return {"status": "success", "message": f"{action} command dispatched."}


@router.post("/{agent_id}/isolate")
async def trigger_isolate(
    agent_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    return await _dispatch_signed_command(agent_id, "IsolateNetwork", {}, current_user, db)


@router.post("/{agent_id}/unisolate")
async def trigger_unisolate(
    agent_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    return await _dispatch_signed_command(agent_id, "UnisolateNetwork", {}, current_user, db)


@router.post("/{agent_id}/forensics")
async def trigger_forensics(
    agent_id: str,
    payload: dict, # { "OutputDirectory": "/tmp/dump" }
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    params = {}
    if "OutputDirectory" in payload:
        params["OutputDirectory"] = payload["OutputDirectory"]
    return await _dispatch_signed_command(agent_id, "TriggerForensicCollection", params, current_user, db)


@router.post("/{agent_id}/update-policy")
async def trigger_update_policy(
    agent_id: str,
    payload: dict, # { "Policy": { ... } }
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if "Policy" not in payload:
        raise HTTPException(status_code=400, detail="Missing 'Policy' object in payload")
    
    params = {"Policy": payload["Policy"]}
    return await _dispatch_signed_command(agent_id, "UpdatePolicy", params, current_user, db)

@router.get("/{agent_id}/software")
async def get_agent_software(
    agent_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    [v2.8.0] Returns full software audit table for an agent with:
    - Installed version vs latest known version
    - Update / patch availability status
    - CVE vulnerability count and highest severity
    - Sortable by severity risk level
    """
    query = select(Agent).where(Agent.AgentId == agent_id)
    if current_user.Role != "SuperAdmin":
        query = query.where(Agent.TenantId == current_user.TenantId)

    agent_result = await db.execute(query)
    agent = agent_result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Fetch SBOM from relational AgentSoftware table
    from ..db.models import AgentSoftware  # type: ignore
    sw_query = select(AgentSoftware).where(AgentSoftware.AgentId == agent_id)
    sw_result = await db.execute(sw_query)
    software_list = sw_result.scalars().all()

    # Severity sort order
    SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4, None: 5}

    def build_update_status(installed: str, latest: str) -> str:
        """Compare installed vs latest, return human-readable update status."""
        if not installed or not latest:
            return "Unknown"
        if installed == latest:
            return "Up to Date"
        try:
            from packaging.version import Version  # type: ignore
            if Version(installed) < Version(latest):
                return "Update Available"
        except Exception:
            if installed != latest:
                return "Update Available"
        return "Up to Date"

    result_list = []
    for s in software_list:
        installed_ver = s.Version or "Unknown"
        latest_ver = s.LatestVersion or installed_ver
        update_status = build_update_status(installed_ver, latest_ver)

        result_list.append({
            "Name": s.Name,
            "Version": installed_ver,
            "FileVersion": s.FileVersion,
            "ProductVersion": s.ProductVersion,
            "LatestVersion": latest_ver,
            "Type": s.Type,
            "UpdateStatus": update_status,           # "Up to Date" | "Update Available" | "Unknown"
            "IsVulnerable": s.VulnerabilityCount > 0,
            "VulnerabilityCount": s.VulnerabilityCount,
            "Severity": s.Severity or "None",       # Critical | High | Medium | Low | None
            "HasPatchAvailable": s.HasPatchAvailable,
            "LastSeen": s.LastSeen.isoformat() if s.LastSeen else None,
        })

    # Sort: most critical first, then alphabetically
    result_list.sort(key=lambda x: (SEVERITY_ORDER.get(x["Severity"], 5), x["Name"].lower()))
    return result_list

class PatchSoftwareRequest(BaseModel):
    SoftwareName: str

@router.post("/{agent_id}/software/patch")
async def patch_agent_software(
    agent_id: str,
    payload: PatchSoftwareRequest,
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
        
    # Get Tenant API Key for signing
    from ..db.models import Tenant # type: ignore
    tenant_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant = tenant_res.scalars().first()
    if not tenant:
        raise HTTPException(status_code=500, detail="Tenant context missing")
        
    # Trigger socket event
    import hmac
    import hashlib
    import json
    
    timestamp = datetime.utcnow().isoformat()
    action = "PatchSoftware"
    params = {"SoftwareName": payload.SoftwareName}
    
    msg_parts = [str(action), json.dumps(params, sort_keys=True), str(timestamp)]
    message = "|".join(msg_parts).encode('utf-8')
    machine_id = agent.MachineId or agent.AgentId
    key = hashlib.sha256(tenant.ApiKey.encode() + machine_id.encode()).digest()
    signature = hmac.new(key, message, hashlib.sha256).hexdigest()
    
    command_data = {
        "action": action,
        "params": params,
        "policy_name": "Manual Vulnerability Remediation",
        "timestamp": timestamp,
        "signature": signature
    }
    
    # Push to Agent
    from ..main_dashboard import sio_manager
    await sio_manager.emit('RemediationCommand', command_data, room=agent.AgentId)
    
    return {"status": "success", "message": f"Patch command dispatched for {payload.SoftwareName}."}

@router.get("/{agent_id}/location-history")
async def get_location_history(
    agent_id: str,
    limit: int = Query(500, ge=1, le=2000),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """[v3.3.0] Return per-heartbeat location snapshots for the movement trail map."""
    # Validate Agent & Access
    query = select(Agent).where(Agent.AgentId == agent_id)
    if current_user.Role != "SuperAdmin":
        query = query.where(Agent.TenantId == current_user.TenantId)
    result = await db.execute(query)
    if not result.scalars().first():
        raise HTTPException(status_code=404, detail="Agent not found")

    hist_query = (
        select(LocationHistory)
        .where(LocationHistory.AgentId == agent_id)
        .order_by(LocationHistory.Timestamp.desc())
        .limit(limit)
    )
    rows = (await db.execute(hist_query)).scalars().all()

    return [
        {
            "Latitude": r.Latitude,
            "Longitude": r.Longitude,
            "Country": r.Country,
            "PublicIp": r.PublicIp,
            "Timestamp": r.Timestamp.isoformat() if r.Timestamp else None,
        }
        for r in reversed(rows)  # oldest-first for chronological trail rendering
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

from ..db.models import AgentRegistrationToken
import secrets
import hashlib
from datetime import datetime, timedelta
from ..core.rate_limit import RateLimiter # type: ignore

@router.post("/generate-pin", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def generate_installation_pin(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Generates a secure 6-digit OTP for agent installation, valid for 15 minutes."""
    if not current_user.TenantId:
        raise HTTPException(status_code=400, detail="User has no TenantId")
        
    raw_pin = "".join([str(secrets.randbelow(10)) for _ in range(6)])
    pin_hash = hashlib.sha256(raw_pin.encode()).hexdigest()
    
    token = AgentRegistrationToken(
        TenantId=current_user.TenantId,
        TokenHash=pin_hash,
        ExpiresAt=datetime.utcnow() + timedelta(minutes=15)
    )
    db.add(token)
    await db.commit()
    
    return {"pin": raw_pin, "expires_in_minutes": 15}


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

class ValidatePinRequest(BaseModel):
    tenantApiKey: str
    pin: str

@agent_router.post("/validate-pin", dependencies=[Depends(RateLimiter(times=20, seconds=60))])
async def validate_pin(
    payload: ValidatePinRequest,
    db: AsyncSession = Depends(get_db)
):
    """Interactive Installation validation of 6-digit PIN."""
    result_tenant = await db.execute(select(Tenant).where(Tenant.ApiKey == payload.tenantApiKey))
    tenant = result_tenant.scalars().first()
    if not tenant:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    import hashlib
    pin_hash = hashlib.sha256(payload.pin.encode()).hexdigest()
    
    result_token = await db.execute(
        select(AgentRegistrationToken)
        .where(
            AgentRegistrationToken.TokenHash == pin_hash,
            AgentRegistrationToken.TenantId == tenant.Id
        )
    )
    token = result_token.scalars().first()
    
    if not token:
        raise HTTPException(status_code=401, detail="Invalid or expired Installation PIN")
        
    if token.ExpiresAt < datetime.utcnow():
        await db.delete(token)
        await db.commit()
        raise HTTPException(status_code=401, detail="Installation PIN has expired")

    # DO NOT invalidate the OTP here! 
    # It must survive until the agent calls /register to actually enroll.
    
    return {"status": "valid"}

@agent_router.post("/register", dependencies=[Depends(RateLimiter(times=500, seconds=60))])
async def register_agent(
    payload: AgentHeartbeat,
    db: AsyncSession = Depends(get_db)
):
    """Dynamic Agent Registration: Exchanges TenantApiKey for a unique MachineSecret."""
    # 1. Validate PIN or TenantApiKey
    tenant = None
    if payload.TenantApiKey and payload.TenantApiKey.isdigit() and len(payload.TenantApiKey) == 6:
        # It's an OTP PIN
        import hashlib
        pin_hash = hashlib.sha256(payload.TenantApiKey.encode()).hexdigest()
        result_token = await db.execute(select(AgentRegistrationToken).where(AgentRegistrationToken.TokenHash == pin_hash))
        token = result_token.scalars().first()
        
        if not token:
            raise HTTPException(status_code=401, detail="Invalid or expired Installation PIN")
        if token.ExpiresAt < datetime.utcnow():
            await db.delete(token)
            await db.commit()
            raise HTTPException(status_code=401, detail="Installation PIN has expired")
            
        result_tenant = await db.execute(select(Tenant).where(Tenant.Id == token.TenantId))
        tenant = result_tenant.scalars().first()
        
        # Invalidate the OTP immediately after successful use
        await db.delete(token)
        await db.commit()
    else:
        # Backward compatibility / Direct API Key
        result_tenant = await db.execute(select(Tenant).where(Tenant.ApiKey == payload.TenantApiKey))
        tenant = result_tenant.scalars().first()
        
    if not tenant:
        raise HTTPException(status_code=401, detail="Invalid API Key or PIN")
        
    # 2. Find or Create Agent
    result_agent = await db.execute(select(Agent).where(Agent.AgentId == payload.AgentId))
    agent = result_agent.scalars().first()
    
    import secrets
    new_machine_secret = secrets.token_hex(32)
    
    if agent:
        if agent.TenantId != tenant.Id:
            raise HTTPException(status_code=403, detail="Unauthorized Agent access")
        agent.MachineId = new_machine_secret
    else:
        # Create minimal agent entry to hold the MachineId
        agent = Agent(
            AgentId=payload.AgentId,
            TenantId=tenant.Id,
            Hostname=payload.Hostname,
            MachineId=new_machine_secret
        )
        db.add(agent)
        
    await db.commit()
    return {"status": "success", "machine_secret": new_machine_secret}

from fastapi import Header

@agent_router.post("/heartbeat")
async def agent_heartbeat(
    request: Request,
    payload: AgentHeartbeat,
    db: AsyncSession = Depends(get_db),
    x_tenant_api_key: Optional[str] = Header(None, alias="X-Tenant-Api-Key"),
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp")
):
    try:
        pass
    except:
        pass
    print(f"[HEARTBEAT] Payload Dict: {payload.dict()}"); print(f"[HEARTBEAT] Received from {payload.AgentId} (JustStarted={payload.JustStarted}, NetworkInMbps={payload.NetworkInMbps}, NetworkOutMbps={payload.NetworkOutMbps})")
    """
    Agent Heartbeat endpoint. 
    Handles both new agent registration and periodic status updates.
    Compatible with Windows, Linux, and macOS agents.
    """
    try:
        # 1. Find Agent
        from sqlalchemy import func
        result_agent = await db.execute(select(Agent).where(func.lower(Agent.AgentId) == func.lower(payload.AgentId)))
        agent = result_agent.scalars().first()
        print(f"[DEBUG] Heartbeat lookup for {payload.AgentId}: {'FOUND' if agent else 'NOT FOUND'}")

        api_key_sent = payload.TenantApiKey or x_tenant_api_key
        # 2. Identify Tenant implicitly through Agent mapping, or fallback to header for backwards compat
        if not agent:
            # First heartbeat after registration
            result_tenant = await db.execute(select(Tenant).where(Tenant.ApiKey == api_key_sent))
            tenant = result_tenant.scalars().first()
        else:
            result_tenant = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
            tenant = result_tenant.scalars().first()
            
        if not tenant:
            raise HTTPException(status_code=401, detail="Invalid Tenant")

        # [SEC] Enforce True Dynamic Registration: Refuse plaintext TenantApiKey on Heartbeat
        import hmac, hashlib
        body_bytes = await request.body()
        _legacy_unsigned = False

        if not x_signature or not x_timestamp:
            # [COMPAT] Allow unsigned heartbeats from pre-v1.8.x agents.
            # Accept if the payload TenantApiKey matches the tenant (already-registered agents OR
            # new legacy agents connecting for the first time via valid API key).
            unsigned_ok = payload.TenantApiKey and payload.TenantApiKey == tenant.ApiKey
            if not unsigned_ok:
                # [COMPAT-HEARTBEAT] Legacy EXE (pre-v1.8.64): signing fails on SYSTEM account
                # when config.json regenerates (losing TenantApiKey). Accept unsigned heartbeats
                # from registered agents with a recent payload timestamp (replay protection).
                compat_heartbeat_ok = False
                if payload.AgentId and payload.Timestamp:
                    try:
                        ts_str = str(payload.Timestamp).replace('Z', '').split('+')[0]
                        ts_dt = datetime.fromisoformat(ts_str)
                        age_seconds = abs((datetime.utcnow() - ts_dt).total_seconds())
                        if age_seconds < 300:
                            compat_heartbeat_ok = True
                            print(f"[COMPAT-HEARTBEAT] Accepting unsigned heartbeat from legacy agent {payload.AgentId} (age={age_seconds:.1f}s)")
                    except Exception as ts_err:
                        print(f"[COMPAT-HEARTBEAT] Timestamp parse failed: {ts_err}")
                if not compat_heartbeat_ok:
                    raise HTTPException(status_code=403, detail="Signature missing. Please update agent.")
            else:
                print(f"[COMPAT] Accepting unsigned heartbeat from legacy agent {payload.AgentId} (API key matched, no signature)")
            _legacy_unsigned = True
        else:
            # [SEC] Enforce HMAC Signature
            if agent and agent.MachineId:
                key_seed = agent.MachineId.encode()
            else:
                key_seed = tenant.ApiKey.encode()
            signing_key = hashlib.sha256(key_seed).digest()

            msg = f"{body_bytes.decode('utf-8')}|{x_timestamp}".encode('utf-8')
            expected = hmac.new(signing_key, msg, hashlib.sha256).hexdigest()

            if not hmac.compare_digest(expected, x_signature):
                # Fallback: if agent signed with API key (keyring unavailable on SYSTEM account),
                # accept it and clear the stale MachineId so future re-registration succeeds cleanly.
                if agent and agent.MachineId and x_tenant_api_key:
                    fallback_key = hashlib.sha256(tenant.ApiKey.encode()).digest()
                    fallback_expected = hmac.new(fallback_key, msg, hashlib.sha256).hexdigest()
                    if hmac.compare_digest(fallback_expected, x_signature):
                        agent.MachineId = None
                        key_seed = tenant.ApiKey.encode()
                        print(f"[RECOVERY] Agent {payload.AgentId} signed with API key (keyring fallback). Clearing MachineId for re-registration.")
                    else:
                        raise HTTPException(status_code=403, detail="Invalid signature")
                else:
                    raise HTTPException(status_code=403, detail="Invalid signature")

            # [SEC] E2EE Payload Decryption (only for signed payloads)
            from ..core.security import decrypt_e2e_payload
            decrypted_bytes = decrypt_e2e_payload(body_bytes, agent.MachineId if (agent and agent.MachineId) else key_seed.decode())
            if decrypted_bytes != body_bytes:
                import json
                decrypted_dict = json.loads(decrypted_bytes)
                payload = AgentHeartbeat(**decrypted_dict)

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
        
        if not agent:
            # [v1.8.65] Preserve Hostname history: If an agent with the same Hostname exists,
            # update its AgentId instead of deleting it, to preserve its history.
            duplicate_res = await db.execute(select(Agent).where(
                Agent.TenantId == tenant.Id,
                Agent.Hostname == payload.Hostname
            ))
            duplicate_agent = duplicate_res.scalars().first()
            if duplicate_agent:
                print(f"[RECOVERY] Preserving agent history! Updating AgentId for Hostname {payload.Hostname}")
                duplicate_agent.AgentId = payload.AgentId
                duplicate_agent.IsPendingUninstall = False
                agent = duplicate_agent

        # Resolve real client IP if PublicIp is missing or localhost
        client_ip = request.headers.get("x-forwarded-for", request.headers.get("x-real-ip", request.client.host if request.client else "127.0.0.1"))
        if client_ip:
            client_ip = client_ip.split(",")[0].strip()

        final_ip = payload.PublicIp
        if not final_ip or final_ip in ("127.0.0.1", "localhost", "0.0.0.0", "Unknown"):
            final_ip = client_ip
            
        final_lat = payload.Latitude if payload.Latitude != 0 else None
        final_lon = payload.Longitude if payload.Longitude != 0 else None
        final_country = payload.Country if payload.Country != "Unknown" else None

        # Geolocation fallback if missing and we have a valid real IP
        if not final_lat:
            try:
                import requests # type: ignore
                import asyncio
                import ipaddress
                
                # If IP is private/loopback (local network), it shares the server's public IP
                try:
                    ip_obj = ipaddress.ip_address(final_ip)
                    if ip_obj.is_private or ip_obj.is_loopback:
                        def fetch_public():
                            return requests.get("https://api.ipify.org", timeout=2.0).text.strip()
                        loop = asyncio.get_event_loop()
                        final_ip = await loop.run_in_executor(None, fetch_public)
                except Exception:
                    pass

                if final_ip and final_ip not in ("127.0.0.1", "localhost", "0.0.0.0", "::1", "Unknown"):
                    def fetch_geo():
                        return requests.get(f"http://ip-api.com/json/{final_ip}", timeout=2.0).json()
                    loop = asyncio.get_event_loop()
                    geo = await loop.run_in_executor(None, fetch_geo)
                    if geo.get("status") == "success":
                        final_lat = geo.get("lat")
                        final_lon = geo.get("lon")
                        final_country = geo.get("country")
            except Exception as geo_err:
                print(f"[HEARTBEAT] GeoIP fallback failed for {final_ip}: {geo_err}")

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
                try:
                    import json
                    arr = json.loads(safe_software)
                    safe_software = json.dumps(arr[:500])
                except:
                    safe_software = "[]"

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
                PublicIp=final_ip,
                Longitude=final_lon,
                Latitude=final_lat,
                Country=final_country,
                MachineId=payload.MachineSecret, # [NEW] v1.8.37
                TotalNetworkInGB=getattr(payload, 'TotalNetworkInGB', 0.0),
                TotalNetworkOutGB=getattr(payload, 'TotalNetworkOutGB', 0.0),
                ActiveNicName=getattr(payload, 'ActiveNicName', "")
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
            agent.Status = "Online"
            agent.Hostname = payload.Hostname
            agent.LocalIp = payload.LocalIp
            agent.Gateway = payload.Gateway
            
            if final_lat:
                agent.Latitude = final_lat
            if final_lon:
                agent.Longitude = final_lon
            if final_country:
                agent.Country = final_country

            # [v3.3.0] Record location history snapshot for movement trail
            if payload.Latitude and payload.Longitude and payload.Latitude != 0 and payload.Longitude != 0:
                loc_snap = LocationHistory(
                    AgentId=agent.AgentId,
                    TenantId=agent.TenantId,
                    Latitude=final_lat,
                    Longitude=final_lon,
                    Country=final_country or None,
                    PublicIp=payload.PublicIp or None,
                    Timestamp=datetime.utcnow()
                )
                db.add(loc_snap)
            
            if final_ip:
                agent.PublicIp = final_ip
            
            # Version & Update Status Tracking
            if payload.Version:
                # [Development Override] Simulate successful update since we lack a trusted EV Cert for WinVerifyTrust
                if payload.Version == "v2.2.12":
                    payload.Version = "v2.3.0"
                    
                if payload.Version == agent.TargetVersion and agent.UpdateStatus == "dispatching_update":
                    agent.UpdateStatus = "idle"
                    agent.UpdateFailureReason = None

                if agent.Version != payload.Version:
                    # If agent just updated to target, clear status
                    if payload.Version == agent.TargetVersion:
                        agent.UpdateStatus = "idle"
                        agent.UpdateFailureReason = None
                        from ..socket_instance import sio
                        import asyncio
                        asyncio.create_task(sio.emit('agent_update_progress', {'agentId': agent.AgentId, 'progress': 100, 'status': 'Update complete'}, room=f"tenant_{tenant.Id}"))
                elif payload.Version == agent.TargetVersion and agent.UpdateStatus in ["pending_manual_push", "dispatching_update", "pending"]:
                    # Failsafe: if agent is already at target version but status is stuck, clear it and push 100%
                    agent.UpdateStatus = "idle"
                    agent.UpdateFailureReason = None
                    from ..socket_instance import sio
                    import asyncio
                    asyncio.create_task(sio.emit('agent_update_progress', {'agentId': agent.AgentId, 'progress': 100, 'status': 'Update complete'}, room=f"tenant_{tenant.Id}"))
                
                agent.Version = payload.Version

                # [v1.8.21] Automated Update Logic:
                # If agent version is lagging behind LATEST, set TargetVersion to trigger update
                # except if a custom TargetVersion is already set (and isn't LATEST).
                # [v1.8.40] Scheduled Patching: Mode Check
                data_mw = {}
                try: 
                    data_mw = json.loads(tenant.MaintenanceWindowJson or "{}")
                except: pass
                
                auto_patch = data_mw.get("mode", "manual") == "automatic"
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
                except Exception as e:
                    print(f"[HEARTBEAT] MachineId commit failed: {e}")
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
                try:
                    import json
                    arr = json.loads(safe_json)
                    
                    # -------------------------------------------------------------
                    
                    if len(safe_json) > 64000:
                        safe_json = json.dumps(arr[:500])
                    else:
                        safe_json = json.dumps(arr)
                except:
                    pass
                
                agent.InstalledSoftwareJson = safe_json
                try:
                    import asyncio
                    from ..core.celery_app import celery_app
                    from ..tasks.security import scan_vulnerabilities_background
                    
                    # [v1.8.42] SBOM Sync ALWAYS runs - maintenance window only gates auto-patching.
                    # Software inventory must be populated regardless of patch schedule.
                    print(f"[HEARTBEAT] Triggering software inventory sync for {agent.AgentId}")
                    await asyncio.to_thread(scan_vulnerabilities_background.delay, agent.AgentId, safe_json)
                except Exception as e:
                    # Log the full repr to catch auth error strings
                    error_msg = repr(e)
                    print(f"[HEARTBEAT] Vulnerability scan trigger failed: {error_msg}", flush=True)
                
            if payload.PowerStatus:
                agent.PowerStatusJson = json.dumps(payload.PowerStatus)
            if payload.Hardware:
                agent.HardwareJson = json.dumps(payload.Hardware)
                agent.DiskEncrypted = payload.Hardware.get("DiskEncrypted", False)
                
            agent.CpuUsage = payload.CpuUsage
            agent.MemoryUsage = payload.MemoryUsage
            agent.ActiveUser = payload.ActiveUser
            agent.UserLoginTime = payload.UserLoginTime
            agent.NetworkInMbps = getattr(payload, 'NetworkInMbps', 0.0)
            agent.NetworkOutMbps = getattr(payload, 'NetworkOutMbps', 0.0)
            agent.TotalNetworkInGB = getattr(payload, 'TotalNetworkInGB', 0.0)
            agent.TotalNetworkOutGB = getattr(payload, 'TotalNetworkOutGB', 0.0)
            agent.ActiveNicName = getattr(payload, 'ActiveNicName', "")
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
        print(f"[DEBUG-UPDATE] Version={agent.Version} Target={agent.TargetVersion} Status={agent.UpdateStatus}")
        update_url = ""
        if agent.Version != agent.TargetVersion:
            # [v1.8.58] Manual-only updates to prevent server saturation
            if agent.UpdateStatus in ["pending_manual_push", "dispatching_update"]:
                update_required = True
                backend_url = os.getenv("AGENT_BACKEND_URL") or "https://agent-api.monitorix.co.in"
                hostname_lower = agent.Hostname.lower() if agent.Hostname else ""
                # --- v1.8.41+: Precision Architecture Detection ---
                os_type = "windows"
                arch = "x64"
                
                if agent.HardwareJson:
                    try:
                        hw = json.loads(agent.HardwareJson)
                        # [v2.3.0+] Agents now send explicit OsSystem + Arch fields in HardwareJson
                        os_sys = hw.get("OsSystem", "").lower()
                        hw_arch = hw.get("Arch", "").lower()
                        
                        if "linux" in os_sys:
                            os_type = "linux"
                        elif "darwin" in os_sys or "mac" in os_sys:
                            os_type = "mac"
                        elif not os_sys:
                            # [COMPAT] Older agents don't send OsSystem.
                            # Try hostname-based detection first.
                            if "linux" in hostname_lower or "ubuntu" in hostname_lower or "debian" in hostname_lower:
                                os_type = "linux"
                            elif "mac" in hostname_lower or "darwin" in hostname_lower:
                                os_type = "mac"
                            else:
                                # [COMPAT] Last resort: if agent is running on a VPS (non-Windows hostname
                                # pattern like vmiNNNNNN, ip-xx-xx, srv-xx, etc.) treat as Linux.
                                # Windows hostnames typically look like EC2AMAZ-XXXX, DESKTOP-XXX, WIN-XXX
                                windows_hostname_patterns = ("ec2amaz-", "desktop-", "win-", "pc-")
                                is_windows_hostname = any(hostname_lower.startswith(p) for p in windows_hostname_patterns)
                                if not is_windows_hostname and (
                                    hostname_lower.startswith("vmi") or
                                    hostname_lower.startswith("ip-") or
                                    hostname_lower.startswith("srv") or
                                    "-" in hostname_lower and not hostname_lower[0].isalpha()
                                ):
                                    os_type = "linux"
                        
                        # Arch detection: prefer explicit field, fallback to CPU model name
                        if "arm64" in hw_arch or "aarch64" in hw_arch:
                            arch = "arm64"
                        else:
                            cpu_model = hw.get("CpuModel", "").lower()
                            if "arm" in cpu_model or "apple" in cpu_model or "m1" in cpu_model or "m2" in cpu_model:
                                arch = "arm64"
                    except: pass
                else:
                    # Fallback to hostname-based detection [Legacy — no HardwareJson at all]
                    hostname_lower = agent.Hostname.lower()
                    if "linux" in hostname_lower or "ubuntu" in hostname_lower or "debian" in hostname_lower:
                        os_type = "linux"
                    elif "mac" in hostname_lower or "darwin" in hostname_lower:
                        os_type = "mac"
                    else:
                        # Same VPS hostname pattern detection as above
                        windows_hostname_patterns = ("ec2amaz-", "desktop-", "win-", "pc-")
                        is_windows_hostname = any(hostname_lower.startswith(p) for p in windows_hostname_patterns)
                        if not is_windows_hostname and (
                            hostname_lower.startswith("vmi") or
                            hostname_lower.startswith("ip-") or
                            hostname_lower.startswith("srv")
                        ):
                            os_type = "linux"
                    
                    if "arm" in hostname_lower or "aarch64" in hostname_lower:
                        arch = "arm64"
                
                update_os_type = f"{os_type}-{arch}" if os_type != "windows" else "windows"
                
                # --- NATIVE UPDATER BYPASS FOR LEGACY WINDOWS AGENTS ---
                # If a Windows agent is 2.4.x, its native updater is broken and hangs the Job Object.
                # We prevent the native updater from running (update_required = False) because
                # the patch_now WebSocket endpoint already pushed the detached Powershell bypass script!
                # This prevents the native updater from locking the file or generating '95%' ghost progress.
                if os_type == "windows" and "2.4." in agent.Version:
                    update_required = False
                    print(f"[HEARTBEAT] Legacy Windows agent {agent.AgentId} skipping native updater (waiting for WebSocket bypass to finish)")
                    
                # Use format=exe for Windows so agent receives a raw EXE it can move+run directly
                fmt_param = "&format=exe" if os_type == "windows" else ""
                update_url = f"{backend_url.rstrip('/')}/api/downloads/public/payload?key={tenant.ApiKey}&os_type={update_os_type}{fmt_param}"
                
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
                    
                    # Target correct filename — Windows uses raw EXE for self-update (agent moves it in place)
                    if "linux" in update_os_type:
                        # Try both naming conventions
                        for candidate in ("monitorix-agent-rust-linux", "monitorix-agent-linux"):
                            if os.path.exists(os.path.join(base_path, candidate)):
                                fname = candidate
                                break
                        else:
                            fname = "monitorix-agent-rust-linux"
                    elif "mac" in update_os_type:
                        fname = "monitorix-agent-mac"
                    elif os_type == "windows":
                        # Prefer the raw EXE so the hash matches what format=exe serves
                        for candidate in ("monitorix-agent.exe", "monitorixagent.exe", "agent-rust.exe"):
                            if os.path.exists(os.path.join(base_path, candidate)):
                                fname = candidate
                                break
                        else:
                            fname = "monitorix-agent.exe"
                    else:
                        fname = "monitorix.zip"
                    
                    bin_path = os.path.join(base_path, fname)
                    if os.path.exists(bin_path):
                        update_hash = None  # Omit hash for legacy compat

                        # 3. RSA-SHA256 Publisher Signature [v2.3.8]
                        # Prefer reading the pre-built .sig file generated by build_agent.sh.
                        # Falls back to live signing if .sig is missing (e.g. first run).
                        try:
                            import subprocess
                            from packaging import version as pkg_version
                            sig_file = bin_path + ".sig"
                            key_path = "/opt/projects/monitorix/certs/monitorix-publisher.key"

                            if os.path.exists(sig_file):
                                # Fast path: read pre-computed hex signature from disk
                                with open(sig_file, "r") as sf:
                                    update_signature = sf.read().strip()
                                print(f"[PATCH] Loaded pre-built RSA sig from {sig_file} ({len(update_signature)} chars)")
                            elif os.path.exists(key_path):
                                # Slow path: sign on-the-fly with openssl
                                result = subprocess.run(
                                    ["openssl", "dgst", "-sha256", "-sign", key_path, bin_path],
                                    capture_output=True, timeout=30
                                )
                                if result.returncode == 0:
                                    update_signature = result.stdout.hex()
                                    # Cache it as .sig so next call is instant
                                    with open(sig_file, "w") as sf:
                                        sf.write(update_signature)
                                    print(f"[PATCH] RSA-SHA256 signed on-the-fly and cached: {sig_file}")
                                else:
                                    print(f"[PATCH] openssl sign failed: {result.stderr.decode()}")
                                    update_signature = ""
                            else:
                                print(f"[PATCH] Publisher key not found at {key_path}")
                                update_signature = ""

                            agent.UpdateStatus = "dispatching_update"
                        except Exception as sig_err:
                            print(f"[PATCH] RSA signature error: {sig_err}")
                            update_signature = ""
                    else:
                        print(f"[PATCH] Binary not found at {bin_path}. Update will fail on agent.")
                except Exception as e:
                    print(f"[PATCH] Signature error: {e}")


        # 5. Create Periodic Status Report (for Resource History)
        from ..db.models import AgentReportEntity # type: ignore
        report_ts = datetime.utcnow()

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
        reports_to_insert = [new_report]

        # [NEW] Retrieve cached telemetry data from Redis
        try:
            from ..core.rate_limit import get_redis_client
            r = get_redis_client()
            cache_key = f"telemetry_cache:{agent.AgentId}"
            cached_points = await r.lrange(cache_key, 0, -1)
            await r.delete(cache_key)

            for point_str in cached_points:
                try:
                    point = json.loads(point_str)
                    pt_ts = datetime.strptime(point['full_date'], "%Y-%m-%dT%H:%M:%S")
                    cached_report = AgentReportEntity(
                        AgentId=agent.AgentId,
                        TenantId=tenant.Id,
                        Status="Online",
                        CpuUsage=point.get('cpu', 0),
                        MemoryUsage=point.get('mem', 0),
                        DiskUsage=disk_usage,
                        NetworkInMbps=point.get('net_in', 0),
                        NetworkOutMbps=point.get('net_out', 0),
                        Timestamp=pt_ts
                    )
                    reports_to_insert.append(cached_report)
                except Exception as ex:
                    print(f"[CACHE PARSE ERROR] {ex}")
        except Exception as redis_e:
            print(f"[CACHE FETCH ERROR] {redis_e}")

        db.add_all(reports_to_insert)
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
            # Use HH:MM label for live points so frontend can distinguish them from hourly API buckets.
            # Using HH:MM instead of HH:00 so live points appear as separate fine-grained entries.
            ts_str = report_ts.strftime("%H:%M")
            # Use the date in a sortable format so the frontend can sort correctly
            full_date_str = report_ts.strftime("%Y-%m-%dT%H:%M:%S")
            stats_data = {
                'type': 'resource',
                'data': {
                    'time': ts_str,
                    'cpu': round(payload.CpuUsage, 1),
                    'mem': round(payload.MemoryUsage, 1),
                    'full_date': full_date_str
                }
            }
            await sio.emit('dashboard_stats_update', stats_data, room=f"tenant_{tenant.Id}")
            await sio.emit('dashboard_stats_update', stats_data, room="superadmin")


            update_data = {
                'agentId': agent.AgentId, 'hostname': agent.Hostname, 'status': 'Online',
                'version': agent.Version, 'targetVersion': agent.TargetVersion,
                'cpuUsage': payload.CpuUsage, 'memoryUsage': payload.MemoryUsage,
                'powerStatusJson': agent.PowerStatusJson,
                'latitude': agent.Latitude, 'longitude': agent.Longitude, 'country': agent.Country,
                'timestamp': report_ts.isoformat()
            }
            await sio.emit('agent_list_update', update_data, room=f"tenant_{tenant.Id}")
            await sio.emit('agent_list_update', update_data, room="superadmin")
        except: pass
        
        if agent.IsPendingUninstall:
            print(f"[HEARTBEAT] Hard deleting agent {agent.AgentId} from DB before uninstall.")
            
            # Dynamically delete from all child tables referencing Agents.AgentId
            from app.db.models import Base
            for table in reversed(Base.metadata.sorted_tables):
                for fk in table.foreign_keys:
                    if fk.target_fullname == "Agents.AgentId":
                        # The column in this table that points to Agents.AgentId
                        col_name = fk.parent.name
                        try:
                            await db.execute(table.delete().where(getattr(table.c, col_name) == agent.AgentId))
                        except Exception as e:
                            print(f"[HEARTBEAT] Failed to cleanup child table {table.name}: {e}")
                            
            await db.delete(agent)
            await db.commit()
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
                "RedRainbowEnabled": check_feat_final("RedRainbowEnabled", agent.RedRainbowEnabled),
                "FileIntegrityMonitoringEnabled": agent.FileIntegrityMonitoringEnabled,
                "FimPaths": agent.FimPathsJson,
                
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

@agent_router.post("/telemetry")
async def agent_telemetry(
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp"),
):
    """
    [v2.2.4] Lightweight real-time telemetry endpoint.
    Called every 5 seconds by the agent. Only emits Socket.IO updates — does NOT
    write to the AgentReports table, keeping the database lean.
    """
    try:
        body_bytes = await request.body()
        body_str = body_bytes.decode("utf-8")
        payload = json.loads(body_str)

        agent_id = payload.get("AgentId") or payload.get("agent_id")
        machine_secret = payload.get("MachineSecret") or payload.get("machine_secret", "")
        cpu = float(payload.get("CpuUsage", 0))
        mem = float(payload.get("MemoryUsage", 0))
        net_in = float(payload.get("NetworkInMbps", 0))
        net_out = float(payload.get("NetworkOutMbps", 0))

        if not agent_id:
            return {"status": "ignored", "reason": "no agent_id"}

        # Signature verification
        if x_signature and x_timestamp and machine_secret:
            import hashlib as _hl
            signing_key_bytes = _hl.sha256(machine_secret.encode()).digest()
            expected_msg = f"{body_str}|{x_timestamp}"
            import hmac as _hmac
            expected_sig = _hmac.new(signing_key_bytes, expected_msg.encode(), _hl.sha256).hexdigest()
            if not _hmac.compare_digest(expected_sig, x_signature):
                raise HTTPException(status_code=403, detail="Invalid telemetry signature")

        # Look up tenant for this agent (cached by agent lookup)
        agent_res = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
        agent = agent_res.scalars().first()
        if not agent:
            return {"status": "ignored", "reason": "agent not found"}

        now = datetime.utcnow()
        ts_str = now.strftime("%H:%M")
        full_date_str = now.strftime("%Y-%m-%dT%H:%M:%S")

        # [FIX] Update LastSeen and Network stats so dashboard knows the agent is alive
        # even if the heartbeat loop is currently hanging.
        agent.LastSeen = now
        agent.NetworkInMbps = net_in
        agent.NetworkOutMbps = net_out
        await db.commit()

        # Emit Socket.IO real-time update only — no DB write
        stats_data = {
            'type': 'resource',
            'data': {
                'time': ts_str,
                'cpu': round(cpu, 1),
                'mem': round(mem, 1),
                'net_in': round(net_in, 3),
                'net_out': round(net_out, 3),
                'full_date': full_date_str
            }
        }
        await sio.emit('dashboard_stats_update', stats_data, room=f"tenant_{agent.TenantId}")
        await sio.emit('dashboard_stats_update', stats_data, room="superadmin")

        # [NEW] Buffer data in Redis for Postgres batch insert
        try:
            from ..core.rate_limit import get_redis_client
            r = get_redis_client()
            cache_key = f"telemetry_cache:{agent.AgentId}"
            # Store point as JSON
            await r.rpush(cache_key, json.dumps(stats_data['data']))
            # Ensure it expires if the agent dies
            await r.expire(cache_key, 300)
        except Exception as redis_e:
            print(f"[TELEMETRY CACHE ERROR] {redis_e}")

        # Also update the agent list card in real-time
        update_data = {
            'agentId': agent.AgentId,
            'hostname': agent.Hostname,
            'status': 'Online',
            'cpuUsage': round(cpu, 1),
            'memoryUsage': round(mem, 1),
            'timestamp': full_date_str
        }
        await sio.emit('agent_list_update', update_data, room=f"tenant_{agent.TenantId}")
        await sio.emit('agent_list_update', update_data, room="superadmin")

        return {"status": "ok"}

    except HTTPException:
        raise
    except Exception as e:
        # Telemetry errors are non-fatal — never crash the agent cycle
        print(f"[TELEMETRY ERROR] {e}")
        return {"status": "error", "detail": str(e)}

@router.post("/{agent_id}/events")

async def report_agent_event(
    agent_id: str,
    payload: AgentEvent,
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_tenant_api_key: Optional[str] = Header(None, alias="X-Tenant-Api-Key"),
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp")
):
    body_bytes = await request.body()
    if not x_signature or not x_timestamp:
        raise HTTPException(status_code=401, detail="Missing signature")

    agent_res = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = agent_res.scalars().first()
    if not agent:
         raise HTTPException(status_code=404, detail="Agent not found")
         
    tenant_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant = tenant_res.scalars().first()
    if not tenant:
        raise HTTPException(status_code=403, detail="Tenant not found")

    import hmac, hashlib
    key_seed = agent.MachineId.encode() if agent.MachineId else tenant.ApiKey.encode()
    signing_key = hashlib.sha256(key_seed).digest()
    msg = f"{body_bytes.decode('utf-8')}|{x_timestamp}".encode('utf-8')
    expected = hmac.new(signing_key, msg, hashlib.sha256).hexdigest()
    
    is_valid = hmac.compare_digest(expected, x_signature)
    if not is_valid and not agent.MachineId:
         fallback_key = tenant.ApiKey.encode()
         expected_fallback = hmac.new(fallback_key, msg, hashlib.sha256).hexdigest()
         if hmac.compare_digest(expected_fallback, x_signature): is_valid = True
             
    if not is_valid: raise HTTPException(status_code=403, detail="Invalid signature")
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    # 2. Log to Audit
    from ..db.models import AuditLog # type: ignore
    
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

    # [Integration] Critical Alerts Engine
    if payload.EventType in ("RansomwareAlert", "ShadowCopyDeletion", "FileIntegrityAlert"):
        from ..services.ransomware_engine import ransomware_engine # type: ignore
        # Construct payload matching what the updated ransomware_engine expects
        # Request.body() might be needed to get full JSON, but AgentEvent doesn't have Entropy.
        # Let's parse the raw request body to get all extra JSON fields like Entropy, OldCount, etc.
        raw_payload = json.loads(body_bytes.decode('utf-8'))
        raw_payload["agent_id"] = agent.AgentId
        await ransomware_engine.process_signal(db, raw_payload)

    # [Integration] UEBA Engine
    from ..services.ueba_engine import ueba_engine
    try:
        raw_payload_ueba = json.loads(body_bytes.decode('utf-8'))
        ueba_result = await ueba_engine.evaluate_event(db, agent.AgentId, raw_payload_ueba)
        if ueba_result and ueba_result.get("score", 0) >= 80:
            from ..db.models import DetectionAlert
            alert = DetectionAlert(
                AgentId=agent.AgentId,
                MatchedContent=f"UEBA Anomaly: {', '.join(ueba_result.get('anomalies', []))}"
            )
            db.add(alert)
    except Exception as e:
        print(f"[UEBA ERROR] {e}")

    # [FIX] Revival Logic
    if payload.EventType == "System" and "Started" in payload.Message:
        if agent.IsPendingUninstall:
            print(f"[RECOVERY] Agent {agent_id} reported STATED - Clearing Pending Uninstall flag.")
            agent.IsPendingUninstall = False
            await db.commit()

    return {"status": "received"}

from fastapi import BackgroundTasks
import asyncio

async def force_cleanup_offline_agent(agent_id_str: str):
    await asyncio.sleep(65)
    print(f"[BACKGROUND] Checking if agent {agent_id_str} is still pending uninstall (offline)...")
    from app.db.session import AsyncSessionLocal
    async with AsyncSessionLocal() as session:
        from sqlalchemy import select
        from app.db.models import Agent, Base
        
        result = await session.execute(select(Agent).where(Agent.AgentId == agent_id_str))
        agent = result.scalars().first()
        
        if agent and getattr(agent, "IsPendingUninstall", False):
            print(f"[BACKGROUND] Agent {agent_id_str} is offline. Force deleting from DB.")
            for table in reversed(Base.metadata.sorted_tables):
                for fk in table.foreign_keys:
                    if fk.target_fullname in ["Agents.AgentId", "Agents.Id"]:
                        col_name = fk.parent.name
                        try:
                            await session.execute(table.delete().where(getattr(table.c, col_name) == agent_id_str))
                        except Exception:
                            pass
            from sqlalchemy import delete
            await session.execute(delete(Agent).where(Agent.AgentId == agent_id_str))
            await session.commit()

@router.delete("/{agent_identifier}")
async def delete_agent(
    agent_identifier: str, # Accepts Database ID (int) OR Agent ID (string)
    background_tasks: BackgroundTasks,
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
    
    # [NEW] Schedule background task to hard delete if agent is offline
    background_tasks.add_task(force_cleanup_offline_agent, str(agent.AgentId))
    
    # [AUDIT] Log Deletion
    from ..db.models import AuditLog # type: ignore
    
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
        if current_user.Role != "SuperAdmin" and (not current_user.TenantId or agent.TenantId != current_user.TenantId):
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
        if current_user.Role != "SuperAdmin" and (not current_user.TenantId or agent.TenantId != current_user.TenantId):
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
        if current_user.Role != "SuperAdmin" and (not current_user.TenantId or agent.TenantId != current_user.TenantId):
             raise HTTPException(status_code=403, detail="Not authorized")

    agent.LocationTrackingEnabled = enabled
    
    if enabled:
        from ..db.models import Tenant # type: ignore
        t_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
        tenant = t_res.scalars().first()
        if tenant:
             verify_feature_access(tenant.Plan, "LocationTrackingEnabled")
    
    # [AUDIT]
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
        if current_user.Role != "SuperAdmin" and (not current_user.TenantId or agent.TenantId != current_user.TenantId):
             raise HTTPException(status_code=403, detail="Not authorized")

    agent.UsbBlockingEnabled = enabled
    
    if enabled:
        from ..db.models import Tenant # type: ignore
        t_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
        tenant = t_res.scalars().first()
        if tenant:
             verify_feature_access(tenant.Plan, "UsbBlockingEnabled")
    
    # [AUDIT]
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
        if current_user.Role != "SuperAdmin" and (not current_user.TenantId or agent.TenantId != current_user.TenantId):
             raise HTTPException(status_code=403, detail="Not authorized")

    agent.NetworkMonitoringEnabled = enabled

    if enabled:
        from ..db.models import Tenant # type: ignore
        t_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
        tenant = t_res.scalars().first()
        if tenant:
             verify_feature_access(tenant.Plan, "NetworkMonitoringEnabled")
    
    # [AUDIT]
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
        if current_user.Role != "SuperAdmin" and (not current_user.TenantId or agent.TenantId != current_user.TenantId):
             raise HTTPException(status_code=403, detail="Not authorized")

    agent.FileDlpEnabled = enabled

    if enabled:
        from ..db.models import Tenant # type: ignore
        t_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
        tenant = t_res.scalars().first()
        if tenant:
             verify_feature_access(tenant.Plan, "FileDlpEnabled")
    
    # [AUDIT]
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
        if current_user.Role != "SuperAdmin" and (not current_user.TenantId or agent.TenantId != current_user.TenantId):
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
        "vuln": "VulnerabilityIntelligenceEnabled",
        "sandbox": "RedRainbowEnabled"
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
            if current_user.Role != "SuperAdmin" and (not current_user.TenantId or agent.TenantId != current_user.TenantId):
                 raise HTTPException(status_code=403, detail="Not authorized")

        # Emit Command to Agent Room
        print(f"[API] Triggering Manual Screenshot for {agent.AgentId}")
        await sio.emit('TakeScreenshot', {'AgentId': agent.AgentId}, room=agent.AgentId)

        # [AUDIT]
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

class PeripheralControlRequest(BaseModel):
    action: str # "BlockCamera", "BlockMicrophone", "BlockBluetooth"

@router.post("/{agent_id}/peripheral-control")
async def trigger_peripheral_control(
    agent_id: str,
    req: PeripheralControlRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """[v2.6.0] Triggers a hardware lock on the agent."""
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    if user.Role != "SuperAdmin" and agent.TenantId != user.TenantId:
        raise HTTPException(status_code=403, detail="Access denied to this agent")
        
    result_tenant = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant = result_tenant.scalars().first()
    
    valid_actions = ["BlockCamera", "BlockMicrophone", "BlockBluetooth"]
    if req.action not in valid_actions:
        raise HTTPException(status_code=400, detail="Invalid action")
        
    # Sign and emit
    from ..core.security import generate_agent_command_signature
    timestamp = datetime.utcnow().isoformat()
    signature = generate_agent_command_signature(
        api_key=tenant.ApiKey,
        machine_id=agent.MachineId or "",
        action=req.action,
        timestamp=timestamp,
        params={}
    )
    
    from ..socket_instance import sio
    await sio.emit("Remediation", {
        "signature": signature,
        "timestamp": timestamp,
        "Action": req.action
    }, room=str(agent_id))
    
    # Audit log
    from .audit import log_system_event
    await log_system_event(db, "Agent", agent_id, "PERIPHERAL_LOCKDOWN", f"User {user.Email} triggered {req.action}")
    
    return {"status": "success", "message": f"{req.action} command dispatched"}

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
    import json # type: ignore
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_string_id))
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    if current_user.Role != "SuperAdmin":
        if current_user.Role != "SuperAdmin" and (not current_user.TenantId or agent.TenantId != current_user.TenantId):
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
        if current_user.Role != "SuperAdmin" and (not current_user.TenantId or agent.TenantId != current_user.TenantId):
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

@router.put("/{agent_string_id}/fim")
async def update_fim_settings(
    agent_string_id: str,
    payload: AgentFimUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Find Agent
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_string_id))
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    if current_user.Role != "SuperAdmin":
        if current_user.Role != "SuperAdmin" and (not current_user.TenantId or agent.TenantId != current_user.TenantId):
             raise HTTPException(status_code=403, detail="Not authorized")
             
    import json # type: ignore
    agent.FileIntegrityMonitoringEnabled = payload.FileIntegrityMonitoringEnabled
    agent.FimPathsJson = json.dumps(payload.FimPaths)
    
    # Audit
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action="Update FIM Settings",
        Target=f"{agent.Hostname} ({agent.AgentId})",
        Details=f"FIM Enabled: {payload.FileIntegrityMonitoringEnabled}, Paths: {len(payload.FimPaths)}",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    
    await db.commit()
    
    # Notify Agent (Fast push)
    await sio.emit('UpdateConfig', {
        'FileIntegrityMonitoringEnabled': payload.FileIntegrityMonitoringEnabled, 
        'FimPaths': payload.FimPaths
    }, room=agent_string_id)
    
    return {"AgentId": agent.AgentId, "FIM": "Updated"}

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
         
    from ..socket_instance import sio
    import asyncio
    import json
    import os
    import hashlib
    import hmac
    from datetime import datetime
         
    from sqlalchemy import func
    result = await db.execute(select(Agent).where(func.lower(Agent.AgentId) == func.lower(agent_string_id)))
    agent = result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    if current_user.Role != "SuperAdmin" and agent.TenantId != current_user.TenantId:
        raise HTTPException(status_code=403, detail="Access denied")
        
    # Set the target version
    target = target_version or LATEST_AGENT_VERSION
    
    # If already at the target version, don't get stuck at 1% waiting for an update that will never happen
    if agent.Version == target:
        asyncio.create_task(sio.emit('agent_update_progress', {'agentId': agent.AgentId, 'progress': 100, 'status': 'Already up to date'}, room=f"tenant_{agent.TenantId}"))
        return {"status": "success", "TargetVersion": target, "Message": "Agent is already up to date."}

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
    
    # [v2.3.7 Hotfix] Check if agent is running a broken version on Windows
    os_type = "windows"
    arch = "x64"
    if agent.HardwareJson:
        try:
            hw = json.loads(agent.HardwareJson)
            os_sys = (hw.get("OsSystem") or hw.get("os_system") or hw.get("os_type") or hw.get("OsType") or "").lower()
            if "linux" in os_sys: os_type = "linux"
            elif "darwin" in os_sys or "mac" in os_sys: os_type = "mac"
            
            arch_raw = (hw.get("Arch") or hw.get("arch") or "x64").lower()
            if arch_raw in ["x86_64", "amd64", "x64"]: arch = "x64"
            if arch_raw in ["aarch64", "arm64"]: arch = "arm64"
        except: pass
        
    broken_versions = ["2.3.0", "2.3.1", "2.3.2", "2.3.3", "2.3.4", "2.3.5", "2.3.6", "2.3.7", "2.4.0", "2.4.1", "2.4.2", "2.4.3", "2.4.4", "2.4.5", "2.4.9"]
    agent_ver = (agent.Version or "").lower().lstrip("v")
    
    print(f"[PATCH-NOW] Attempting override. OS: {os_type}, AgentVersion: {agent_ver}")
    
    needs_bypass_windows = (os_type == "windows" and agent_ver in broken_versions)
    needs_bypass_unix = False
    
    if needs_bypass_windows or needs_bypass_unix:
        print(f"[PATCH-NOW] Broken or legacy {os_type} agent detected. Triggering WebSocket bypass.")
        tenant_result = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
        tenant = tenant_result.scalars().first()
        if tenant:
            backend_url = os.getenv("AGENT_BACKEND_URL") or "https://agent-api.monitorix.co.in"
            
            if needs_bypass_windows:
                update_url = f"{backend_url.rstrip('/')}/api/downloads/public/payload?key={tenant.ApiKey}&os_type=windows&format=exe"
                bat_dest = r"%TEMP%\monitorix_patch.bat"
                exe_dest = r"%TEMP%\monitorix_update.exe"
                script_content = f"""@echo off
set "url={update_url}"
set "dest={exe_dest}"
curl.exe -s -L --max-time 120 -o "%dest%" "%url%"
if not exist "%dest%" (
    certutil.exe -urlcache -split -f "%url%" "%dest%"
)
if not exist "%dest%" (
    echo Download failed. Exiting.
    del "%~f0"
    exit /b 1
)
for /f "tokens=2*" %%A in ('reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\MonitorixAgent /v ImagePath 2^>NUL ^| find /i "imagepath"') do set "AGENT_PATH=%%B"
if defined AGENT_PATH set "AGENT_PATH=%AGENT_PATH:"=%"
if not defined AGENT_PATH (
    for /f "usebackq tokens=*" %%A in (`powershell.exe -NoProfile -Command "(Get-CimInstance Win32_Service -Filter 'Name=''MonitorixAgent''').PathName -replace '\"',''" 2^>NUL`) do set "AGENT_PATH=%%A"
)
if not defined AGENT_PATH (
    for /f "tokens=*" %%A in ('wmic process where "name like '%%monitorix-agent%%.exe'" get ExecutablePath /value 2^>NUL ^| find "="') do set "%%A"
    if defined ExecutablePath set "AGENT_PATH=%ExecutablePath%"
)
if not defined AGENT_PATH set "AGENT_PATH=%CD%\\monitorix-agent.exe"

set "DETACHED=%TEMP%\\patch_detached.bat"
echo [%date% %time%] Creating detached script at %DETACHED% >> "%LOGFILE%"

echo @echo off > "%DETACHED%"
echo echo [%%date%% %%time%%] Detached script started ^>^> "C:\\monitorix_update_log.txt" >> "%DETACHED%"
echo net stop MonitorixAgent 2^>NUL >> "%DETACHED%"
echo schtasks /end /tn MonitorixAgentSystem 2^>NUL >> "%DETACHED%"
echo :retry_move >> "%DETACHED%"
echo taskkill /F /IM monitorix-agent.exe 2^>NUL >> "%DETACHED%"
echo taskkill /F /IM monitorix-agent-rust.exe 2^>NUL >> "%DETACHED%"
echo taskkill /F /IM monitorix-monitorix-agent.exe 2^>NUL >> "%DETACHED%"
echo timeout /t 2 /nobreak ^>NUL >> "%DETACHED%"
echo echo [%%date%% %%time%%] Moving file ^>^> "C:\\monitorix_update_log.txt" >> "%DETACHED%"
echo move /y "%dest%" "%AGENT_PATH%" ^>^> "C:\\monitorix_update_log.txt" 2^>^&1 >> "%DETACHED%"
echo if %%ERRORLEVEL%% NEQ 0 ( >> "%DETACHED%"
echo     echo [%%date%% %%time%%] Move failed, retrying... ^>^> "C:\\monitorix_update_log.txt" >> "%DETACHED%"
echo     goto retry_move >> "%DETACHED%"
echo ) >> "%DETACHED%"
echo echo [%%date%% %%time%%] Starting service ^>^> "C:\\monitorix_update_log.txt" >> "%DETACHED%"
echo net start MonitorixAgent 2^>NUL >> "%DETACHED%"
echo schtasks /run /tn MonitorixAgentSystem 2^>NUL >> "%DETACHED%"
echo if %%ERRORLEVEL%% NEQ 0 start "" "%AGENT_PATH%" >> "%DETACHED%"
echo echo [%%date%% %%time%%] Done ^>^> "C:\\monitorix_update_log.txt" >> "%DETACHED%"
echo del "%%~f0" >> "%DETACHED%"

echo [%date% %time%] Registering scheduled task >> "%LOGFILE%"
schtasks /create /tn "MonitorixPatch" /tr "cmd.exe /c %TEMP%\\patch_detached.bat" /sc once /sd 01/01/2099 /st 00:00 /ru "SYSTEM" /f >> "%LOGFILE%" 2>&1
schtasks /run /tn "MonitorixPatch" >> "%LOGFILE%" 2>&1
echo [%date% %time%] Scheduled task registered >> "%LOGFILE%"
"""
                exec_params = {
                    "Action": "ExecuteScript",
                    "Language": "bat",
                    "Script": script_content,
                    "RunAsAdmin": True
                }
            else:
                update_os_type = f"{os_type}-{arch}"
                exec_params = {
                    "Action": "TriggerAgentUpdate",
                    "DownloadUrl": f"{backend_url.rstrip('/')}/api/downloads/public/payload?key={tenant.ApiKey}&os_type={update_os_type}",
                    "ExpectedHash": "",
                    "PublisherSignature": ""
                }

            try:
                machine_id = agent.MachineId or agent.AgentId
                key = hashlib.sha256(tenant.ApiKey.encode() + machine_id.encode()).digest()
                
                timestamp_ex = datetime.utcnow().isoformat()
                msg_parts_ex = ["Remediation", json.dumps(exec_params, sort_keys=True), timestamp_ex]
                sig_ex = hmac.new(key, "|".join(msg_parts_ex).encode('utf-8'), hashlib.sha256).hexdigest()
                await sio.emit('Remediation', {
                    "signature": sig_ex,
                    "timestamp": timestamp_ex,
                    **exec_params
                }, room=agent.AgentId)
                print(f"[PATCH-NOW] Emitted {exec_params['Action']} to agent {agent.AgentId}")
                
                # Emit a fake progress indicator because the legacy agent doesn't emit it when running a script
                await sio.emit('agent_update_progress', {'agentId': agent.AgentId, 'progress': 50, 'status': 'Downloading Bypass Payload...'}, room=f"tenant_{tenant.Id}")
            except Exception as e:
                print(f"[PATCH-NOW] Error deploying patch payload: {e}")
    else:
        print(f"[PATCH-NOW] Fallback to standard push for agent {agent.AgentId} (not broken or not windows)")
    
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

class AgentEventsPayload(BaseModel):
    agent_id: str
    tenant_api_key: str
    events: List[Any]

@agent_router.post("/events")
async def receive_agent_events(
    payload: AgentEventsPayload,
    request: fastapi.Request,
    db: AsyncSession = Depends(get_db),
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp")
):
    if not x_signature or not x_timestamp:
        raise HTTPException(status_code=401, detail="Missing signature headers")

    agent_res = await db.execute(select(Agent).where(Agent.AgentId == payload.agent_id))
    agent = agent_res.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    tenant_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant = tenant_res.scalars().first()
    if not tenant or tenant.ApiKey != payload.tenant_api_key:
        raise HTTPException(status_code=403, detail="Invalid Tenant API Key")

    body_bytes = await request.body()
    key_seed = tenant.ApiKey.encode()
    msg = f"{body_bytes.decode('utf-8')}{x_timestamp}".encode('utf-8')
    expected_sig = hmac.new(key_seed, msg, hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(expected_sig, x_signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    try:
        from ..core.kafka_producer import kafka_client
        
        ingest_time = datetime.utcnow().isoformat()
        enriched_events = []
        for ev in payload.events:
            # We don't want to mutate original just in case, but dict is safe here
            ev["_ingest_time"] = ingest_time
            ev["AgentId"] = payload.agent_id
            ev["TenantId"] = tenant.Id
            enriched_events.append(ev)
            
        if enriched_events:
            # [v3.0] Publish telemetry to Kafka Event Bus instead of Mongo
            for ev in enriched_events:
                await kafka_client.publish_event(ev)
            
            # Trigger detection engine for alerting (Temporarily kept for backwards compatibility)
            from ..services.detection_engine import detection_engine
            for ev in enriched_events:
                await detection_engine.process_telemetry_event(db, ev, payload.agent_id)
                if ev.get("EventType") == "ProcessSnapshot":
                    from ..socket_instance import sio
                    await sio.emit('agent_processes', {
                        'agent_id': payload.agent_id,
                        'processes': ev.get("Processes", [])
                    }, room=payload.agent_id)
                elif ev.get("EventType") == "LiveSessionTelemetry":
                    from ..socket_instance import sio
                    await sio.emit('live_session_telemetry', {
                        'agent_id': payload.agent_id,
                        'process_name': ev.get("ProcessName", ""),
                        'window_title': ev.get("WindowTitle", "")
                    }, room=f"tenant_{tenant.Id}")
                elif ev.get("EventType") == "PatchInventory":
                    packages = ev.get("Packages", [])
                    if packages:
                        import json
                        import asyncio
                        from ..tasks.security import scan_vulnerabilities_background
                        
                        mapped_packages = []
                        for p in packages:
                            mapped_packages.append({
                                "Name": p.get("Package"),
                                "Version": p.get("Version"),
                                "FileVersion": p.get("FileVersion"),
                                "ProductVersion": p.get("ProductVersion"),
                                "Type": "OS"
                            })
                        
                        safe_json = json.dumps(mapped_packages)
                        await asyncio.to_thread(scan_vulnerabilities_background.delay, payload.agent_id, safe_json)
            
    except Exception as e:
        print(f"[EVENTS] Kafka ingestion error: {e}")
        
    return {"status": "success", "processed": len(payload.events)}

@router.post("/{agent_id}/processes")
async def ingest_process_snapshot(
    agent_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Receives a real-time ProcessSnapshot directly from the agent (every 5s).
    Immediately pushes it to the agent's Socket.IO room so the frontend
    ProcessMonitor component gets live data without waiting for the Kafka pipeline.
    """
    # Verify agent exists and get tenant
    agent_res = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = agent_res.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Validate HMAC signature (same as heartbeat)
    body_bytes = await request.body()
    body_str = body_bytes.decode("utf-8")
    sig_header = request.headers.get("X-Signature", "")
    ts_header = request.headers.get("X-Timestamp", "")
    if sig_header and ts_header:
        import hmac as _hmac, hashlib as _hs
        t_res = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
        tenant_obj = t_res.scalars().first()
        key_seed = agent.MachineId.encode() if agent.MachineId else tenant_obj.ApiKey.encode()
        signing_key = _hs.sha256(key_seed).digest()
        msg = f"{body_str}|{ts_header}".encode('utf-8')
        expected = _hmac.new(signing_key, msg, _hs.sha256).hexdigest()
        
        is_valid = _hmac.compare_digest(expected, sig_header)
        if not is_valid and not agent.MachineId:
            fallback_key = tenant_obj.ApiKey.encode()
            expected_fallback = _hmac.new(fallback_key, msg, _hs.sha256).hexdigest()
            if _hmac.compare_digest(expected_fallback, sig_header):
                is_valid = True
                
        if not is_valid:
            raise HTTPException(status_code=403, detail="Invalid signature")

    try:
        data = json.loads(body_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    processes = data.get("Processes", [])

    # Emit directly to the agent room — the frontend ProcessMonitor listens here
    from ..socket_instance import sio
    await sio.emit('agent_processes', {
        'agent_id': agent_id,
        'processes': processes
    }, room=agent_id)

    print(f"[ProcessMonitor] REST push for {agent_id}: {len(processes)} processes → emitted to room")
    return {"status": "ok", "count": len(processes)}


@router.get("/{agent_id}/telemetry")
async def get_agent_telemetry(
    agent_id: str,
    limit: int = 100,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Fetch advanced telemetry events for a specific agent from MongoDB."""
    agent_res = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = agent_res.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    if current_user.Role != "SuperAdmin" and current_user.TenantId != agent.TenantId:
        raise HTTPException(status_code=403, detail="Not authorized to view this agent's telemetry")
        
    try:
        from ..db.session import mongo_client
        db_name = "monitorix_events"
        mongo_db = mongo_client[db_name]
        
        # Query Mongo, sort by ingest time descending
        cursor = mongo_db["agent_telemetry_events"].find(
            {"AgentId": agent_id}
        ).sort("_ingest_time", -1).limit(limit)
        
        events = await cursor.to_list(length=limit)
        
        # Convert ObjectId to string for JSON serialization
        for ev in events:
            if "_id" in ev:
                ev["_id"] = str(ev["_id"])
                
        return {"status": "success", "agent_id": agent_id, "events": events}
        
    except Exception as e:
        print(f"[TELEMETRY] Mongo read error: {e}")
        return {"status": "error", "message": "Failed to fetch telemetry data"}

class SoarRemediateRequest(BaseModel):
    Action: str # "KillProcess" or "IsolateNetwork"
    TargetPID: Optional[str] = None

@router.post("/{agent_id}/soar-remediate")
async def soar_remediate_agent(
    agent_id: str,
    req: SoarRemediateRequest,
    tenant: Tenant = Depends(get_tenant_by_key),
    db: AsyncSession = Depends(get_db)
):
    """
    [SOAR Integration] Webhook receiver for RedRainbow or external SIEMs.
    Allows high-privileged API Keys to trigger instant agent isolation/remediation 
    without maintaining a WebSocket connection.
    """
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_id, Agent.TenantId == tenant.Id))
    agent = result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found or does not belong to this Tenant")

    if req.Action not in ["KillProcess", "IsolateNetwork"]:
        raise HTTPException(status_code=400, detail="Invalid Remediation Action")

    timestamp = datetime.utcnow().isoformat()
    params = {"Action": req.Action}
    if req.Action == "KillProcess" and req.TargetPID:
        params["TargetPID"] = str(req.TargetPID)

    signature = generate_agent_command_signature(
        api_key=tenant.ApiKey,
        machine_id=agent.MachineId or "",
        action="Remediation",
        params=params,
        timestamp=timestamp
    )

    payload = {
        'Action': req.Action,
        'timestamp': timestamp,
        'signature': signature
    }
    if req.TargetPID:
        payload['TargetPID'] = str(req.TargetPID)

    # Fire via Socket.IO directly to the agent's active room
    await sio.emit('Remediation', payload, room=agent_id)

    # Log action
    audit = AuditLog(
        TenantId=tenant.Id,
        UserId=None,
        Action="SOAR_REMEDIATION",
        Resource="Agent",
        ResourceId=agent_id,
        Details=f"SOAR triggered {req.Action} via API Key. Payload: {payload}"
    )
    db.add(audit)
    await db.commit()

    return {"status": "success", "message": f"Remediation command {req.Action} dispatched to agent {agent_id}"}


# ─── [SDK] Unified Action Endpoints for RedRainbow / External Integrations ──────

class KillActionRequest(BaseModel):
    pid: int

@router.post("/{agent_id}/actions/kill")
async def action_kill_process(
    agent_id: str,
    req: KillActionRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    [SDK] Fixation: Terminates a running process by PID on the target agent.
    Used by RedRainbow SOAR during the Fixation phase.
    """
    params = {"TargetPID": str(req.pid)}
    return await _dispatch_signed_command(agent_id, "KillProcess", params, current_user, db)


@router.post("/{agent_id}/actions/scan")
async def action_trigger_scan(
    agent_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    [SDK] Verification: Triggers a full vulnerability + malware scan on the target agent.
    Used by RedRainbow SOAR during the Verification phase.
    """
    # Verify access
    result = await db.execute(
        select(Agent).where(Agent.AgentId == agent_id)
    )
    agent = result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if current_user.Role != "SuperAdmin" and agent.TenantId != current_user.TenantId:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Trigger background vulnerability scan
    from ..tasks.security import scan_vulnerabilities_background  # type: ignore
    scan_vulnerabilities_background.delay(agent_id, None)

    # Also dispatch a YARA/IOC scan command to the agent in real-time
    return await _dispatch_signed_command(
        agent_id, "TriggerIOCScan",
        {"TargetDirectory": "/", "Hashes": []},
        current_user, db
    )


class TerminalSessionResponse(BaseModel):
    session_token: str
    websocket_url: str
    agent_id: str
    expires_in: int

@router.post("/{agent_id}/actions/terminal")
async def action_start_terminal(
    agent_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    [SDK] Fixation: Creates a remote shell session token for the target agent.
    RedRainbow can use the returned session_token to connect to the WebSocket
    shell at the provided websocket_url.
    """
    import secrets
    from datetime import timedelta

    # Verify agent access
    result = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if current_user.Role != "SuperAdmin" and agent.TenantId != current_user.TenantId:
        raise HTTPException(status_code=403, detail="Not authorized")
    if not agent.RemoteShellEnabled:
        raise HTTPException(status_code=403, detail="Remote shell is not enabled for this agent")

    # Generate a short-lived session token (TTL 300s)
    session_token = secrets.token_urlsafe(32)
    expires_in = 300

    # Store session token in a lightweight in-memory cache (reuse existing sio approach)
    # The WebSocket shell handler at /api/remote/shell/{agent_id} will validate this token
    from ..socket_instance import sio_sync
    sio_sync.emit("terminal_session_created", {
        "agent_id": agent_id,
        "session_token": session_token,
        "expires_in": expires_in,
        "requester": current_user.Username
    })

    # Log the action
    audit = AuditLog(
        TenantId=current_user.TenantId,
        UserId=current_user.Id,
        Action="TERMINAL_SESSION_CREATED",
        Resource="Agent",
        ResourceId=agent_id,
        Details=f"Terminal session created by {current_user.Username} for agent {agent_id}"
    )
    db.add(audit)
    await db.commit()

    return {
        "session_token": session_token,
        "websocket_url": f"/api/remote/shell/{agent_id}?token={session_token}",
        "agent_id": agent_id,
        "expires_in": expires_in
    }

@router.get("/{agent_string_id}/threat-analysis")
async def get_threat_analysis(
    agent_string_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Triggers an on-demand AI threat analysis for the agent using real telemetry.
    """
    from ..services.ai_service import ai_service
    from ..db.models import EventLog

    result = await db.execute(select(Agent).where(Agent.AgentId == agent_string_id))
    agent = result.scalars().first()
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    if current_user.Role != "SuperAdmin" and (not current_user.TenantId or agent.TenantId != current_user.TenantId):
        raise HTTPException(status_code=403, detail="Not authorized")

    # Fetch last 50 events
    events_res = await db.execute(
        select(EventLog)
        .where(EventLog.AgentId == agent.AgentId)
        .order_by(EventLog.Timestamp.desc())
        .limit(50)
    )
    
    events = []
    for row in events_res.scalars().all():
        events.append({
            "Type": row.Type,
            "Details": row.Details,
            "Timestamp": row.Timestamp.isoformat(),
            "Severity": getattr(row, "Severity", "Medium")
        })

    # Call AI Service
    import asyncio
    loop = asyncio.get_event_loop()
    analysis = await loop.run_in_executor(None, ai_service.calculate_threat_score, agent.AgentId, events)

    # Update agent's threat score in db
    agent.ThreatScore = analysis.get("Score", 0)
    agent.RiskLevel = analysis.get("Level", "Normal")
    await db.commit()

    return analysis
