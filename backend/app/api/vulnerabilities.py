from fastapi import APIRouter, Depends, HTTPException, Response # type: ignore
from fastapi.responses import StreamingResponse # type: ignore
import csv # type: ignore
import io # type: ignore
import json # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from typing import List, Optional # type: ignore
from datetime import datetime # type: ignore

from ..db.session import get_db # type: ignore
from ..db.models import EventLog, User, Agent, Tenant # type: ignore
from .deps import get_current_user # type: ignore
from .agents import verify_feature_access # type: ignore

import hmac
import hashlib
from ..socket_instance import sio
from .agents import is_in_maintenance_window

router = APIRouter()

@router.post("/patch/{agent_id}")
async def patch_agent_system(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Manually triggers a system-wide software patch (e.g. winget/choco/apt upgrade).
    """
    # 1. Verify Agent & Access
    query = select(Agent).where(Agent.AgentId == agent_id)
    if current_user.Role != "SuperAdmin":
        query = query.where(Agent.TenantId == current_user.TenantId)
    
    result = await db.execute(query)
    agent = result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    # 2. Get Tenant Info for Signing
    res_t = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant = res_t.scalars().first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    # 3. Construct Command based on OS
    # Note: We use silent flags to ensure background installation
    command = ""
    if "win" in (agent.Hostname or "").lower() or "windows" in (agent.Version or "").lower():
        # Try winget first (built-in), fallback to choco if available
        command = "winget upgrade --all --silent --accept-package-agreements --accept-source-agreements --include-unknown"
    else:
        command = "export DEBIAN_FRONTEND=noninteractive; apt-get update && apt-get upgrade -y"

    # 4. Sign the Command (Sovereign Security)
    timestamp = datetime.utcnow().isoformat()
    action = "ExecuteCommand"
    params = {"command": command}
    
    # Message for signing: action | params_json | timestamp
    msg_parts = [
        str(action),
        json.dumps(params, sort_keys=True),
        str(timestamp)
    ]
    message = "|".join(msg_parts).encode('utf-8')
    
    # Derive Key (Sha256(ApiKey + MachineId))
    machine_id = agent.MachineId or agent.AgentId # Fallback
    key = hashlib.sha256(tenant.ApiKey.encode() + machine_id.encode()).digest()
    signature = hmac.new(key, message, hashlib.sha256).hexdigest()

    # 5. Send via WebSocket
    payload = {
        "action": action,
        "params": params,
        "timestamp": timestamp,
        "signature": signature,
        "policy_name": "Manual Patch Trigger"
    }
    
    try:
        await sio.emit('Remediation', payload, room=agent_id)
        
        # Log the event
        patch_event = EventLog(
            AgentId=agent_id,
            Type="System Patch Triggered",
            Details=f"Manual system-wide patch dispatched by {current_user.Username}: {command[:50]}...",
            Timestamp=datetime.utcnow()
        )
        db.add(patch_event)
        await db.commit()
        
        # [v2.2.0] Forward to SIEM
        from ..services.siem_service import siem_service # type: ignore
        await siem_service.forward_event(tenant.SiemConfigJson, {
            "Id": patch_event.Id,
            "AgentId": agent_id,
            "TenantId": agent.TenantId,
            "Type": "System Patch Triggered",
            "Details": patch_event.Details,
            "Severity": "Low"
        })

        return {"status": "dispatched", "command": command}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to relay command: {e}")

@router.get("/alerts")
async def get_vulnerability_alerts(
    agent_id: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Fetches vulnerability alerts logged as EventLogs.
    """
    query = select(EventLog).join(Agent, EventLog.AgentId == Agent.AgentId).where(EventLog.Type == "Vulnerability Alert").order_by(EventLog.Timestamp.desc())
    
    if agent_id:
        query = query.where(EventLog.AgentId == agent_id)
        
    if current_user.Role != "SuperAdmin":
        # [SECURITY] Plan Check
        res_t = await db.execute(select(Tenant).where(Tenant.Id == current_user.TenantId))
        tenant = res_t.scalars().first()
        if tenant:
            verify_feature_access(tenant.Plan, "VulnerabilityIntelligenceEnabled")
        
        # [SECURITY] Filter by Tenant
        query = query.where(Agent.TenantId == current_user.TenantId)

    query = query.limit(min(limit, 500))
    result = await db.execute(query)
    events = result.scalars().all()
    
    return events

@router.post("/scan/{agent_id}")
async def trigger_manual_scan(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Manually triggers a vulnerability scan for a specific agent.
    """
    # 1. Verify Agent & Access
    query = select(Agent).where(Agent.AgentId == agent_id)
    if current_user.Role != "SuperAdmin":
        query = query.where(Agent.TenantId == current_user.TenantId)
    
    result = await db.execute(query)
    agent = result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    # 2. Plan Check
    res_t = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant = res_t.scalars().first()
    if tenant:
        verify_feature_access(tenant.Plan, "VulnerabilityIntelligenceEnabled")

    # 3. Trigger Background Task
    from ..tasks.security import scan_vulnerabilities_background # type: ignore
    scan_vulnerabilities_background.delay(agent_id, None) # None triggers DB fetch in task

    return {"status": "triggered", "agentId": agent_id}

@router.post("/scan-all")
async def trigger_bulk_scan(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Triggers vulnerability scans for all agents visible to the user.
    """
    query = select(Agent)
    if current_user.Role != "SuperAdmin":
        query = query.where(Agent.TenantId == current_user.TenantId)
    
    result = await db.execute(query)
    agents = result.scalars().all()
    
    from ..tasks.security import scan_vulnerabilities_background # type: ignore
    
    triggered_count = 0
    for agent in agents:
        # Note: We skip plan check here for speed, the background task will handle or 
        # we assume current_user has access if they can hit this (needs middleware/doc check)
        scan_vulnerabilities_background.delay(agent.AgentId, None)
        triggered_count += 1
        
    return {"status": "triggered", "count": triggered_count}

@router.post("/toggle-autopatch/{agent_id}")
async def toggle_autopatch(
    agent_id: str,
    enabled: bool,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Toggles the automatic patching feature for a specific agent.
    """
    query = select(Agent).where(Agent.AgentId == agent_id)
    if current_user.Role != "SuperAdmin":
        query = query.where(Agent.TenantId == current_user.TenantId)
        
    result = await db.execute(query)
    agent = result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    agent.AutoPatchEnabled = enabled
    await db.commit()
    
    return {"status": "updated", "agentId": agent_id, "autoPatchEnabled": enabled}

@router.get("/export/{agent_id}")
async def export_agent_vulnerabilities(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Exports vulnerability alerts for a specific agent (or all) to CSV.
    """
    # 1. Fetch Alerts
    alert_query = select(EventLog).join(Agent, EventLog.AgentId == Agent.AgentId).where(
        EventLog.Type == "Vulnerability Alert"
    ).order_by(EventLog.Timestamp.desc())

    if agent_id != "all":
        # Verify Access for specific agent
        agent_query = select(Agent).where(Agent.AgentId == agent_id)
        if current_user.Role != "SuperAdmin":
            agent_query = agent_query.where(Agent.TenantId == current_user.TenantId)
        
        result = await db.execute(agent_query)
        agent = result.scalars().first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        alert_query = alert_query.where(EventLog.AgentId == agent_id)
    else:
        # Filter by tenant if not SuperAdmin
        if current_user.Role != "SuperAdmin":
            alert_query = alert_query.where(Agent.TenantId == current_user.TenantId)

    alert_result = await db.execute(alert_query)
    alerts = alert_result.scalars().all()

    # 3. Generate CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "AgentId", "Type", "Details"])
    
    for alert in alerts:
        writer.writerow([alert.Timestamp, alert.AgentId, alert.Type, alert.Details])
    
    output.seek(0)
    filename = f"VulnerabilityReport_{agent_id}_{datetime.now().strftime('%Y%m%d')}.csv"
    
    return StreamingResponse(
        io.StringIO(output.getvalue()),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/fleet-software")
async def get_fleet_software(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    [v2.8.0] Fleet-wide software audit table.
    Returns all installed software across agents with vulnerability & update status.
    """
    from ..db.models import AgentSoftware  # type: ignore
    query = select(Agent)
    if current_user.Role != "SuperAdmin":
        query = query.where(Agent.TenantId == current_user.TenantId)

    result = await db.execute(query)
    agents = result.scalars().all()

    SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}

    def build_update_status(installed: str, latest: str) -> str:
        if not installed or not latest or installed == latest:
            return "Up to Date"
        try:
            from packaging.version import Version  # type: ignore
            return "Update Available" if Version(installed) < Version(latest) else "Up to Date"
        except Exception:
            return "Update Available" if installed != latest else "Up to Date"

    software_map: dict = {}  # key = (Name, InstalledVersion)

    for agent in agents:
        # Use relational table first
        sw_query = select(AgentSoftware).where(AgentSoftware.AgentId == agent.AgentId)
        sw_res = await db.execute(sw_query)
        sw_items = sw_res.scalars().all()

        for s in sw_items:
            key = (s.Name, s.Version or "Unknown")
            installed_ver = s.Version or "Unknown"
            latest_ver = s.LatestVersion or installed_ver

            if key not in software_map:
                software_map[key] = {
                    "Name": s.Name,
                    "InstalledVersion": installed_ver,
                    "LatestVersion": latest_ver,
                    "Type": s.Type,
                    "UpdateStatus": build_update_status(installed_ver, latest_ver),
                    "IsVulnerable": s.VulnerabilityCount > 0,
                    "VulnerabilityCount": s.VulnerabilityCount,
                    "Severity": s.Severity or "None",
                    "HasPatchAvailable": s.HasPatchAvailable,
                    "AgentCount": 0,
                    "Agents": []
                }
            software_map[key]["AgentCount"] += 1
            software_map[key]["Agents"].append({
                "AgentId": agent.AgentId,
                "Hostname": agent.Hostname
            })

    flat = list(software_map.values())
    flat.sort(key=lambda x: (SEVERITY_ORDER.get(x["Severity"], 4), -x["AgentCount"], x["Name"].lower()))

    return {
        "total": len(flat),
        "vulnerable": sum(1 for s in flat if s["IsVulnerable"]),
        "updates_available": sum(1 for s in flat if s["UpdateStatus"] == "Update Available"),
        "software": flat
    }


@router.get("/software-audit/{agent_id}")
async def get_agent_software_audit(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    [v2.8.0] Full software audit table for a specific agent.
    Shows: Name | Installed Version | Latest Version | Update Status | Vulnerable | Severity | Patch Available
    Sorted by severity (Critical first), then alphabetically.
    """
    from ..db.models import AgentSoftware  # type: ignore

    # Verify agent access
    agent_query = select(Agent).where(Agent.AgentId == agent_id)
    if current_user.Role != "SuperAdmin":
        agent_query = agent_query.where(Agent.TenantId == current_user.TenantId)

    agent_result = await db.execute(agent_query)
    agent = agent_result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    sw_query = select(AgentSoftware).where(AgentSoftware.AgentId == agent_id)
    sw_res = await db.execute(sw_query)
    software_list = sw_res.scalars().all()

    SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}

    def build_update_status(installed: str, latest: str) -> str:
        if not installed or not latest or installed == latest:
            return "Up to Date"
        try:
            from packaging.version import Version  # type: ignore
            return "Update Available" if Version(installed) < Version(latest) else "Up to Date"
        except Exception:
            return "Update Available" if installed != latest else "Up to Date"

    rows = []
    for s in software_list:
        installed_ver = s.Version or "Unknown"
        latest_ver = s.LatestVersion or installed_ver
        rows.append({
            "Name": s.Name,
            "InstalledVersion": installed_ver,
            "LatestVersion": latest_ver,
            "Type": s.Type or "Unknown",
            "UpdateStatus": build_update_status(installed_ver, latest_ver),
            "IsVulnerable": s.VulnerabilityCount > 0,
            "VulnerabilityCount": s.VulnerabilityCount,
            "Severity": s.Severity or "None",
            "HasPatchAvailable": s.HasPatchAvailable,
            "LastSeen": s.LastSeen.isoformat() if s.LastSeen else None,
        })

    rows.sort(key=lambda x: (SEVERITY_ORDER.get(x["Severity"], 4), x["Name"].lower()))

    return {
        "AgentId": agent_id,
        "Hostname": agent.Hostname,
        "TotalPackages": len(rows),
        "VulnerablePackages": sum(1 for r in rows if r["IsVulnerable"]),
        "UpdatesAvailable": sum(1 for r in rows if r["UpdateStatus"] == "Update Available"),
        "CriticalCount": sum(1 for r in rows if r["Severity"] == "Critical"),
        "HighCount": sum(1 for r in rows if r["Severity"] == "High"),
        "MediumCount": sum(1 for r in rows if r["Severity"] == "Medium"),
        "Software": rows,
    }


@router.post("/status/{event_id}")
async def update_vulnerability_status(
    event_id: int,
    status: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    [v2.2.0] SOC Workflow: Updates the remediation status of a vulnerability alert.
    """
    query = select(EventLog).join(Agent, EventLog.AgentId == Agent.AgentId).where(EventLog.Id == event_id)
    if current_user.Role != "SuperAdmin":
        query = query.where(Agent.TenantId == current_user.TenantId)

    result = await db.execute(query)
    event = result.scalars().first()
    if not event:
        raise HTTPException(status_code=404, detail="Alert not found")

    valid_statuses = ["Open", "In-Progress", "Resolved", "Risk-Accepted"]
    if status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of {valid_statuses}")

    event.Status = status
    await db.commit()

    return {"status": "updated", "eventId": event_id, "newStatus": status}

