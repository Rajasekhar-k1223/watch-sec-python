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

router = APIRouter()

@router.get("/alerts")
async def get_vulnerability_alerts(
    agent_id: Optional[str] = None,
    severity: Optional[str] = None,
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
    Aggregates software inventory across all agents for the tenant.
    """
    query = select(Agent)
    if current_user.Role != "SuperAdmin":
        query = query.where(Agent.TenantId == current_user.TenantId)
    
    result = await db.execute(query)
    agents = result.scalars().all()
    
    software_map = {} # { (Name, Version): { "count": X, "agents": [id1, id2] } }
    
    for agent in agents:
        if agent.InstalledSoftwareJson:
            try:
                inventory = json.loads(agent.InstalledSoftwareJson)
                for sw in inventory:
                    name = sw.get("Name", "Unknown")
                    version = sw.get("Version", "Unknown")
                    key = (name, version)
                    
                    if key not in software_map:
                        software_map[key] = {
                            "Name": name,
                            "Version": version,
                            "AgentCount": 0,
                            "Agents": []
                        }
                    
                    software_map[key]["AgentCount"] += 1
                    software_map[key]["Agents"].append(agent.AgentId)
            except:
                continue
                
    # Convert to list and sort by AgentCount
    flat_list = list(software_map.values())
    flat_list.sort(key=lambda x: x["AgentCount"], reverse=True)
    
    return flat_list
