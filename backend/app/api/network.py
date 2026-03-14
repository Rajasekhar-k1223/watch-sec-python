from fastapi import APIRouter, Depends # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from typing import List # type: ignore

from ..db.session import get_db # type: ignore
from ..db.models import Agent, User, Tenant # type: ignore
from .deps import get_current_user # type: ignore
from .agents import verify_feature_access # type: ignore

router = APIRouter()

@router.get("/topology")
async def get_network_topology(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Goal: Return Nodes and Edges for Front-end visualization
    
    query = select(Agent)
    if current_user.Role != "SuperAdmin":
        query = query.where(Agent.TenantId == current_user.TenantId)
    
    # [SECURITY] Plan Check (Network Topology is Enterprise)
    if current_user.Role != "SuperAdmin":
        res_t = await db.execute(select(Tenant).where(Tenant.Id == current_user.TenantId))
        tenant = res_t.scalars().first()
        if tenant:
            verify_feature_access(tenant.Plan, "NetworkMonitoringEnabled")

    result = await db.execute(query)
    agents = result.scalars().all()
    
    nodes = []
    edges = []
    
    # 1. Create Gateway Node (Mock Central Node)
    nodes.append({
        "id": "gateway", 
        "label": "Gateway", 
        "type": "gateway",
        "color": "#3b82f6"
    })
    
    subnets = {}
    
    for agent in agents:
        # OS Inference from Hostname
        os_type = "windows"
        h_lower = agent.Hostname.lower() if agent.Hostname else ""
        if "ubuntu" in h_lower or "linux" in h_lower:
            os_type = "linux"
        elif "mac" in h_lower or "darwin" in h_lower:
            os_type = "macos"

        # Create Agent Node
        nodes.append({
            "id": agent.AgentId,
            "label": agent.AgentId,
            "type": "agent",
            "os": os_type,
            "color": "#10b981" if agent.ScreenshotsEnabled else "#ef4444"
        })
        
        # Link to Gateway (Star Topology for now)
        edges.append({
            "source": agent.AgentId,
            "target": "gateway",
            "animated": True
        })
        
        # Identify Subnets (Mock Logic: Group by first 3 octets)
        if agent.LocalIp:
            parts = agent.LocalIp.split('.')
            if len(parts) == 4:
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.x"
                if subnet not in subnets:
                    subnets[subnet] = []
                subnets[subnet].append(agent.AgentId)

    # Add Subnet Links? for now Star topology is enough for demo
    
    return {"nodes": nodes, "edges": edges}
