from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List

from ..db.session import get_db
from ..db.models import Agent, User
from .deps import get_current_user

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
        # Create Agent Node
        nodes.append({
            "id": agent.AgentId,
            "label": agent.AgentId,
            "type": "agent",
            "os": "windows", # TODO: Store OS in DB
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
