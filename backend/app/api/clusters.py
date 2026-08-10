import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from ..db.session import get_db
from ..db.models import Agent, EventLog, User
from .deps import get_current_user as get_current_active_user

router = APIRouter()
logger = logging.getLogger("ClusterAPI")

@router.get("/{cluster_name}/events")
async def get_cluster_events(
    cluster_name: str,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """[v2.6.0] Aggregated Cluster Log Stream: Fetches events for all nodes in a cluster."""
    
    # 1. Identify all agents in the cluster
    agent_query = select(Agent.AgentId).where(
        Agent.ClusterName == cluster_name,
        Agent.TenantId == user.TenantId
    )
    result = await db.execute(agent_query)
    agent_ids = result.scalars().all()
    
    if not agent_ids:
        return []
        
    # 2. Fetch aggregated events for these agents
    event_query = select(EventLog).where(
        EventLog.AgentId.in_(agent_ids)
    ).order_by(EventLog.Timestamp.desc()).limit(limit)
    
    event_result = await db.execute(event_query)
    events = event_result.scalars().all()
    
    return events

@router.get("/{cluster_name}/health")
async def get_cluster_health(
    cluster_name: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """[v2.6.0] Cluster Health Summary: Aggregate metrics for the entire node group."""
    query = select(Agent).where(
        Agent.ClusterName == cluster_name,
        Agent.TenantId == user.TenantId
    )
    result = await db.execute(query)
    agents = result.scalars().all()
    
    if not agents:
        raise HTTPException(status_code=404, detail="Cluster not found")
        
    total = len(agents)
    online = len([a for a in agents if a.Status == "Online"])
    avg_cpu = sum(a.CpuUsage or 0 for a in agents) / total if total > 0 else 0
    avg_mem = sum(a.MemoryUsage or 0 for a in agents) / total if total > 0 else 0
    
    return {
        "cluster": cluster_name,
        "nodes": {
            "total": total,
            "online": online,
            "offline": total - online
        },
        "aggregateMetrics": {
            "avgCpuUsage": round(avg_cpu, 2),
            "avgMemoryUsage": round(avg_mem, 2)
        },
        "status": "Healthy" if online == total else "Degraded" if online > 0 else "Down"
    }

@router.post("/{cluster_name}/patch")
async def patch_cluster(
    cluster_name: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """[v2.6.0] Cluster Rolling Patch: Sequentially updates all nodes in a cluster."""
    # Verify cluster exists and belongs to tenant
    query = select(Agent).where(
        Agent.ClusterName == cluster_name,
        Agent.TenantId == user.TenantId
    )
    result = await db.execute(query)
    agents = result.scalars().all()
    
    if not agents:
        raise HTTPException(status_code=404, detail="Cluster not found or empty")
        
    # Trigger the background orchestration task
    from ..tasks.rolling_updates import execute_cluster_patch # type: ignore
    execute_cluster_patch.delay(cluster_name, user.TenantId, user.Id)
    
    return {
        "status": "queued",
        "cluster": cluster_name,
        "nodesFound": len(agents),
        "message": "Rolling patch initiated. Status updates will be sent via WebSocket."
    }
