"""
[v3.0.0] Feature 57: High Availability (HA) & Disaster Recovery API
Endpoints for querying multi-node cluster topology, replication health,
and triggering automated failover recovery benchmarks.
"""

from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any

from app.db.models import User
from app.api.deps import get_current_user
from app.services.ha_cluster_engine import ha_engine

router = APIRouter()

@router.get("/status")
async def get_ha_status(
    current_user: User = Depends(get_current_user)
):
    """
    Returns live multi-node HA cluster topology, node replication lag, and quorum status.
    """
    return ha_engine.get_cluster_status()

@router.post("/failover-test")
async def run_failover_test(
    current_user: User = Depends(get_current_user)
):
    """
    Executes a simulated automated leader failure and standby promotion test.
    Validates sub-second RTO, zero data loss (RPO=0), and split-brain fencing.
    """
    return await ha_engine.execute_failover_test()
