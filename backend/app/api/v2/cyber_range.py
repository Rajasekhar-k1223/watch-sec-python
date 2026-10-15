"""
[v3.0.0] Cyber Range & Adversary Simulation API
Endpoints for triggering live adversary scenarios, inspecting attack stages,
and validating autonomous EDR containment.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from app.db.session import get_db
from app.db.models import User
from app.api.deps import get_current_user
from app.services.cyber_range_engine import cyber_range_engine

router = APIRouter()

class SimulationRunRequest(BaseModel):
    scenario_code: str
    target_agent_id: Optional[str] = None

@router.get("/scenarios")
async def list_scenarios(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Lists all available attack simulation scenarios in the Cyber Range catalog."""
    return await cyber_range_engine.get_scenarios(db)

@router.get("/runs")
async def list_simulation_runs(
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieves history of past adversary simulation runs."""
    return await cyber_range_engine.get_recent_runs(db, limit=limit)

@router.post("/run")
async def run_simulation(
    payload: SimulationRunRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Executes a multi-stage attack scenario against a selected agent.
    Validates end-to-end detection rules and automated SOAR containment.
    """
    if current_user.Role not in ("SuperAdmin", "TenantAdmin"):
        raise HTTPException(status_code=403, detail="Insufficient privileges to trigger adversary simulation.")

    try:
        result = await cyber_range_engine.execute_simulation(
            db=db,
            scenario_code=payload.scenario_code,
            target_agent_id=payload.target_agent_id
        )
        return {"status": "success", "result": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Simulation error: {str(e)}")
