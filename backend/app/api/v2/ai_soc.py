"""
[v3.0.0] Feature 60 & 61: AI SOC Evaluation & Autonomous Guardrails API
Endpoints for running AI accuracy benchmarks, inspecting investigation scores,
and configuring Human-In-The-Loop (HITL) response policies & circuit breakers.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from app.db.models import User
from app.api.deps import get_current_user
from app.services.ai_soc_eval_guardrails import ai_soc_engine

router = APIRouter()

class GuardrailUpdateRequest(BaseModel):
    autonomy_mode: Optional[str] = None
    max_autonomous_actions_per_hour: Optional[int] = None
    protected_critical_assets: Optional[List[str]] = None

@router.post("/benchmark/run")
async def run_ai_soc_benchmark(
    current_user: User = Depends(get_current_user)
):
    """
    Executes live AI SOC accuracy benchmark across 10 gold-standard security attack scenarios.
    Measures root cause accuracy, MITRE precision, hallucination rate, and triage latency.
    """
    return await ai_soc_engine.run_accuracy_benchmark()

@router.get("/benchmark/latest")
async def get_latest_ai_benchmark(
    current_user: User = Depends(get_current_user)
):
    """
    Returns latest AI SOC evaluation report and accuracy scorecard.
    """
    return ai_soc_engine.get_latest_benchmark()

@router.get("/guardrails")
async def get_guardrails_configuration(
    current_user: User = Depends(get_current_user)
):
    """
    Returns current Autonomous Response Guardrails, circuit breaker status, and protected asset rules.
    """
    return ai_soc_engine.get_guardrails()

@router.patch("/guardrails")
async def update_guardrails_configuration(
    request: GuardrailUpdateRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Updates autonomous response boundaries, maximum containment actions per hour, and asset exclusions.
    """
    updates = {k: v for k, v in request.dict().items() if v is not None}
    return ai_soc_engine.update_guardrails(updates)

@router.post("/guardrails/circuit-breaker/reset")
async def reset_circuit_breaker(
    current_user: User = Depends(get_current_user)
):
    """
    Manually resets the autonomous containment circuit breaker after safety review.
    """
    return ai_soc_engine.reset_circuit_breaker()
