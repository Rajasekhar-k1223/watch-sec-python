"""
[v3.8.0] Phase 14: Monitorix Autonomous Security & Defense API Router
=====================================================================
Endpoints:
- GET  /api/v2/autonomous/dashboard
- POST /api/v2/autonomous/investigation/run
- POST /api/v2/autonomous/hunting/generate
- POST /api/v2/autonomous/action/propose
- POST /api/v2/autonomous/action/{action_id}/approve
- POST /api/v2/autonomous/action/{action_id}/reject
- POST /api/v2/autonomous/action/{action_id}/rollback
- POST /api/v2/autonomous/guardrail/kill-switch
- GET  /api/v2/autonomous/guardrail/config
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Body, Header, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

from app.db.session import get_db
from app.db.models import User
from app.api.deps import get_current_user
from app.services.autonomous_security_service import AutonomousSecurityService

router = APIRouter()

# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class AutonomousInvestigationRequest(BaseModel):
    incident_id: Optional[int] = Field(default=None, example=1)
    seed_ioc_or_target: str = Field(..., example="WORKSTATION-08", description="Hostname, IP, Hash, or Alert ID to investigate")

class AutonomousHuntRequest(BaseModel):
    focus_topic: str = Field(default="Active Directory Kerberoasting & LSASS Dumping", example="LSASS memory dump")

class ProposeActionRequest(BaseModel):
    action_type: str = Field(..., example="isolate_endpoint", description="One of: isolate_endpoint, kill_process, block_ioc, disable_account, revoke_session, collect_evidence")
    target_entity: str = Field(..., example="192.168.1.105")
    incident_id: Optional[int] = Field(default=None, example=1)
    agent_id: Optional[str] = Field(default=None, example="agent-corp-042")
    confidence_score: float = Field(default=0.96, example=0.96)
    reasoning: str = Field(..., example="Host exhibits outbound Cobalt Strike beaconing on port 443 with anomalous LSASS access.")
    evidence_summary: str = Field(..., example="Memory dump matched Trojan.CobaltStrike.Stager. SHA256: 9b1c9f... (62/70 VT)")
    risk_level: str = Field(default="High", example="High")
    auto_approve_if_permitted: bool = Field(default=False)

class ApproveActionRequest(BaseModel):
    notes: Optional[str] = Field(default="Approved by SecOps lead")

class RejectActionRequest(BaseModel):
    reason: str = Field(default="False positive detected during maintenance window")
    is_false_positive: bool = Field(default=True)

class RollbackActionRequest(BaseModel):
    rollback_reason: str = Field(default="Maintenance test completed. Normal business connectivity restored.")

class KillSwitchRequest(BaseModel):
    engage: bool = Field(..., example=True)

# ---------------------------------------------------------------------------
# 14.8 Dashboard & Telemetry
# ---------------------------------------------------------------------------

@router.get("/dashboard", summary="Retrieve autonomous security operations dashboard telemetry")
async def get_dashboard(
    tenant_id: Optional[int] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    target_tenant_id = tenant_id or current_user.TenantId or 1
    return await AutonomousSecurityService.get_autonomous_dashboard_stats(target_tenant_id, db)

# ---------------------------------------------------------------------------
# 14.1 Autonomous Investigation
# ---------------------------------------------------------------------------

@router.post("/investigation/run", summary="Execute AI autonomous investigation on an endpoint, IOC or incident")
async def run_investigation(
    req: AutonomousInvestigationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    target_tenant_id = current_user.TenantId or 1
    res = await AutonomousSecurityService.run_autonomous_investigation(
        tenant_id=target_tenant_id,
        incident_id=req.incident_id,
        seed_ioc_or_target=req.seed_ioc_or_target,
        db=db
    )
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res

# ---------------------------------------------------------------------------
# 14.2 Autonomous Threat Hunting
# ---------------------------------------------------------------------------

@router.post("/hunting/generate", summary="Generate autonomous threat hunting hypothesis, queries (KQL/Sigma/SPL) and candidate rules")
async def run_hunting(
    req: AutonomousHuntRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    target_tenant_id = current_user.TenantId or 1
    res = await AutonomousSecurityService.run_autonomous_hunt(
        tenant_id=target_tenant_id,
        focus_topic=req.focus_topic,
        db=db
    )
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res

# ---------------------------------------------------------------------------
# 14.3 Autonomous Response & Confidence Engine
# ---------------------------------------------------------------------------

@router.post("/action/propose", summary="Propose policy-controlled autonomous response action with confidence scoring")
async def propose_action(
    req: ProposeActionRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    target_tenant_id = current_user.TenantId or 1
    res = await AutonomousSecurityService.propose_and_execute_response(
        tenant_id=target_tenant_id,
        action_type=req.action_type,
        target_entity=req.target_entity,
        incident_id=req.incident_id,
        agent_id=req.agent_id,
        confidence_score=req.confidence_score,
        reasoning=req.reasoning,
        evidence_summary=req.evidence_summary,
        risk_level=req.risk_level,
        auto_approve_if_permitted=req.auto_approve_if_permitted,
        db=db
    )
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res

# ---------------------------------------------------------------------------
# 14.5 Approval & Verification
# ---------------------------------------------------------------------------

@router.post("/action/{action_id}/approve", summary="Human authorization of pending autonomous action followed by post-action verification")
async def approve_action(
    action_id: str,
    req: ApproveActionRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    res = await AutonomousSecurityService.approve_and_execute_action(
        action_id=action_id,
        approver_username=current_user.Username or "secops_admin",
        db=db
    )
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res

@router.post("/action/{action_id}/reject", summary="Human rejection of pending autonomous action")
async def reject_action(
    action_id: str,
    req: RejectActionRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    res = await AutonomousSecurityService.reject_action(
        action_id=action_id,
        rejector_username=current_user.Username or "secops_admin",
        reason=req.reason,
        is_false_positive=req.is_false_positive,
        db=db
    )
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res

# ---------------------------------------------------------------------------
# 14.6 Safe Rollback
# ---------------------------------------------------------------------------

@router.post("/action/{action_id}/rollback", summary="Execute safe rollback for a completed reversible action")
async def rollback_action(
    action_id: str,
    req: RollbackActionRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    res = await AutonomousSecurityService.rollback_action(
        action_id=action_id,
        operator_username=current_user.Username or "secops_admin",
        rollback_reason=req.rollback_reason,
        db=db
    )
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res

# ---------------------------------------------------------------------------
# 14.7 AI Guardrails & Human Override Kill Switch
# ---------------------------------------------------------------------------

@router.post("/guardrail/kill-switch", summary="Engage or disengage emergency human override kill switch")
async def toggle_kill_switch(
    req: KillSwitchRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    target_tenant_id = current_user.TenantId or 1
    return await AutonomousSecurityService.toggle_human_override_kill_switch(
        tenant_id=target_tenant_id,
        engage_kill_switch=req.engage,
        operator_username=current_user.Username or "secops_admin",
        db=db
    )

@router.get("/guardrail/config", summary="Retrieve tenant autonomous safety guardrails")
async def get_guardrail_config(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    target_tenant_id = current_user.TenantId or 1
    cfg = await AutonomousSecurityService.get_or_create_guardrail_config(target_tenant_id, db)
    return {
        "tenant_id": cfg.TenantId,
        "autonomy_mode": cfg.AutonomyMode,
        "min_confidence_threshold": cfg.MinConfidenceThreshold,
        "require_human_approval_for_high_impact": cfg.RequireHumanApprovalForHighImpact,
        "rate_limit_per_minute": cfg.RateLimitPerMinute,
        "circuit_breaker_tripped": cfg.CircuitBreakerTripped,
        "prompt_injection_defense_enabled": cfg.PromptInjectionDefenseEnabled,
        "groundedness_threshold": cfg.GroundednessThreshold,
        "human_override_kill_switch": cfg.HumanOverrideKillSwitch
    }
