"""
Monitorix Attack-Path Validation & Automated Breach Emulation API Router (Wave 1.13)
=====================================================================================
100% Sovereign Monitorix Architecture. Zero external dependencies.
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.services.attack_validation_service import AttackValidationService

router = APIRouter()


class ExecuteValidationRequest(BaseModel):
    scenario_id: str = Field(..., description="Scenario ID to emulate (e.g. VAL-SCEN-001)")
    target_asset: str = Field("ELSEA-DESKTOP", description="Target agent, cloud account, or cluster")
    telemetry_depth: str = Field("FULL_SPECTRUM", description="Telemetry observation depth")


class CertifyPostureRequest(BaseModel):
    tenant_id: int = Field(1, description="Tenant ID to certify")


@router.get("/overview")
async def get_overview(db: AsyncSession = Depends(get_db)):
    """Retrieve validation posture score, MTTD/MTTC metrics, and defense grade"""
    try:
        return await AttackValidationService.get_overview(db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scenarios")
async def get_scenarios(
    category: Optional[str] = Query(None, description="Ransomware Blast, Identity Kill-Chain, Cloud Crown Jewel, Container Escape"),
    db: AsyncSession = Depends(get_db),
):
    """List available adversary breach validation scenarios"""
    scenarios = await AttackValidationService.get_scenarios(db, category=category)
    return [
        {
            "id": s.Id,
            "scenario_id": s.ScenarioId,
            "name": s.Name,
            "category": s.Category,
            "severity": s.Severity,
            "description": s.Description,
            "total_stages": s.TotalStages,
            "target_scope": s.TargetScope,
            "recommended_playbook": s.RecommendedPlaybook,
            "is_enabled": s.IsEnabled,
            "created_at": s.CreatedAt.isoformat() if s.CreatedAt else None,
        }
        for s in scenarios
    ]


@router.get("/executions")
async def get_executions(
    scenario_id: Optional[str] = Query(None, description="Filter by scenario ID"),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """List historical adversary validation executions"""
    executions = await AttackValidationService.get_executions(db, scenario_id=scenario_id, limit=limit)
    return [
        {
            "id": e.Id,
            "execution_id": e.ExecutionId,
            "scenario_id": e.ScenarioId,
            "target_asset": e.TargetAgentOrAsset,
            "status": e.Status,
            "defense_efficacy_score": e.DefenseEfficacyScore,
            "mttd_ms": e.MeanTimeToDetectMs,
            "mttc_ms": e.MeanTimeToContainMs,
            "stages_completed": e.StagesCompleted,
            "total_stages": e.TotalStages,
            "containment_action": e.ContainmentActionTaken,
            "forensic_proof_hash": e.ForensicProofHash,
            "started_at": e.StartedAt.isoformat() if e.StartedAt else None,
            "completed_at": e.CompletedAt.isoformat() if e.CompletedAt else None,
        }
        for e in executions
    ]


@router.get("/executions/{execution_id}")
async def get_execution_detail(execution_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve full stage logs and cryptographic proof for an execution run"""
    detail = await AttackValidationService.get_execution_detail(db, execution_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Execution {execution_id} not found")
    return detail


@router.get("/certifications")
async def get_posture_certs(db: AsyncSession = Depends(get_db)):
    """List cryptographically signed enterprise defense posture certificates"""
    certs = await AttackValidationService.get_posture_certs(db)
    return [
        {
            "id": c.Id,
            "cert_id": c.CertId,
            "tenant_id": c.TenantId,
            "posture_grade": c.PostureGrade,
            "validation_score": c.ValidationScore,
            "total_scenarios_tested": c.TotalScenariosTested,
            "prevented_kill_chains": c.PreventedKillChains,
            "cryptographic_attestation": c.CryptographicAttestation,
            "issued_at": c.IssuedAt.isoformat() if c.IssuedAt else None,
            "expires_at": c.ExpiresAt.isoformat() if c.ExpiresAt else None,
        }
        for c in certs
    ]


@router.post("/execute")
async def execute_validation_run(
    req: ExecuteValidationRequest,
    db: AsyncSession = Depends(get_db),
):
    """Trigger live end-to-end adversary breach emulation and measure defense efficacy"""
    try:
        return await AttackValidationService.execute_validation_run(
            db,
            scenario_id=req.scenario_id,
            target_asset=req.target_asset,
            telemetry_depth=req.telemetry_depth,
        )
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/certify")
async def generate_posture_certification(
    req: CertifyPostureRequest,
    db: AsyncSession = Depends(get_db),
):
    """Issue a cryptographically signed defense posture certification"""
    try:
        return await AttackValidationService.generate_posture_certification(
            db,
            tenant_id=req.tenant_id,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
