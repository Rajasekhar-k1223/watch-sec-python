"""
================================================================================
MONITORIX API v2 — CONTINUOUS EVOLUTION & RELEASE GOVERNANCE (Phase 18)
================================================================================
Endpoints for the permanent Monitorix engineering & release program:
- 7 Release Streams (Major, Minor, Security, Agent, Detection-pack, Intel, Connector)
- 13 Production Release Gates automated evaluation & verification
- 10-Stage Continuous Development Lifecycle
- Continuous Quality Metrics (AI, Agent fleet, Platform, Security, Detection, Compliance)
- Versioning enforcement: Rejects Phase 19/20, enforces Monitorix v18.x+
================================================================================
"""

from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.services.continuous_evolution_service import (
    ContinuousEvolutionService,
    MANDATORY_RELEASE_GATES,
    CONTINUOUS_DEVELOPMENT_LIFECYCLE,
)

router = APIRouter()


class ReleaseRegistrationRequest(BaseModel):
    version_string: str = Field(..., example="v18.1.0-STABLE")
    stream_key: str = Field(..., example="MINOR")
    release_type: str = Field(..., example="MINOR")
    changelog_summary: str = Field(..., example="Sub-second graph correlation and kernel telemetry expansion.")
    rollback_target_version: Optional[str] = Field("v18.0.0", example="v18.0.0")


class GateEvaluationRequest(BaseModel):
    release_id: str = Field(..., example="REL-V18-1-0-CANARY")


class PromotionRequest(BaseModel):
    target_stage: str = Field(..., example="PRODUCTION") # CANARY, STAGING, PRODUCTION
    canary_percent: float = Field(100.0, ge=0.0, le=100.0, example=100.0)


class RollbackRequest(BaseModel):
    reason: str = Field(..., example="Canary fleet latency spike detected during regional rollout.")


@router.get("/overview", summary="Continuous Evolution Program Overview")
async def get_evolution_overview(db: AsyncSession = Depends(get_db)):
    """Returns the comprehensive overview of the continuous evolution program, active streams, and telemetry."""
    try:
        return await ContinuousEvolutionService.get_overview(db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/lifecycle", summary="10-Stage Continuous Development Lifecycle")
async def get_lifecycle_stages():
    """Returns the continuous development lifecycle workflow definitions."""
    return {
        "lifecycle_model": "CONTINUOUS_RESEARCH_AND_RELEASE",
        "stages": CONTINUOUS_DEVELOPMENT_LIFECYCLE
    }


@router.get("/gates", summary="Mandatory 13 Production Release Gates")
async def get_release_gates_definition():
    """Returns the specification and pass criteria for all 13 production release gates."""
    return {
        "total_gates": len(MANDATORY_RELEASE_GATES),
        "policy": "100% of gates must pass before any production deployment.",
        "gates": MANDATORY_RELEASE_GATES
    }


@router.post("/gates/evaluate", summary="Evaluate All 13 Release Gates on a Release Candidate")
async def evaluate_release_gates(payload: GateEvaluationRequest, db: AsyncSession = Depends(get_db)):
    """Executes automated verification across all 13 production release gates for the target release."""
    try:
        return await ContinuousEvolutionService.evaluate_release_gates(db, payload.release_id)
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/releases", summary="Register New Versioned Release (Enforcing v18.x+ Convention)")
async def register_versioned_release(payload: ReleaseRegistrationRequest, db: AsyncSession = Depends(get_db)):
    """Registers a new release candidate. Rejects numbered phases (e.g. Phase 19/20) per master architecture rules."""
    try:
        return await ContinuousEvolutionService.register_versioned_release(
            session=db,
            version_string=payload.version_string,
            stream_key=payload.stream_key,
            release_type=payload.release_type,
            changelog=payload.changelog_summary,
            rollback_target=payload.rollback_target_version
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/releases/{release_id}/promote", summary="Promote Release to Canary or Production")
async def promote_release(release_id: str, payload: PromotionRequest, db: AsyncSession = Depends(get_db)):
    """Promotes a release to CANARY or PRODUCTION after certifying all 13 gates have passed."""
    try:
        return await ContinuousEvolutionService.promote_release(
            session=db,
            release_id=release_id,
            target_stage=payload.target_stage,
            canary_percent=payload.canary_percent
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/releases/{release_id}/rollback", summary="Trigger Emergency Rollback to Baseline")
async def trigger_rollback(release_id: str, payload: RollbackRequest, db: AsyncSession = Depends(get_db)):
    """Executes an emergency rollback of an active release back to the certified baseline version."""
    try:
        return await ContinuousEvolutionService.trigger_emergency_rollback(
            session=db,
            release_id=release_id,
            reason=payload.reason
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
