"""
Trial API Endpoints - Manage 1-hour feature trials
"""
from fastapi import APIRouter, Depends, HTTPException # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from pydantic import BaseModel # type: ignore
from typing import List, Optional # type: ignore

from ..db.session import get_db # type: ignore
from ..db.models import User # type: ignore
from .deps import get_current_user # type: ignore
from ..core import trial_manager # type: ignore
from ..socket_instance import sio # type: ignore

router = APIRouter()


class StartTrialRequest(BaseModel):
    feature: str


class TrialResponse(BaseModel):
    feature: str
    expires_at: str
    remaining_seconds: int
    is_active: bool


class StartTrialResponse(BaseModel):
    success: bool
    trial: Optional[TrialResponse]
    error: Optional[str]


class TrialStatusResponse(BaseModel):
    active_trials: List[dict]
    available_trials: List[str]
    used_trials: List[str]


@router.post("/start", response_model=StartTrialResponse)
async def start_feature_trial(
    request: StartTrialRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Start a 1-hour trial for a premium feature.
    Only available for features not included in current plan.
    """
    if not current_user.TenantId:
        raise HTTPException(status_code=400, detail="User must belong to a tenant")
    
    # Start the trial
    result = await trial_manager.start_trial(
        db=db,
        tenant_id=current_user.TenantId,
        feature_name=request.feature
    )
    
    if not result["success"]:
        return StartTrialResponse(
            success=False,
            trial=None,
            error=result["error"]
        )
    
    trial = result["trial"]
    
    # Emit Socket.IO event to enable feature on all tenant agents
    await sio.emit(
        'UpdateConfig',
        {request.feature: True},
        room=f"tenant_{current_user.TenantId}"
    )
    
    # Calculate remaining seconds
    from datetime import datetime # type: ignore
    remaining = (trial.TrialExpiresAt - datetime.utcnow()).total_seconds()
    
    return StartTrialResponse(
        success=True,
        trial=TrialResponse(
            feature=trial.FeatureName,
            expires_at=trial.TrialExpiresAt.isoformat(),
            remaining_seconds=int(remaining),
            is_active=trial.IsActive
        ),
        error=None
    )


@router.get("/status", response_model=TrialStatusResponse)
async def get_trial_status(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get trial status for current tenant.
    Shows active trials, available trials, and used trials.
    """
    if not current_user.TenantId:
        raise HTTPException(status_code=400, detail="User must belong to a tenant")
    
    status = await trial_manager.get_trial_status(
        db=db,
        tenant_id=current_user.TenantId
    )
    
    return TrialStatusResponse(
        active_trials=status["active_trials"],
        available_trials=status["available_trials"],
        used_trials=status["used_trials"]
    )


@router.get("/check/{feature}")
async def check_trial_eligibility(
    feature: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Check if current tenant is eligible to start a trial for a feature.
    """
    if not current_user.TenantId:
        raise HTTPException(status_code=400, detail="User must belong to a tenant")
    
    eligibility = await trial_manager.check_trial_eligibility(
        db=db,
        tenant_id=current_user.TenantId,
        feature_name=feature
    )
    
    return {
        "eligible": eligibility["eligible"],
        "reason": eligibility["reason"],
        "has_existing_trial": eligibility["existing_trial"] is not None
    }
