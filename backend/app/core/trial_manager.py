"""
Trial Manager - Handles 1-hour trial access for premium features
"""
from datetime import datetime, timedelta # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from sqlalchemy import and_ # type: ignore
from typing import Optional, Dict, List # type: ignore

from ..db.models import FeatureTrial, Tenant # type: ignore
from ..core.constants import FEATURE_TIERS, PLAN_LEVELS # type: ignore

# Features eligible for trial access
TRIAL_ELIGIBLE_FEATURES = ["LiveStreamEnabled", "RemoteShellEnabled"]

# Trial duration in seconds (1 hour)
TRIAL_DURATION_SECONDS = 3600


async def check_trial_eligibility(
    db: AsyncSession,
    tenant_id: int,
    feature_name: str
) -> Dict[str, any]:
    """
    Check if a tenant is eligible to start a trial for a feature.
    
    Returns:
        {
            "eligible": bool,
            "reason": str,  # If not eligible
            "existing_trial": FeatureTrial or None
        }
    """
    # Check if feature is trial-eligible
    if feature_name not in TRIAL_ELIGIBLE_FEATURES:
        return {
            "eligible": False,
            "reason": f"Feature '{feature_name}' is not eligible for trial access",
            "existing_trial": None
        }
    
    # Get tenant plan
    tenant_result = await db.execute(
        select(Tenant).where(Tenant.Id == tenant_id)
    )
    tenant = tenant_result.scalars().first()
    
    if not tenant:
        return {
            "eligible": False,
            "reason": "Tenant not found",
            "existing_trial": None
        }
    
    # Check if tenant already has access via their plan
    plan_level = PLAN_LEVELS.get(tenant.Plan, 1)
    required_level = FEATURE_TIERS.get(feature_name, 3)
    
    if plan_level >= required_level:
        return {
            "eligible": False,
            "reason": f"Feature already included in {tenant.Plan} plan",
            "existing_trial": None
        }
    
    # Check if trial already exists (used or active)
    trial_result = await db.execute(
        select(FeatureTrial).where(
            and_(
                FeatureTrial.TenantId == tenant_id,
                FeatureTrial.FeatureName == feature_name
            )
        )
    )
    existing_trial = trial_result.scalars().first()
    
    if existing_trial:
        return {
            "eligible": False,
            "reason": "Trial already used for this feature",
            "existing_trial": existing_trial
        }
    
    return {
        "eligible": True,
        "reason": None,
        "existing_trial": None
    }


async def start_trial(
    db: AsyncSession,
    tenant_id: int,
    feature_name: str
) -> Dict[str, any]:
    """
    Start a 1-hour trial for a premium feature.
    
    Returns:
        {
            "success": bool,
            "trial": FeatureTrial or None,
            "error": str or None
        }
    """
    # Check eligibility first
    eligibility = await check_trial_eligibility(db, tenant_id, feature_name)
    
    if not eligibility["eligible"]:
        return {
            "success": False,
            "trial": None,
            "error": eligibility["reason"]
        }
    
    # Create trial record
    now = datetime.utcnow()
    expires_at = now + timedelta(seconds=TRIAL_DURATION_SECONDS)
    
    trial = FeatureTrial(
        TenantId=tenant_id,
        FeatureName=feature_name,
        TrialStartedAt=now,
        TrialExpiresAt=expires_at,
        IsActive=True
    )
    
    db.add(trial)
    await db.commit()
    await db.refresh(trial)
    
    return {
        "success": True,
        "trial": trial,
        "error": None
    }


async def get_active_trial(
    db: AsyncSession,
    tenant_id: int,
    feature_name: str
) -> Optional[FeatureTrial]:
    """Get active trial for a specific feature"""
    now = datetime.utcnow()
    
    result = await db.execute(
        select(FeatureTrial).where(
            and_(
                FeatureTrial.TenantId == tenant_id,
                FeatureTrial.FeatureName == feature_name,
                FeatureTrial.IsActive == True,
                FeatureTrial.TrialExpiresAt > now
            )
        )
    )
    
    return result.scalars().first()


async def get_all_active_trials(
    db: AsyncSession,
    tenant_id: int
) -> List[FeatureTrial]:
    """Get all active trials for a tenant"""
    now = datetime.utcnow()
    
    result = await db.execute(
        select(FeatureTrial).where(
            and_(
                FeatureTrial.TenantId == tenant_id,
                FeatureTrial.IsActive == True,
                FeatureTrial.TrialExpiresAt > now
            )
        )
    )
    
    return result.scalars().all()


async def get_trial_status(
    db: AsyncSession,
    tenant_id: int
) -> Dict[str, any]:
    """
    Get comprehensive trial status for a tenant.
    
    Returns:
        {
            "active_trials": [
                {
                    "feature": str,
                    "expires_at": datetime,
                    "remaining_seconds": int
                }
            ],
            "available_trials": [str],  # Features that can be trialed
            "used_trials": [str]  # Features already trialed
        }
    """
    now = datetime.utcnow()
    
    # Get all trials (active and expired) for this tenant
    all_trials_result = await db.execute(
        select(FeatureTrial).where(FeatureTrial.TenantId == tenant_id)
    )
    all_trials = all_trials_result.scalars().all()
    
    # Get tenant plan to check what they already have access to
    tenant_result = await db.execute(
        select(Tenant).where(Tenant.Id == tenant_id)
    )
    tenant = tenant_result.scalars().first()
    plan_level = PLAN_LEVELS.get(tenant.Plan, 1) if tenant else 1
    
    # Categorize trials
    active_trials = []
    used_features = set()
    
    for trial in all_trials:
        used_features.add(trial.FeatureName)
        
        if trial.IsActive and trial.TrialExpiresAt > now:
            remaining = (trial.TrialExpiresAt - now).total_seconds()
            active_trials.append({
                "feature": trial.FeatureName,
                "expires_at": trial.TrialExpiresAt.isoformat(),
                "remaining_seconds": int(remaining)
            })
    
    # Determine available trials
    available_trials = []
    for feature in TRIAL_ELIGIBLE_FEATURES:
        # Skip if already trialed
        if feature in used_features:
            continue
        
        # Skip if already have access via plan
        required_level = FEATURE_TIERS.get(feature, 3)
        if plan_level >= required_level:
            continue
        
        available_trials.append(feature)
    
    return {
        "active_trials": active_trials,
        "available_trials": available_trials,
        "used_trials": list(used_features)
    }


async def expire_trial(
    db: AsyncSession,
    trial: FeatureTrial
) -> bool:
    """Mark a trial as inactive (expired)"""
    trial.IsActive = False
    await db.commit()
    return True


async def find_expired_trials(db: AsyncSession) -> List[FeatureTrial]:
    """Find all trials that have expired but are still marked as active"""
    now = datetime.utcnow()
    
    result = await db.execute(
        select(FeatureTrial).where(
            and_(
                FeatureTrial.IsActive == True,
                FeatureTrial.TrialExpiresAt <= now
            )
        )
    )
    
    return result.scalars().all()
