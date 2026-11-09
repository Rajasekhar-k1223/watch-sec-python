"""
[v3.9.0] Phase 15: Monitorix Security Intelligence Network API Router
=====================================================================
Endpoints:
- GET  /api/v2/intelligence/portal
- POST /api/v2/intelligence/signal/contribute
- POST /api/v2/intelligence/distribute
- GET  /api/v2/intelligence/privacy
- PUT  /api/v2/intelligence/privacy
- GET  /api/v2/intelligence/campaigns
- GET  /api/v2/intelligence/signals
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Body, Header, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

from app.db.session import get_db
from app.db.models import User
from app.api.deps import get_current_user
from app.services.security_intelligence_network_service import SecurityIntelligenceNetworkService

router = APIRouter()

# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class ContributeSignalRequest(BaseModel):
    signal_type: str = Field(..., example="IOC_PATTERN", description="IOC_PATTERN, ATTACK_TECHNIQUE, MALWARE_CHARACTERISTIC, CAMPAIGN_INDICATOR, BEHAVIORAL_PATTERN")
    indicator_value: str = Field(..., example="9b1c9f4d7e2a8c3e5f1b0a9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e")
    indicator_category: str = Field(default="Hash", example="Hash")
    mitre_tactics: List[str] = Field(default=["Execution"], example=["Execution", "Defense Evasion"])
    severity: str = Field(default="High", example="High")
    confidence_score: float = Field(default=0.95, example=0.95)
    sector: str = Field(default="Technology", example="Technology")
    metadata: Dict[str, Any] = Field(default={}, example={"malware_family": "CobaltStrike_Stager"})

class DistributeIntelligenceRequest(BaseModel):
    signal_or_campaign_id: str = Field(..., example="SIG-20261021-01")
    destination_target: str = Field(..., example="DetectionEngine", description="DetectionEngine, ThreatIntelFeed, AiSoc, SecurityGraph, SOAR, EndpointAgent")

class UpdatePrivacyProfileRequest(BaseModel):
    opt_in_sharing: bool = Field(default=True)
    share_iocs: bool = Field(default=True)
    share_techniques: bool = Field(default=True)
    share_malware_signatures: bool = Field(default=True)
    share_process_anomalies: bool = Field(default=False)
    retention_days: int = Field(default=60)

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/portal", summary="Retrieve complete global threat intelligence portal telemetry")
async def get_portal_data(
    tenant_id: Optional[int] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    target_tenant_id = tenant_id or current_user.TenantId or 1
    return await SecurityIntelligenceNetworkService.get_analyst_portal_data(target_tenant_id, db)

@router.post("/signal/contribute", summary="Contribute an anonymized, minimized threat intelligence signal")
async def contribute_signal(
    req: ContributeSignalRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    target_tenant_id = current_user.TenantId or 1
    res = await SecurityIntelligenceNetworkService.contribute_threat_signal(
        tenant_id=target_tenant_id,
        signal_type=req.signal_type,
        indicator_value=req.indicator_value,
        indicator_category=req.indicator_category,
        mitre_tactics=req.mitre_tactics,
        severity=req.severity,
        confidence_score=req.confidence_score,
        sector=req.sector,
        metadata=req.metadata,
        db=db
    )
    if not res.get("accepted"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res

@router.post("/distribute", summary="Safely distribute validated intelligence to detection engines, feeds, or agents")
async def distribute_intelligence(
    req: DistributeIntelligenceRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    res = await SecurityIntelligenceNetworkService.distribute_validated_intelligence(
        signal_or_campaign_id=req.signal_or_campaign_id,
        destination_target=req.destination_target,
        db=db
    )
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res

@router.get("/privacy", summary="Retrieve tenant privacy & telemetry sharing profile")
async def get_privacy_profile(
    tenant_id: Optional[int] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    target_tenant_id = tenant_id or current_user.TenantId or 1
    profile = await SecurityIntelligenceNetworkService.get_or_create_tenant_privacy_profile(target_tenant_id, db)
    return {
        "tenant_id": profile.TenantId,
        "opt_in_sharing": profile.OptInSharing,
        "share_iocs": profile.ShareIocs,
        "share_techniques": profile.ShareTechniques,
        "share_malware_signatures": profile.ShareMalwareSignatures,
        "share_process_anomalies": profile.ShareProcessAnomalies,
        "retention_days": profile.RetentionDays,
        "minimization_rules_enforced": profile.MinimizationRulesEnforced,
        "total_signals_contributed": profile.TotalSignalsContributed
    }

@router.put("/privacy", summary="Update tenant privacy & sharing preferences")
async def update_privacy_profile(
    req: UpdatePrivacyProfileRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    target_tenant_id = current_user.TenantId or 1
    return await SecurityIntelligenceNetworkService.update_tenant_privacy_profile(
        tenant_id=target_tenant_id,
        opt_in_sharing=req.opt_in_sharing,
        share_iocs=req.share_iocs,
        share_techniques=req.share_techniques,
        share_malware_signatures=req.share_malware_signatures,
        share_process_anomalies=req.share_process_anomalies,
        retention_days=req.retention_days,
        db=db
    )
