"""
[v18.3.0] Monitorix ITDR API Router (Identity Threat Detection & Response)
==========================================================================
API Endpoints:
- GET  /api/v2/itdr/overview        - Aggregated posture, high-risk counts, tier distribution
- GET  /api/v2/itdr/accounts        - Directory accounts with privilege tiers & posture flags
- GET  /api/v2/itdr/threats         - Active identity threats (Kerberoasting, DCSync, PtH)
- GET  /api/v2/itdr/graph           - Identity attack path graph nodes & relationships
- POST /api/v2/itdr/evaluate        - Real-time heuristic evaluation for identity telemetry
- POST /api/v2/itdr/contain         - 1-click active response containment
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Body, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

from app.db.session import get_db
from app.services.itdr_service import MonitorixITDRService

router = APIRouter()

# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class EvaluateEventRequest(BaseModel):
    event_type: str = Field(..., example="TGS_REQUEST", description="TGS_REQUEST, DCSYNC, NTLM_LOGON, OAUTH_CONSENT, etc.")
    source_account: Optional[str] = Field(default="unknown", example="sconnor@corp.enterprise.com")
    target_account: Optional[str] = Field(default="unknown", example="svc_mssql_prod")
    source_host: Optional[str] = Field(default="0.0.0.0", example="10.0.4.15")
    target_domain: Optional[str] = Field(default="corp.enterprise.com", example="corp.enterprise.com")
    encryption: Optional[str] = Field(default=None, example="0x17 (RC4_HMAC_MD5)")
    spn: Optional[str] = Field(default=None, example="MSSQLSvc/db01.corp.enterprise.com:1433")
    auth_package: Optional[str] = Field(default=None, example="NTLM")
    logon_type: Optional[Any] = Field(default=None, example=3)
    scopes: Optional[List[str]] = Field(default=None, example=["Directory.ReadWrite.All"])
    simulate_threat: Optional[str] = Field(default=None, example=None)

class ContainThreatRequest(BaseModel):
    threat_id: str = Field(..., example="ITDR-THR-2026-001")
    action: str = Field(default="DISABLE_ACCOUNT", example="DISABLE_ACCOUNT", description="DISABLE_ACCOUNT, REVOKE_OAUTH_TOKENS, TRIGGER_PASSWORD_RESET, ISOLATE_KERBEROS_TICKET")

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/overview")
async def get_itdr_overview(db: AsyncSession = Depends(get_db)):
    """Retrieve high-level ITDR identity posture, risk scores, and threat counters."""
    return await MonitorixITDRService.get_overview(db)

@router.get("/accounts")
async def get_itdr_accounts(
    privilege_tier: Optional[str] = Query(None, description="TIER_0_DOMAIN_ADMIN, TIER_1_SERVER_ADMIN, TIER_2_USER, TIER_CRITICAL_SERVICE"),
    min_risk: Optional[float] = Query(None, description="Filter accounts with risk score >= min_risk"),
    account_type: Optional[str] = Query(None, description="USER, SERVICE_ACCOUNT, ADMIN, OAUTH_APP, GUEST"),
    db: AsyncSession = Depends(get_db)
):
    """List directory and cloud accounts with privilege tiers, shadow admin flags, and risk."""
    return await MonitorixITDRService.get_accounts(
        db,
        privilege_tier=privilege_tier,
        min_risk=min_risk,
        account_type=account_type
    )

@router.get("/threats")
async def get_itdr_threats(
    status_filter: Optional[str] = Query(None, description="ACTIVE, INVESTIGATING, CONTAINED, RESOLVED"),
    severity_filter: Optional[str] = Query(None, description="CRITICAL, HIGH, MEDIUM, LOW"),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve identity threat events (Kerberoasting, Pass-the-Hash, DCSync, OAuth abuse)."""
    return await MonitorixITDRService.get_threats(
        db,
        status_filter=status_filter,
        severity_filter=severity_filter
    )

@router.get("/graph")
async def get_itdr_graph(db: AsyncSession = Depends(get_db)):
    """Retrieve graph representation (nodes & edges) mapping privilege escalation paths to Tier-0."""
    return await MonitorixITDRService.get_attack_graph(db)

@router.post("/evaluate")
async def evaluate_identity_event(
    req: EvaluateEventRequest,
    db: AsyncSession = Depends(get_db)
):
    """Evaluate real-time identity telemetry against heuristic detection rules."""
    return await MonitorixITDRService.evaluate_identity_event(db, req.dict())

@router.post("/contain")
async def contain_identity_threat(
    req: ContainThreatRequest,
    db: AsyncSession = Depends(get_db)
):
    """Execute 1-click active response containment on an identity threat."""
    return await MonitorixITDRService.contain_threat(db, req.threat_id, req.action)
