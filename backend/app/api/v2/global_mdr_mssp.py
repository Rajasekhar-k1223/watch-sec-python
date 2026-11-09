"""
[v3.11.0] Phase 17: Monitorix Global MDR & MSSP API Router
===========================================================
Endpoints:
- GET  /api/v2/mssp/overview
- GET  /api/v2/mssp/partners
- POST /api/v2/mssp/partners
- GET  /api/v2/mssp/partners/{partner_id}
- GET  /api/v2/mssp/partners/{partner_id}/whitelabel
- PUT  /api/v2/mssp/partners/{partner_id}/whitelabel
- GET  /api/v2/mssp/customers
- POST /api/v2/mssp/customers/onboard
- POST /api/v2/mssp/shifts/handover
- POST /api/v2/mssp/escalations
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Body, Header, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

from app.db.session import get_db
from app.db.models import User
from app.api.deps import get_current_user
from app.services.global_mdr_mssp_service import GlobalMdrMsspService

router = APIRouter()

# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class CreatePartnerRequest(BaseModel):
    name: str = Field(..., example="Apex Cyber Defense MSSP")
    primary_domain: str = Field(..., example="apexcyber.com")
    tier: str = Field(default="PLATINUM", example="PLATINUM", description="PLATINUM, GOLD, SILVER, ELITE")
    revenue_share_pct: float = Field(default=25.0, example=25.0)
    billing_plan: str = Field(default="WHOLESALE_AGGREGATED", example="WHOLESALE_AGGREGATED")
    sla_p1_min: int = Field(default=15, example=15)
    sla_p2_min: int = Field(default=30, example=30)
    sla_p3_min: int = Field(default=120, example=120)
    sla_p4_min: int = Field(default=480, example=480)

class UpdateWhiteLabelRequest(BaseModel):
    enabled: Optional[bool] = Field(default=True)
    brand_name: Optional[str] = Field(default=None, example="ApexCyber Managed Defense")
    logo_url: Optional[str] = Field(default=None, example="https://cdn.apexcyber.com/logo.svg")
    favicon_url: Optional[str] = Field(default=None, example="https://cdn.apexcyber.com/favicon.ico")
    custom_domain: Optional[str] = Field(default=None, example="soc.apexcyber.com")
    primary_brand_color: Optional[str] = Field(default=None, example="#0ea5e9")
    accent_brand_color: Optional[str] = Field(default=None, example="#6366f1")
    custom_css: Optional[Dict[str, Any]] = Field(default=None)
    email_header_html: Optional[str] = Field(default=None)
    email_footer_html: Optional[str] = Field(default=None)

class OnboardCustomerRequest(BaseModel):
    partner_id: str = Field(..., example="MSSP-PARTNER-APEX")
    customer_name: str = Field(..., example="Acme Financial Corp")
    industry: str = Field(default="Financial Services", example="Financial Services")
    mdr_tier: str = Field(default="MANAGED_RESPONSE", example="MANAGED_RESPONSE", description="MANAGED_DETECTION, MANAGED_RESPONSE, PREMIUM_HUNTING, ENTERPRISE_SOC")
    endpoints_count: int = Field(default=500, example=500)

class ShiftHandoverRequest(BaseModel):
    from_region: str = Field(..., example="APAC", description="APAC, EMEA, AMER")
    to_region: str = Field(..., example="EMEA", description="EMEA, AMER, APAC")
    outgoing_lead: str = Field(..., example="Kenji Takahashi")
    incoming_lead: str = Field(..., example="Sarah Jenkins")
    active_incidents_count: int = Field(default=3, example=3)
    escalated_p1_count: int = Field(default=1, example=1)
    watch_items: List[str] = Field(default=["Continuous C2 sweeping", "Honeypot canary monitoring"])
    briefing_notes: str = Field(default="All high severity incidents contained.", example="All high severity incidents contained.")
    threat_advisory_brief: str = Field(default="Increased ransomware activity in healthcare.", example="Increased ransomware activity in healthcare.")

class EscalationRequest(BaseModel):
    incident_id: int = Field(..., example=101)
    tenant_id: int = Field(default=1, example=1)
    partner_id: Optional[str] = Field(default=None, example="MSSP-PARTNER-APEX")
    severity: str = Field(default="P1_CRITICAL", example="P1_CRITICAL", description="P1_CRITICAL, P2_HIGH, P3_MEDIUM, P4_LOW")
    escalation_tier: str = Field(default="L2_INVESTIGATION", example="L2_INVESTIGATION", description="L1_TRIAGE, L2_INVESTIGATION, L3_THREAT_HUNTER, PRINCIPAL_COMMANDER")
    originating_region: str = Field(default="APAC", example="APAC")
    target_region: str = Field(default="EMEA", example="EMEA")
    trigger_reason: str = Field(..., example="Reverse shell spawn on domain controller detected by eBPF probe.")

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/overview", summary="Retrieve Global SOC & MSSP operations overview and metrics")
async def get_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await GlobalMdrMsspService.get_global_soc_overview(db)

@router.get("/partners", summary="List all MSSP Partner Organizations")
async def list_partners(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await GlobalMdrMsspService.list_partners(db)

@router.post("/partners", summary="Register a new MSSP Partner Organization")
async def create_partner(
    req: CreatePartnerRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await GlobalMdrMsspService.create_partner(db, req.dict())

@router.get("/partners/{partner_id}", summary="Get detailed MSSP Partner profile & managed tenants")
async def get_partner(
    partner_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await GlobalMdrMsspService.get_partner_details(db, partner_id)

@router.get("/partners/{partner_id}/whitelabel", summary="Get partner white-label branding config")
async def get_white_label(
    partner_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await GlobalMdrMsspService.get_white_label_config(db, partner_id)

@router.put("/partners/{partner_id}/whitelabel", summary="Update partner white-label branding (Sovereign Audit Locked)")
async def update_white_label(
    partner_id: str,
    req: UpdateWhiteLabelRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    payload = {k: v for k, v in req.dict().items() if v is not None}
    return await GlobalMdrMsspService.update_white_label_config(db, partner_id, payload)

@router.get("/customers", summary="List managed customer accounts across MSSP fleet")
async def list_customers(
    partner_id: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await GlobalMdrMsspService.list_customer_accounts(db, partner_id=partner_id)

@router.post("/customers/onboard", summary="Onboard new customer account under MSSP partner")
async def onboard_customer(
    req: OnboardCustomerRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await GlobalMdrMsspService.onboard_customer_account(db, req.dict())

@router.post("/shifts/handover", summary="Record Follow-the-Sun regional SOC shift handover")
async def record_shift_handover(
    req: ShiftHandoverRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await GlobalMdrMsspService.create_shift_handover(db, req.dict())

@router.post("/escalations", summary="Escalate incident across global SOC tiers with SLA tracking")
async def create_escalation(
    req: EscalationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return await GlobalMdrMsspService.create_escalation(db, req.dict())
