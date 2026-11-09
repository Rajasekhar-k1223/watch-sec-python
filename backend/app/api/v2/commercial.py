"""
[v3.6.0] Phase 12: Monitorix Commercialization & Managed Security API Router
============================================================================
Provides endpoints for:
- 12.1 Commercial Plans & Entitlements
- 12.2 Licensing Engine (Online, Offline Air-Gapped, Validation)
- 12.3 Billing Integration & Invoices (Stripe, Paddle, Mock)
- 12.4 Customer Lifecycle Transitions
- 12.5 Customer Success Telemetry Hub (/#/customer-success)
- 12.6 & 12.7 24/7 MDR Operations & Service Packages (/#/mdr)
- 12.8 Automated Customer Reports (Daily, Weekly, Monthly, Executive, Risk, Compliance)
- 12.9 SLA Engine & Breach Audit
- 12.10 Commercial Analytics Hub (/#/business/analytics)
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Body, Header, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import json

from app.db.session import get_db
from app.db.models import User
from app.api.deps import get_current_user
from app.services.commercial_service import commercial_service, MDR_SERVICE_PACKAGES

router = APIRouter()

# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class IssueLicenseRequest(BaseModel):
    plan_tier: str = Field(default="Enterprise", example="Enterprise")
    license_type: str = Field(default="Online", example="Online") # Online, Offline, Enterprise
    validity_days: int = Field(default=365, example=365)

class VerifyEntitlementRequest(BaseModel):
    feature: str = Field(..., example="endpoints")
    current_count: int = Field(default=1, example=500)

class CheckoutRequest(BaseModel):
    plan_tier: str = Field(..., example="Enterprise")
    billing_cycle: str = Field(default="annual", example="annual") # annual, monthly
    provider: str = Field(default="Stripe", example="Stripe") # Stripe, Paddle, Mock

class RecordInvoiceRequest(BaseModel):
    amount_usd: float = Field(..., example=36000.0)
    provider: str = Field(default="Stripe", example="Stripe")
    description: str = Field(default="Monitorix Security Platform Subscription", example="Enterprise Subscription")

class TransitionStageRequest(BaseModel):
    target_stage: str = Field(..., example="Active") # Lead, Trial, Onboarding, Active, Expansion, Renewal, Cancellation
    notes: Optional[str] = None

class CreateMdrTicketRequest(BaseModel):
    title: str = Field(..., example="Cobalt Strike Beacon Discovered on Accounting Host")
    severity: str = Field(default="High", example="Critical")
    mdr_package: str = Field(default="Managed Response", example="Managed Response")
    incident_id: Optional[int] = None
    assigned_analyst: str = Field(default="tier2_specialist", example="tier2_specialist")
    shift: str = Field(default="Day", example="Day")
    queue: str = Field(default="Tier 2 Specialist", example="Tier 2 Specialist")
    customer_notes: Optional[str] = None

class UpdateMdrTicketRequest(BaseModel):
    status: str = Field(..., example="Resolved")
    assigned_analyst: Optional[str] = None
    queue: Optional[str] = None
    customer_notes: Optional[str] = None
    resolution_summary: Optional[str] = None

# ---------------------------------------------------------------------------
# 12.1 Commercial Plans
# ---------------------------------------------------------------------------

@router.get("/plans")
async def list_plans(current_user: User = Depends(get_current_user)):
    """Returns all 6 commercial plan tiers and their entitlement matrices."""
    return {
        "status": "success",
        "total_plans": 6,
        "plans": commercial_service.list_commercial_plans()
    }

# ---------------------------------------------------------------------------
# 12.2 Licensing Engine
# ---------------------------------------------------------------------------

@router.get("/license")
async def get_tenant_license(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieves live commercial license and entitlement status for the tenant."""
    tenant_id = getattr(current_user, "TenantId", None) or 1
    lic_info = await commercial_service.validate_commercial_license(db, tenant_id)
    return {
        "status": "success",
        "tenant_id": tenant_id,
        "license": lic_info
    }

@router.post("/license/issue", status_code=status.HTTP_201_CREATED)
async def issue_license(
    req: IssueLicenseRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Issues or upgrades a cryptographically signed commercial or offline license."""
    tenant_id = getattr(current_user, "TenantId", None) or 1
    actor = getattr(current_user, "Username", "admin")
    lic = await commercial_service.issue_commercial_license(
        db=db,
        tenant_id=tenant_id,
        plan_tier=req.plan_tier,
        license_type=req.license_type,
        validity_days=req.validity_days,
        actor=actor
    )
    return {"status": "success", "license": lic}

@router.post("/license/entitlements/verify")
async def verify_entitlement(
    req: VerifyEntitlementRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Verifies whether the current usage conforms to the tenant's license limits."""
    tenant_id = getattr(current_user, "TenantId", None) or 1
    result = await commercial_service.verify_entitlement(
        db=db,
        tenant_id=tenant_id,
        feature=req.feature,
        current_metric=req.current_count
    )
    return result

# ---------------------------------------------------------------------------
# 12.3 Billing Integration (Provider Abstraction)
# ---------------------------------------------------------------------------

@router.post("/billing/checkout")
async def create_checkout(
    req: CheckoutRequest,
    current_user: User = Depends(get_current_user)
):
    """Generates an abstracted checkout session without handling raw card credentials."""
    tenant_id = getattr(current_user, "TenantId", None) or 1
    session = await commercial_service.create_checkout(
        tenant_id=tenant_id,
        plan_tier=req.plan_tier,
        billing_cycle=req.billing_cycle,
        provider_name=req.provider
    )
    return {"status": "success", "checkout_session": session}

@router.get("/billing/invoices")
async def list_invoices(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Lists historical invoices and payment statuses."""
    tenant_id = getattr(current_user, "TenantId", None) or 1
    invoices = await commercial_service.list_tenant_invoices(db, tenant_id)
    return {"status": "success", "total_invoices": len(invoices), "invoices": invoices}

@router.post("/billing/invoices", status_code=status.HTTP_201_CREATED)
async def create_invoice(
    req: RecordInvoiceRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Records an invoice transaction from the abstracted billing provider."""
    tenant_id = getattr(current_user, "TenantId", None) or 1
    inv = await commercial_service.record_invoice(
        db=db,
        tenant_id=tenant_id,
        amount_usd=req.amount_usd,
        provider_name=req.provider,
        description=req.description
    )
    return {"status": "success", "invoice": inv}

# ---------------------------------------------------------------------------
# 12.4 Customer Lifecycle & 12.5 Customer Success
# ---------------------------------------------------------------------------

@router.get("/customer-success")
async def get_customer_success(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieves composite customer success telemetry for /#/customer-success."""
    tenant_id = getattr(current_user, "TenantId", None) or 1
    hub = await commercial_service.get_customer_success_hub(db, tenant_id)
    return {"status": "success", "customer_success": hub}

@router.post("/customer-lifecycle/transition")
async def transition_customer_stage(
    req: TransitionStageRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Updates customer lifecycle stage (Lead -> Trial -> Onboarding -> Active -> Expansion -> Renewal -> Cancellation)."""
    tenant_id = getattr(current_user, "TenantId", None) or 1
    actor = getattr(current_user, "Username", "admin")
    try:
        res = await commercial_service.transition_customer_stage(
            db=db,
            tenant_id=tenant_id,
            target_stage=req.target_stage,
            actor=actor,
            notes=req.notes
        )
        return {"status": "success", "transition": res}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

# ---------------------------------------------------------------------------
# 12.6 & 12.7 MDR Operations & Packages
# ---------------------------------------------------------------------------

@router.get("/mdr/packages")
async def list_mdr_packages(current_user: User = Depends(get_current_user)):
    """Returns the 5 core MDR service packages."""
    return {
        "status": "success",
        "service_packages": MDR_SERVICE_PACKAGES
    }

@router.get("/mdr/tickets")
async def list_mdr_tickets(
    queue: Optional[str] = Query(None),
    shift: Optional[str] = Query(None),
    ticket_status: Optional[str] = Query(None, alias="status"),
    package: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Lists 24/7 MDR ticket assignments, queues, and active SLA clocks."""
    tenant_id = getattr(current_user, "TenantId", None) or 1
    tickets = await commercial_service.list_mdr_tickets(
        db=db,
        tenant_id=tenant_id,
        queue=queue,
        shift=shift,
        status=ticket_status,
        package=package
    )
    return {
        "status": "success",
        "total_tickets": len(tickets),
        "tickets": tickets
    }

@router.post("/mdr/tickets", status_code=status.HTTP_201_CREATED)
async def create_mdr_ticket(
    req: CreateMdrTicketRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    tenant_id = getattr(current_user, "TenantId", None) or 1
    ticket = await commercial_service.create_mdr_ticket(
        db=db,
        tenant_id=tenant_id,
        title=req.title,
        severity=req.severity,
        mdr_package=req.mdr_package,
        incident_id=req.incident_id,
        assigned_analyst=req.assigned_analyst,
        shift=req.shift,
        queue=req.queue,
        customer_notes=req.customer_notes
    )
    return {"status": "success", "ticket": ticket}

@router.post("/mdr/tickets/{ticket_id}/status")
async def update_mdr_ticket(
    ticket_id: int,
    req: UpdateMdrTicketRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    tenant_id = getattr(current_user, "TenantId", None) or 1
    try:
        updated = await commercial_service.update_mdr_ticket_status(
            db=db,
            tenant_id=tenant_id,
            ticket_id=ticket_id,
            status=req.status,
            analyst=req.assigned_analyst,
            queue=req.queue,
            notes=req.customer_notes,
            resolution_summary=req.resolution_summary
        )
        return {"status": "success", "ticket": updated}
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))

# ---------------------------------------------------------------------------
# 12.8 Automated Customer Reporting
# ---------------------------------------------------------------------------

@router.get("/reports/generate")
async def generate_customer_report(
    report_type: str = Query("Executive", example="Executive"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generates automated reports (Daily, Weekly, Monthly, Executive, Incident, Risk, Compliance)."""
    tenant_id = getattr(current_user, "TenantId", None) or 1
    rep = await commercial_service.generate_customer_report(db, tenant_id, report_type)
    return {"status": "success", "report": rep}

# ---------------------------------------------------------------------------
# 12.9 SLA Engine
# ---------------------------------------------------------------------------

@router.get("/sla")
async def get_sla_metrics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Returns SLA compliance rates, targets, and breach audits."""
    tenant_id = getattr(current_user, "TenantId", None) or 1
    sla = await commercial_service.get_tenant_sla_metrics(db, tenant_id)
    return {"status": "success", "sla": sla}

# ---------------------------------------------------------------------------
# 12.10 Commercial Analytics
# ---------------------------------------------------------------------------

@router.get("/analytics")
async def get_commercial_analytics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Returns global commercial ARR, MRR, endpoints, churn, and plan distribution."""
    metrics = await commercial_service.get_commercial_analytics(db)
    return {"status": "success", "analytics": metrics}
