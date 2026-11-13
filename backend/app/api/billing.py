from fastapi import APIRouter, Depends, HTTPException, Request, Header # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from pydantic import BaseModel # type: ignore
from typing import Optional, List, Dict, Any # type: ignore
import stripe # type: ignore
import os # type: ignore
import json # type: ignore

from ..db.session import get_db # type: ignore
from ..db.models import Tenant, User # type: ignore
from .deps import get_current_user # type: ignore

router = APIRouter()

# [CONFIG] Stripe Keys
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "sk_test_PLACEHOLDER")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_PLACEHOLDER")
stripe.api_key = STRIPE_SECRET_KEY

# [CONFIG] Price IDs (Replace with your actual Stripe Price IDs)
PLAN_PRICES = {
    "Starter": None, # Free
    "Professional": "price_1PkX...", # Replace with actual price ID
    "Enterprise": "price_1PkY..."    # Replace with actual price ID
}

class PlanDto(BaseModel):
    TenantId: int
    Plan: str
    AgentLimit: int
    NextBillingDate: str
    AmountDue: float
    StripeCustomerId: str | None
    SubscriptionStatus: str

class CheckoutRequest(BaseModel):
    PlanName: str # Starter, Professional, Enterprise

class PlanUpdateRequest(BaseModel):
    PlanName: Optional[str] = None
    plan: Optional[str] = None
    plan_name: Optional[str] = None
    tenant_id: Optional[int] = None

    def get_plan(self) -> str:
        return self.PlanName or self.plan or self.plan_name or "Professional"


@router.get("", response_model=PlanDto)
@router.get("/", response_model=PlanDto, include_in_schema=False)
async def get_billing_info(
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    tenant_id = current_user.TenantId or 1
    result = await db.execute(select(Tenant).where(Tenant.Id == tenant_id))
    tenant = result.scalars().first()
    
    if not tenant:
        return PlanDto(
            TenantId=1,
            Plan="Enterprise",
            AgentLimit=500,
            NextBillingDate="2027-01-01T00:00:00",
            AmountDue=299.99,
            StripeCustomerId=None,
            SubscriptionStatus="active"
        )
        
    amounts = {"Starter": 0.0, "Professional": 49.99, "Enterprise": 299.99}
    
    return PlanDto(
        TenantId=tenant.Id,
        Plan=tenant.Plan,
        AgentLimit=tenant.AgentLimit,
        NextBillingDate=tenant.NextBillingDate.isoformat() if tenant.NextBillingDate else "2027-01-01T00:00:00",
        AmountDue=amounts.get(tenant.Plan, 0.0),
        StripeCustomerId=tenant.StripeCustomerId,
        SubscriptionStatus=tenant.SubscriptionStatus or "active"
    )

@router.post("/update-plan")
async def update_plan_direct(
    req: PlanUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Directly update and save subscription plan without requiring external payment gateway.
    """
    if current_user.Role not in ["TenantAdmin", "SuperAdmin"]:
        raise HTTPException(status_code=403, detail="Only Tenant Admins and SuperAdmins can update plans.")

    tenant_id = (req.tenant_id if (current_user.Role == "SuperAdmin" and req.tenant_id) else None) or current_user.TenantId or 1
    result = await db.execute(select(Tenant).where(Tenant.Id == tenant_id))
    tenant = result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    plan_name = req.get_plan()
    tier_limits = {"Starter": 5, "Professional": 50, "Enterprise": 1000, "Sovereign": 5000}
    tenant.Plan = plan_name
    tenant.AgentLimit = tier_limits.get(plan_name, 50)
    tenant.SubscriptionStatus = "active"

    # [SYNC] Automatically cascade plan upgrade features to all tenant agents
    from ..core.constants import FEATURE_TIERS, resolve_plan_level
    new_level = resolve_plan_level(plan_name)
    from ..db.models import Agent
    agents_res = await db.execute(select(Agent).where(Agent.TenantId == tenant.Id))
    for ag in agents_res.scalars().all():
        ag.ActivityMonitorEnabled = True
        ag.InputAuditEnabled = (new_level >= FEATURE_TIERS.get("KeyloggerEnabled", 2))
        ag.ClipboardAuditEnabled = (new_level >= FEATURE_TIERS.get("ClipboardMonitorEnabled", 2))
        ag.AppEnforcementEnabled = (new_level >= FEATURE_TIERS.get("AppBlockerEnabled", 2))
        ag.BrowserComplianceEnabled = (new_level >= FEATURE_TIERS.get("BrowserEnforcerEnabled", 1))
        ag.PrintAuditEnabled = (new_level >= FEATURE_TIERS.get("PrinterMonitorEnabled", 2))
        ag.ShadowAuditEnabled = (new_level >= FEATURE_TIERS.get("ShadowMonitorEnabled", 3))
        ag.SessionForensicEnabled = (new_level >= FEATURE_TIERS.get("LiveStreamEnabled", 3))
        ag.RemoteRemediationEnabled = (new_level >= FEATURE_TIERS.get("RemoteShellEnabled", 3))
        ag.MailIntelligenceEnabled = (new_level >= FEATURE_TIERS.get("MailMonitorEnabled", 3))
        ag.VoiceIntelligenceEnabled = (new_level >= FEATURE_TIERS.get("SpeechMonitorEnabled", 3))
        ag.VulnerabilityIntelligenceEnabled = (new_level >= FEATURE_TIERS.get("VulnerabilityIntelligenceEnabled", 3))
        ag.VisualActivityEnabled = (new_level >= FEATURE_TIERS.get("ScreenshotsEnabled", 1))
        ag.LocationAuditEnabled = (new_level >= FEATURE_TIERS.get("LocationTrackingEnabled", 2))
        ag.UsbComplianceEnabled = (new_level >= FEATURE_TIERS.get("UsbBlockingEnabled", 2))
        ag.NetworkAuditEnabled = (new_level >= FEATURE_TIERS.get("NetworkMonitoringEnabled", 3))
        ag.DataLossPreventionEnabled = (new_level >= FEATURE_TIERS.get("FileDlpEnabled", 3))

    # Audit log
    from datetime import datetime
    from ..db.models import AuditLog
    audit = AuditLog(
        TenantId=tenant.Id,
        Actor=current_user.Username,
        Action="PlanUpdate",
        Target=f"Tenant #{tenant.Id}",
        Details=f"Direct plan switch to {plan_name} (Agent Limit: {tenant.AgentLimit})",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    await db.commit()
    await db.refresh(tenant)

    amounts = {"Starter": 0.0, "Professional": 49.99, "Enterprise": 299.99}
    return PlanDto(
        TenantId=tenant.Id,
        Plan=tenant.Plan,
        AgentLimit=tenant.AgentLimit,
        NextBillingDate=tenant.NextBillingDate.isoformat() if tenant.NextBillingDate else "2027-01-01T00:00:00",
        AmountDue=amounts.get(tenant.Plan, 0.0),
        StripeCustomerId=tenant.StripeCustomerId,
        SubscriptionStatus=tenant.SubscriptionStatus or "active"
    )

@router.post("/create-checkout-session")
async def create_checkout_session(
    req: CheckoutRequest,
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    """
    Creates a Stripe Checkout Session for subscription upgrade.
    """
    if current_user.Role not in ["TenantAdmin", "SuperAdmin"]:
        raise HTTPException(status_code=403, detail="Only Tenant Admins and SuperAdmins can upgrade.")

    tenant_id = current_user.TenantId or 1
    result = await db.execute(select(Tenant).where(Tenant.Id == tenant_id))
    tenant = result.scalars().first()

    # Graceful mock handling if running in local/test environment without live Stripe keys
    if STRIPE_SECRET_KEY == "sk_test_PLACEHOLDER" or not STRIPE_SECRET_KEY:
        if tenant:
            tier_limits = {"Starter": 5, "Professional": 50, "Enterprise": 1000}
            tenant.Plan = req.PlanName
            tenant.AgentLimit = tier_limits.get(req.PlanName, 50)
            await db.commit()
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173")
        return {"checkoutUrl": f"{frontend_url}/billing?success=true&plan={req.PlanName}&mock=true"}

    price_id = PLAN_PRICES.get(req.PlanName)
    if not price_id and req.PlanName != "Starter":
        # Check if using Env vars for dynamic price IDs
        price_id = os.getenv(f"STRIPE_PRICE_{req.PlanName.upper()}")
    
    if not price_id:
        raise HTTPException(status_code=400, detail=f"Invalid Plan or Price ID missing for {req.PlanName}")

    try:
        # Create or Get Customer
        customer_id = tenant.StripeCustomerId if tenant else None
        if not customer_id and tenant:
            customer = stripe.Customer.create(
                email=current_user.Username, # Assuming username is email, or fetch email
                metadata={"tenant_id": str(tenant.Id)}
            )
            customer_id = customer.id
            tenant.StripeCustomerId = customer_id
            await db.commit()

        # Create Session
        checkout_session = stripe.checkout.Session.create(
            customer=customer_id,
            line_items=[
                {
                    'price': price_id,
                    'quantity': 1,
                },
            ],
            mode='subscription',
            success_url=os.getenv("FRONTEND_URL", "http://localhost:5173") + "/billing?success=true",
            cancel_url=os.getenv("FRONTEND_URL", "http://localhost:5173") + "/billing?canceled=true",
            metadata={"tenant_id": str(tenant.Id if tenant else 1), "new_plan": req.PlanName}
        )
        return {"checkoutUrl": checkout_session.url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/create-portal-session")
async def create_portal_session(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Redirects to Stripe Customer Portal for managing existing subscriptions.
    """
    tenant_id = current_user.TenantId or 1
    result = await db.execute(select(Tenant).where(Tenant.Id == tenant_id))
    tenant = result.scalars().first()

    if STRIPE_SECRET_KEY == "sk_test_PLACEHOLDER" or not STRIPE_SECRET_KEY:
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173")
        return {"portalUrl": f"{frontend_url}/billing?portal=mock"}

    if not tenant or not tenant.StripeCustomerId:
        raise HTTPException(status_code=400, detail="No active billing account.")

    try:
        portal_session = stripe.billing_portal.Session.create(
            customer=tenant.StripeCustomerId,
            return_url=os.getenv("FRONTEND_URL", "http://localhost:5173") + "/billing"
        )
        return {"portalUrl": portal_session.url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/webhook")
async def stripe_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    """
    Handles async events from Stripe (Payment Succeeded, Subscription Updated)
    """
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError as e:
        raise HTTPException(status_code=400, detail="Invalid signature")

    # Handle the event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        tenant_id =  session.get('metadata', {}).get('tenant_id')
        new_plan = session.get('metadata', {}).get('new_plan')
        
        if tenant_id and new_plan:
             # Fulfill the purchase...
             result = await db.execute(select(Tenant).where(Tenant.Id == int(tenant_id)))
             tenant = result.scalars().first()
             if tenant:
                 tenant.Plan = new_plan
                 # Update Agent Limit based on plan
                 limits = {"Professional": 50, "Enterprise": 1000}
                 tenant.AgentLimit = limits.get(new_plan, 5)
                 tenant.SubscriptionStatus = "active"
                 await db.commit()

    elif event['type'] == 'customer.subscription.updated':
        subscription = event['data']['object']
        status = subscription['status']
        # Find tenant by customer ID? Or store sub ID?
        # Ideally we search by StripeCustomerId
        customer_id = subscription['customer']
        result = await db.execute(select(Tenant).where(Tenant.StripeCustomerId == customer_id))
        tenant = result.scalars().first()
        if tenant:
            tenant.SubscriptionStatus = status
            if status in ['past_due', 'canceled', 'unpaid']:
                # Maybe downgrade logic here or strict enforcement
                pass
            await db.commit()

    return {"status": "success"}
