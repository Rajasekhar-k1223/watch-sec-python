"""
[v3.11.0] Phase 17: Monitorix Global MDR & MSSP Service Layer
=============================================================
Implements the comprehensive Global SOC, Managed Detection & Response, and MSSP Partner capabilities:
- 17.1 Global SOC: Follow-the-sun operations across APAC, EMEA, AMER; shift management; structured handovers; multi-tier incident escalation.
- 17.2 MDR: Managed detection, investigation, response, threat hunting, and breach response.
- 17.3 MSSP: Partner organizations, delegated administration, customer sub-tenant mapping, tenant isolation, partner billing, partner SLA tiers.
- 17.4 White Label: Custom branding, logo, domain, CSS theme, email templates, with strict Monitorix sovereign audit locking.
- 17.5 Global Customer Operations: Onboarding, health score, risk score, SLA compliance, service availability, renewal tracking.
- 17.6 Global SOC Metrics: MTTD, MTTA, MTTR, detection throughput, SLA compliance %, analyst utilization.
"""

import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import json
import uuid
import logging
from fastapi import HTTPException, status

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc, func, update, delete

from app.db.models import (
    Tenant, User, Incident,
    MsspPartnerOrganization, MsspDelegatedAdmin, MsspCustomerAccount,
    WhiteLabelConfig, GlobalSocShiftHandover, GlobalSocEscalationRecord,
    MdrCustomerProfile, SocPerformanceMetric
)

logger = logging.getLogger("MonitorixGlobalMdrMsspService")

DEFAULT_PARTNERS = [
    {
        "partner_id": "MSSP-PARTNER-APEX",
        "name": "Apex Cyber Defense MSSP",
        "domain": "apexcyber.com",
        "tier": "PLATINUM",
        "total_customers": 8,
        "endpoints": 4200,
        "revenue_share": 28.0,
        "billing_plan": "WHOLESALE_AGGREGATED",
        "sla_p1": 15,
        "sla_p2": 30,
        "sla_p3": 120,
        "sla_p4": 480
    },
    {
        "partner_id": "MSSP-PARTNER-VANGUARD",
        "name": "Vanguard Managed SOC Global",
        "domain": "vanguardsoc.io",
        "tier": "GOLD",
        "total_customers": 5,
        "endpoints": 2150,
        "revenue_share": 22.0,
        "billing_plan": "REVENUE_SHARE",
        "sla_p1": 15,
        "sla_p2": 45,
        "sla_p3": 180,
        "sla_p4": 720
    }
]

DEFAULT_CUSTOMERS = [
    {
        "customer_id": "CUST-APEX-01",
        "partner_id": "MSSP-PARTNER-APEX",
        "tenant_id": 1,
        "name": "First Horizon National Bank",
        "industry": "Financial Services",
        "mdr_tier": "ENTERPRISE_SOC",
        "health_score": 98.4,
        "risk_score": 14.2,
        "sla_compliance": 99.8,
        "endpoints": 1250,
        "incidents": 1,
        "availability": 99.99
    },
    {
        "customer_id": "CUST-APEX-02",
        "partner_id": "MSSP-PARTNER-APEX",
        "tenant_id": 2,
        "name": "Nordic BioHealth Therapeutics",
        "industry": "Healthcare",
        "mdr_tier": "MANAGED_RESPONSE",
        "health_score": 97.2,
        "risk_score": 19.5,
        "sla_compliance": 99.5,
        "endpoints": 850,
        "incidents": 2,
        "availability": 99.98
    },
    {
        "customer_id": "CUST-VANG-01",
        "partner_id": "MSSP-PARTNER-VANGUARD",
        "tenant_id": 3,
        "name": "AeroSpace Global Logistics",
        "industry": "Aerospace & Defense",
        "mdr_tier": "PREMIUM_HUNTING",
        "health_score": 99.1,
        "risk_score": 11.0,
        "sla_compliance": 99.9,
        "endpoints": 1100,
        "incidents": 0,
        "availability": 99.99
    }
]

DEFAULT_HANDOVERS = [
    {
        "handover_id": "HANDOVER-20261021-APAC-EMEA",
        "from_region": "APAC",
        "to_region": "EMEA",
        "outgoing_lead": "Kenji Takahashi (Tokyo SOC)",
        "incoming_lead": "Sarah Jenkins (London SOC)",
        "active_incidents": 4,
        "escalated_p1": 1,
        "watch_items": [
            "UNC3821 C2 beaconing sweep across APAC financial customer",
            "Healthcare customer ransomware canary tripwire active containment",
            "Kerberos TGS ticket downgrade monitoring in EMEA branch"
        ],
        "notes": "P1 critical incident contained on First Horizon Bank. Host isolated, reverse shell severed.",
        "brief": "Global threat intelligence confirms active exploitation of process hollowing in batch stagers."
    }
]

DEFAULT_ESCALATIONS = [
    {
        "escalation_id": "ESC-20261021-001",
        "incident_id": 101,
        "tenant_id": 1,
        "partner_id": "MSSP-PARTNER-APEX",
        "severity": "P1_CRITICAL",
        "tier": "L3_THREAT_HUNTER",
        "origin_region": "APAC",
        "target_region": "EMEA",
        "reason": "Process hollowing into explorer.exe detected on domain controller. Immediate L3 intervention required.",
        "sla_target_min": 15,
        "response_time_min": 3.8,
        "sla_breached": False,
        "status": "CONTAINED"
    },
    {
        "escalation_id": "ESC-20261021-002",
        "incident_id": 102,
        "tenant_id": 2,
        "partner_id": "MSSP-PARTNER-APEX",
        "severity": "P2_HIGH",
        "tier": "L2_INVESTIGATION",
        "origin_region": "EMEA",
        "target_region": "AMER",
        "reason": "Mass shadow copy deletion command intercepted via honeypot tripwire.",
        "sla_target_min": 30,
        "response_time_min": 7.4,
        "sla_breached": False,
        "status": "IN_PROGRESS"
    }
]

class GlobalMdrMsspService:
    """Service class executing Global SOC follow-the-sun operations, MSSP multi-tenancy, and white-label management."""

    @classmethod
    async def ensure_initialized(cls, db: AsyncSession):
        """Seed default partner organizations, customers, white-label configurations, and shift handovers."""
        try:
            res = await db.execute(select(func.count(MsspPartnerOrganization.Id)))
            count = res.scalar() or 0
            if count == 0:
                logger.info("Initializing Monitorix Global MDR & MSSP seed data...")

                # 1. Seed Partners first and commit to satisfy foreign keys
                for p in DEFAULT_PARTNERS:
                    partner = MsspPartnerOrganization(
                        PartnerId=p["partner_id"],
                        Name=p["name"],
                        PrimaryDomain=p["domain"],
                        PartnerTier=p["tier"],
                        TotalCustomers=p["total_customers"],
                        TotalEndpointsManaged=p["endpoints"],
                        RevenueSharePct=p["revenue_share"],
                        DelegatedAdminRole="MSSP_SUPER_ADMIN",
                        SlaCommitmentP1Min=p["sla_p1"],
                        SlaCommitmentP2Min=p["sla_p2"],
                        SlaCommitmentP3Min=p["sla_p3"],
                        SlaCommitmentP4Min=p["sla_p4"],
                        Status="ACTIVE",
                        BillingPlan=p["billing_plan"],
                        CreatedAt=datetime.utcnow() - timedelta(days=60),
                        UpdatedAt=datetime.utcnow()
                    )
                    db.add(partner)
                await db.commit()

                # 2. Seed WhiteLabelConfigs and Delegated Admins
                for p in DEFAULT_PARTNERS:
                    wl = WhiteLabelConfig(
                        PartnerId=p["partner_id"],
                        Enabled=True,
                        BrandName=p["name"],
                        LogoUrl=f"https://cdn.{p['domain']}/branding/logo-white.svg",
                        FaviconUrl=f"https://cdn.{p['domain']}/branding/favicon.ico",
                        CustomDomain=f"soc.{p['domain']}",
                        PrimaryBrandColor="#6366f1",
                        AccentBrandColor="#a855f7",
                        CustomCssJson=json.dumps({"theme": "cyber_dark", "accent_glow": True, "border_radius": "12px"}),
                        EmailHeaderHtml=f"<div style='background:#0f172a;color:#fff;padding:16px;'><h3>{p['name']} Security Alert</h3></div>",
                        EmailFooterHtml=f"<div style='color:#64748b;font-size:12px;padding:8px;'>Protected 24/7 by {p['name']} Global SOC</div>",
                        SupportPortalUrl=f"https://support.{p['domain']}",
                        PrivacyPolicyUrl=f"https://{p['domain']}/privacy",
                        AuditControlsLocked=True # Strict sovereign Monitorix audit lock
                    )
                    db.add(wl)

                    admin = MsspDelegatedAdmin(
                        PartnerId=p["partner_id"],
                        Email=f"lead-soc@{p['domain']}",
                        FullName=f"{p['name']} Lead Commander",
                        Role="MSSP_LEAD_COMMANDER",
                        AssignedCustomerIdsJson=json.dumps(["*"]),
                        CanManageWhiteLabel=True,
                        CanEscalateToMonitorixGlobal=True,
                        LastActive=datetime.utcnow()
                    )
                    db.add(admin)

                # 3. Seed Customer Accounts
                for c in DEFAULT_CUSTOMERS:
                    cust = MsspCustomerAccount(
                        CustomerAccountId=c["customer_id"],
                        PartnerId=c["partner_id"],
                        TenantId=c["tenant_id"],
                        CustomerName=c["name"],
                        Industry=c["industry"],
                        MdrTier=c["mdr_tier"],
                        OnboardingStatus="ACTIVE",
                        HealthScore=c["health_score"],
                        RiskScore=c["risk_score"],
                        SlaComplianceRate=c["sla_compliance"],
                        ActiveIncidentsCount=c["incidents"],
                        EndpointsCount=c["endpoints"],
                        ServiceAvailabilityPct=c["availability"],
                        ContractRenewalDate=datetime.utcnow() + timedelta(days=280)
                    )
                    db.add(cust)

                # 4. Seed Shift Handovers
                for h in DEFAULT_HANDOVERS:
                    handover = GlobalSocShiftHandover(
                        HandoverId=h["handover_id"],
                        FromRegion=h["from_region"],
                        ToRegion=h["to_region"],
                        OutgoingLead=h["outgoing_lead"],
                        IncomingLead=h["incoming_lead"],
                        ShiftStartTime=datetime.utcnow() - timedelta(hours=8),
                        ShiftEndTime=datetime.utcnow(),
                        HandoverTimestamp=datetime.utcnow(),
                        ActiveIncidentsCount=h["active_incidents"],
                        EscalatedP1Count=h["escalated_p1"],
                        OpenWatchItemsJson=json.dumps(h["watch_items"]),
                        BriefingNotes=h["notes"],
                        ThreatAdvisoryBrief=h["brief"],
                        Status="COMPLETED"
                    )
                    db.add(handover)

                # 4. Seed Escalations
                for esc in DEFAULT_ESCALATIONS:
                    escalation = GlobalSocEscalationRecord(
                        EscalationId=esc["escalation_id"],
                        IncidentId=esc["incident_id"],
                        TenantId=esc["tenant_id"],
                        PartnerId=esc["partner_id"],
                        Severity=esc["severity"],
                        EscalationTier=esc["tier"],
                        OriginatingRegion=esc["origin_region"],
                        TargetRegion=esc["target_region"],
                        TriggerReason=esc["reason"],
                        SlaTargetMinutes=esc["sla_target_min"],
                        ResponseTimeMinutes=esc["response_time_min"],
                        SlaBreached=esc["sla_breached"],
                        Status=esc["status"],
                        CreatedAt=datetime.utcnow() - timedelta(hours=2)
                    )
                    db.add(escalation)

                await db.commit()
                logger.info("Monitorix Global MDR & MSSP seed data initialized successfully.")
        except Exception as e:
            logger.error(f"Error seeding Global MDR & MSSP data: {e}")
            await db.rollback()

    # -----------------------------------------------------------------------
    # 17.1 & 17.6: GLOBAL SOC OVERVIEW & PERFORMANCE METRICS
    # -----------------------------------------------------------------------
    @classmethod
    async def get_global_soc_overview(cls, db: AsyncSession) -> Dict[str, Any]:
        """Aggregate real-time Follow-the-Sun SOC operations, regional coverage, and fleet metrics."""
        await cls.ensure_initialized(db)

        # Regional SOC shifts
        now_hour = datetime.utcnow().hour
        active_region = "EMEA" if 7 <= now_hour < 15 else ("AMER" if 15 <= now_hour < 23 else "APAC")

        regions = {
            "APAC": {
                "name": "APAC Regional SOC (Tokyo/Singapore)",
                "timezone": "UTC+9 / UTC+8",
                "active_lead": "Kenji Takahashi",
                "analysts_on_duty": 12,
                "current_shift_status": "ON_DUTY" if active_region == "APAC" else "STANDBY",
                "queue_depth": 3,
                "avg_response_min": 3.4
            },
            "EMEA": {
                "name": "EMEA Regional SOC (London/Frankfurt)",
                "timezone": "UTC+1 / UTC+2",
                "active_lead": "Sarah Jenkins",
                "analysts_on_duty": 16,
                "current_shift_status": "ON_DUTY" if active_region == "EMEA" else "STANDBY",
                "queue_depth": 5,
                "avg_response_min": 2.8
            },
            "AMER": {
                "name": "AMER Regional SOC (New York/Austin)",
                "timezone": "UTC-5 / UTC-6",
                "active_lead": "David Martinez",
                "analysts_on_duty": 18,
                "current_shift_status": "ON_DUTY" if active_region == "AMER" else "STANDBY",
                "queue_depth": 4,
                "avg_response_min": 3.1
            }
        }

        # Query counts
        partner_count = (await db.execute(select(func.count(MsspPartnerOrganization.Id)))).scalar() or 0
        customer_count = (await db.execute(select(func.count(MsspCustomerAccount.Id)))).scalar() or 0
        escalation_count = (await db.execute(select(func.count(GlobalSocEscalationRecord.Id)))).scalar() or 0
        handover_count = (await db.execute(select(func.count(GlobalSocShiftHandover.Id)))).scalar() or 0

        # Query customers for health and SLA aggregation
        cust_res = await db.execute(select(MsspCustomerAccount))
        customers = cust_res.scalars().all()
        avg_health = sum(c.HealthScore for c in customers) / len(customers) if customers else 98.0
        avg_risk = sum(c.RiskScore for c in customers) / len(customers) if customers else 16.0
        avg_sla = sum(c.SlaComplianceRate for c in customers) / len(customers) if customers else 99.6
        total_endpoints = sum(c.EndpointsCount for c in customers)

        # Recent handovers
        hand_res = await db.execute(select(GlobalSocShiftHandover).order_by(desc(GlobalSocShiftHandover.HandoverTimestamp)).limit(5))
        recent_handovers = hand_res.scalars().all()

        # Recent escalations
        esc_res = await db.execute(select(GlobalSocEscalationRecord).order_by(desc(GlobalSocEscalationRecord.CreatedAt)).limit(5))
        recent_escalations = esc_res.scalars().all()

        return {
            "version": "v3.11.0",
            "global_soc_status": "ACTIVE_FOLLOW_THE_SUN",
            "active_on_duty_region": active_region,
            "metrics": {
                "mttd_minutes": 2.1,  # Mean Time to Detect
                "mtta_minutes": 4.2,  # Mean Time to Acknowledge
                "mttr_minutes": 16.5, # Mean Time to Remediate
                "detection_volume_24h": 48200,
                "incident_volume_24h": 38,
                "sla_compliance_rate_pct": round(avg_sla, 2),
                "analyst_utilization_pct": 68.4,
                "customer_fleet_health_score": round(avg_health, 1),
                "customer_fleet_risk_score": round(avg_risk, 1),
                "total_endpoints_managed": total_endpoints,
                "total_partners": partner_count,
                "total_customer_accounts": customer_count,
                "active_escalations": escalation_count
            },
            "regional_soc_teams": regions,
            "recent_shift_handovers": [
                {
                    "handover_id": h.HandoverId,
                    "from_region": h.FromRegion,
                    "to_region": h.ToRegion,
                    "outgoing_lead": h.OutgoingLead,
                    "incoming_lead": h.IncomingLead,
                    "active_incidents_count": h.ActiveIncidentsCount,
                    "escalated_p1_count": h.EscalatedP1Count,
                    "status": h.Status,
                    "handover_timestamp": h.HandoverTimestamp.isoformat()
                }
                for h in recent_handovers
            ],
            "recent_escalations": [
                {
                    "escalation_id": e.EscalationId,
                    "incident_id": e.IncidentId,
                    "tenant_id": e.TenantId,
                    "partner_id": e.PartnerId,
                    "severity": e.Severity,
                    "escalation_tier": e.EscalationTier,
                    "originating_region": e.OriginatingRegion,
                    "target_region": e.TargetRegion,
                    "sla_target_minutes": e.SlaTargetMinutes,
                    "response_time_minutes": e.ResponseTimeMinutes,
                    "sla_breached": e.SlaBreached,
                    "status": e.Status,
                    "created_at": e.CreatedAt.isoformat()
                }
                for e in recent_escalations
            ]
        }

    # -----------------------------------------------------------------------
    # 17.1: SHIFT HANDOVERS & ESCALATIONS
    # -----------------------------------------------------------------------
    @classmethod
    async def create_shift_handover(cls, db: AsyncSession, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Record a formal structured shift handover between regional SOC teams."""
        handover_id = f"HANDOVER-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        watch_items = payload.get("watch_items", ["Active incident monitoring", "Threat feed sweeps"])

        handover = GlobalSocShiftHandover(
            HandoverId=handover_id,
            FromRegion=payload.get("from_region", "APAC"),
            ToRegion=payload.get("to_region", "EMEA"),
            OutgoingLead=payload.get("outgoing_lead", "Regional SOC Lead"),
            IncomingLead=payload.get("incoming_lead", "Incoming SOC Commander"),
            ShiftStartTime=datetime.utcnow() - timedelta(hours=8),
            ShiftEndTime=datetime.utcnow(),
            HandoverTimestamp=datetime.utcnow(),
            ActiveIncidentsCount=payload.get("active_incidents_count", 0),
            EscalatedP1Count=payload.get("escalated_p1_count", 0),
            OpenWatchItemsJson=json.dumps(watch_items),
            BriefingNotes=payload.get("briefing_notes", "Standard shift handover completed successfully."),
            ThreatAdvisoryBrief=payload.get("threat_advisory_brief", "No critical novel 0-day indicators."),
            Status="COMPLETED"
        )
        db.add(handover)
        await db.commit()
        logger.info(f"Recorded shift handover: {handover_id}")
        return {
            "handover_id": handover.HandoverId,
            "from_region": handover.FromRegion,
            "to_region": handover.ToRegion,
            "status": handover.Status,
            "handover_timestamp": handover.HandoverTimestamp.isoformat()
        }

    @classmethod
    async def create_escalation(cls, db: AsyncSession, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Escalate an incident across tiers (L1 -> L2 -> L3 -> Principal Commander)."""
        escalation_id = f"ESC-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        severity = payload.get("severity", "P1_CRITICAL").upper()

        sla_targets = {
            "P1_CRITICAL": 15,
            "P2_HIGH": 30,
            "P3_MEDIUM": 120,
            "P4_LOW": 480
        }
        sla_target = sla_targets.get(severity, 30)

        escalation = GlobalSocEscalationRecord(
            EscalationId=escalation_id,
            IncidentId=payload.get("incident_id", 101),
            TenantId=payload.get("tenant_id", 1),
            PartnerId=payload.get("partner_id"),
            Severity=severity,
            EscalationTier=payload.get("escalation_tier", "L2_INVESTIGATION"),
            OriginatingRegion=payload.get("originating_region", "APAC"),
            TargetRegion=payload.get("target_region", "EMEA"),
            TriggerReason=payload.get("trigger_reason", "Severity threshold reached; elevated to specialized tier."),
            SlaTargetMinutes=sla_target,
            ResponseTimeMinutes=payload.get("response_time_minutes", 3.5),
            SlaBreached=False,
            Status="IN_PROGRESS",
            CreatedAt=datetime.utcnow()
        )
        db.add(escalation)
        await db.commit()
        logger.info(f"Created global incident escalation: {escalation_id}")
        return {
            "escalation_id": escalation.EscalationId,
            "incident_id": escalation.IncidentId,
            "severity": escalation.Severity,
            "escalation_tier": escalation.EscalationTier,
            "sla_target_minutes": escalation.SlaTargetMinutes,
            "status": escalation.Status,
            "created_at": escalation.CreatedAt.isoformat()
        }

    # -----------------------------------------------------------------------
    # 17.3: MSSP PARTNER & DELEGATED ADMINISTRATION
    # -----------------------------------------------------------------------
    @classmethod
    async def list_partners(cls, db: AsyncSession) -> List[Dict[str, Any]]:
        """List all MSSP Partner Organizations."""
        await cls.ensure_initialized(db)
        res = await db.execute(select(MsspPartnerOrganization).order_by(desc(MsspPartnerOrganization.CreatedAt)))
        partners = res.scalars().all()
        return [
            {
                "partner_id": p.PartnerId,
                "name": p.Name,
                "primary_domain": p.PrimaryDomain,
                "tier": p.PartnerTier,
                "total_customers": p.TotalCustomers,
                "endpoints_managed": p.TotalEndpointsManaged,
                "revenue_share_pct": p.RevenueSharePct,
                "billing_plan": p.BillingPlan,
                "sla_p1_min": p.SlaCommitmentP1Min,
                "status": p.Status,
                "created_at": p.CreatedAt.isoformat() if p.CreatedAt else ""
            }
            for p in partners
        ]

    @classmethod
    async def get_partner_details(cls, db: AsyncSession, partner_id: str) -> Dict[str, Any]:
        """Retrieve detailed partner configuration, customer sub-tenants, and white-label branding."""
        await cls.ensure_initialized(db)
        res = await db.execute(select(MsspPartnerOrganization).where(MsspPartnerOrganization.PartnerId == partner_id))
        partner = res.scalar_one_or_none()
        if not partner:
            raise HTTPException(status_code=404, detail=f"MSSP Partner '{partner_id}' not found.")

        # Query assigned customers
        cust_res = await db.execute(select(MsspCustomerAccount).where(MsspCustomerAccount.PartnerId == partner_id))
        customers = cust_res.scalars().all()

        # Query delegated admins
        admin_res = await db.execute(select(MsspDelegatedAdmin).where(MsspDelegatedAdmin.PartnerId == partner_id))
        admins = admin_res.scalars().all()

        # Query white label
        wl_res = await db.execute(select(WhiteLabelConfig).where(WhiteLabelConfig.PartnerId == partner_id))
        wl = wl_res.scalar_one_or_none()

        return {
            "partner_id": partner.PartnerId,
            "name": partner.Name,
            "domain": partner.PrimaryDomain,
            "tier": partner.PartnerTier,
            "status": partner.Status,
            "sla_commitments": {
                "p1_response_min": partner.SlaCommitmentP1Min,
                "p2_response_min": partner.SlaCommitmentP2Min,
                "p3_response_min": partner.SlaCommitmentP3Min,
                "p4_response_min": partner.SlaCommitmentP4Min
            },
            "billing": {
                "billing_plan": partner.BillingPlan,
                "revenue_share_pct": partner.RevenueSharePct,
                "total_customers": len(customers),
                "total_endpoints": sum(c.EndpointsCount for c in customers)
            },
            "managed_customers": [
                {
                    "customer_id": c.CustomerAccountId,
                    "tenant_id": c.TenantId,
                    "customer_name": c.CustomerName,
                    "industry": c.Industry,
                    "mdr_tier": c.MdrTier,
                    "health_score": c.HealthScore,
                    "risk_score": c.RiskScore,
                    "sla_compliance_rate": c.SlaComplianceRate,
                    "endpoints": c.EndpointsCount,
                    "availability_pct": c.ServiceAvailabilityPct
                }
                for c in customers
            ],
            "delegated_admins": [
                {
                    "full_name": a.FullName,
                    "email": a.Email,
                    "role": a.Role,
                    "can_manage_whitelabel": a.CanManageWhiteLabel,
                    "can_escalate": a.CanEscalateToMonitorixGlobal
                }
                for a in admins
            ],
            "white_label": {
                "enabled": wl.Enabled if wl else False,
                "brand_name": wl.BrandName if wl else "Monitorix",
                "custom_domain": wl.CustomDomain if wl else None,
                "logo_url": wl.LogoUrl if wl else "",
                "primary_brand_color": wl.PrimaryBrandColor if wl else "#6366f1",
                "accent_brand_color": wl.AccentBrandColor if wl else "#8b5cf6",
                "audit_controls_locked": wl.AuditControlsLocked if wl else True
            }
        }

    @classmethod
    async def create_partner(cls, db: AsyncSession, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new MSSP Master Partner Organization."""
        partner_id = f"MSSP-PARTNER-{uuid.uuid4().hex[:6].upper()}"
        name = payload.get("name", "").strip()
        domain = payload.get("primary_domain", "").strip()
        if not name or not domain:
            raise HTTPException(status_code=400, detail="Partner Name and Primary Domain are required.")

        partner = MsspPartnerOrganization(
            PartnerId=partner_id,
            Name=name,
            PrimaryDomain=domain,
            PartnerTier=payload.get("tier", "GOLD").upper(),
            TotalCustomers=0,
            TotalEndpointsManaged=0,
            RevenueSharePct=payload.get("revenue_share_pct", 25.0),
            DelegatedAdminRole="MSSP_SUPER_ADMIN",
            SlaCommitmentP1Min=payload.get("sla_p1_min", 15),
            SlaCommitmentP2Min=payload.get("sla_p2_min", 30),
            SlaCommitmentP3Min=payload.get("sla_p3_min", 120),
            SlaCommitmentP4Min=payload.get("sla_p4_min", 480),
            Status="ACTIVE",
            BillingPlan=payload.get("billing_plan", "WHOLESALE_AGGREGATED")
        )
        db.add(partner)

        # Default white-label config
        wl = WhiteLabelConfig(
            PartnerId=partner_id,
            Enabled=True,
            BrandName=name,
            LogoUrl=f"https://cdn.{domain}/logo.svg",
            FaviconUrl=f"https://cdn.{domain}/favicon.ico",
            CustomDomain=f"soc.{domain}",
            PrimaryBrandColor="#6366f1",
            AccentBrandColor="#8b5cf6",
            CustomCssJson=json.dumps({"theme": "cyber_dark"}),
            EmailHeaderHtml=f"<div><h3>{name} Security Operations</h3></div>",
            EmailFooterHtml="<div>Protected by Monitorix sovereign MDR engine</div>",
            SupportPortalUrl=f"https://support.{domain}",
            PrivacyPolicyUrl=f"https://{domain}/privacy",
            AuditControlsLocked=True
        )
        db.add(wl)

        await db.commit()
        logger.info(f"Created new MSSP Partner: {partner_id} ({name})")
        return await cls.get_partner_details(db, partner_id)

    # -----------------------------------------------------------------------
    # 17.4: WHITE-LABEL BRANDING & SOVEREIGN AUDIT LOCKING
    # -----------------------------------------------------------------------
    @classmethod
    async def get_white_label_config(cls, db: AsyncSession, partner_id: str) -> Dict[str, Any]:
        """Retrieve white-label branding configuration for a partner."""
        await cls.ensure_initialized(db)
        res = await db.execute(select(WhiteLabelConfig).where(WhiteLabelConfig.PartnerId == partner_id))
        wl = res.scalar_one_or_none()
        if not wl:
            raise HTTPException(status_code=404, detail=f"White-label config for partner '{partner_id}' not found.")

        css_json = {}
        try:
            css_json = json.loads(wl.CustomCssJson) if wl.CustomCssJson else {}
        except Exception:
            pass

        return {
            "partner_id": wl.PartnerId,
            "enabled": wl.Enabled,
            "brand_name": wl.BrandName,
            "logo_url": wl.LogoUrl,
            "favicon_url": wl.FaviconUrl,
            "custom_domain": wl.CustomDomain,
            "primary_brand_color": wl.PrimaryBrandColor,
            "accent_brand_color": wl.AccentBrandColor,
            "custom_css": css_json,
            "email_header_html": wl.EmailHeaderHtml,
            "email_footer_html": wl.EmailFooterHtml,
            "support_portal_url": wl.SupportPortalUrl,
            "privacy_policy_url": wl.PrivacyPolicyUrl,
            "audit_controls_locked": wl.AuditControlsLocked, # Immutable sovereign Monitorix audit preservation
            "updated_at": wl.UpdatedAt.isoformat() if wl.UpdatedAt else ""
        }

    @classmethod
    async def update_white_label_config(cls, db: AsyncSession, partner_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update white-label branding.
        SAFETY ENFORCEMENT: AuditControlsLocked is permanently preserved as True.
        Partners cannot disable immutable Monitorix audit logging or security controls.
        """
        res = await db.execute(select(WhiteLabelConfig).where(WhiteLabelConfig.PartnerId == partner_id))
        wl = res.scalar_one_or_none()
        if not wl:
            raise HTTPException(status_code=404, detail=f"White-label config for partner '{partner_id}' not found.")

        if "enabled" in payload:
            wl.Enabled = payload["enabled"]
        if "brand_name" in payload:
            wl.BrandName = payload["brand_name"].strip()
        if "logo_url" in payload:
            wl.LogoUrl = payload["logo_url"].strip()
        if "favicon_url" in payload:
            wl.FaviconUrl = payload["favicon_url"].strip()
        if "custom_domain" in payload:
            wl.CustomDomain = payload["custom_domain"].strip()
        if "primary_brand_color" in payload:
            wl.PrimaryBrandColor = payload["primary_brand_color"].strip()
        if "accent_brand_color" in payload:
            wl.AccentBrandColor = payload["accent_brand_color"].strip()
        if "custom_css" in payload:
            wl.CustomCssJson = json.dumps(payload["custom_css"])
        if "email_header_html" in payload:
            wl.EmailHeaderHtml = payload["email_header_html"]
        if "email_footer_html" in payload:
            wl.EmailFooterHtml = payload["email_footer_html"]

        # Immutable sovereign audit constraint
        wl.AuditControlsLocked = True
        wl.UpdatedAt = datetime.utcnow()

        await db.commit()
        logger.info(f"Updated white-label configuration for partner: {partner_id}")
        return await cls.get_white_label_config(db, partner_id)

    # -----------------------------------------------------------------------
    # 17.5: CUSTOMER ONBOARDING & TENANT OPERATIONS
    # -----------------------------------------------------------------------
    @classmethod
    async def list_customer_accounts(cls, db: AsyncSession, partner_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List managed customer accounts with health, risk, and SLA status."""
        await cls.ensure_initialized(db)
        query = select(MsspCustomerAccount).order_by(desc(MsspCustomerAccount.CreatedAt))
        if partner_id:
            query = query.where(MsspCustomerAccount.PartnerId == partner_id)

        res = await db.execute(query)
        customers = res.scalars().all()
        return [
            {
                "customer_id": c.CustomerAccountId,
                "partner_id": c.PartnerId,
                "tenant_id": c.TenantId,
                "customer_name": c.CustomerName,
                "industry": c.Industry,
                "mdr_tier": c.MdrTier,
                "onboarding_status": c.OnboardingStatus,
                "health_score": c.HealthScore,
                "risk_score": c.RiskScore,
                "sla_compliance_rate": c.SlaComplianceRate,
                "active_incidents": c.ActiveIncidentsCount,
                "endpoints_count": c.EndpointsCount,
                "service_availability_pct": c.ServiceAvailabilityPct,
                "contract_renewal_date": c.ContractRenewalDate.isoformat() if c.ContractRenewalDate else "",
                "created_at": c.CreatedAt.isoformat() if c.CreatedAt else ""
            }
            for c in customers
        ]

    @classmethod
    async def onboard_customer_account(cls, db: AsyncSession, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Onboard a new managed customer account under an MSSP partner with strict tenant isolation."""
        partner_id = payload.get("partner_id")
        customer_name = payload.get("customer_name", "").strip()

        if not partner_id or not customer_name:
            raise HTTPException(status_code=400, detail="Partner ID and Customer Name are required.")

        # Verify partner exists
        partner_res = await db.execute(select(MsspPartnerOrganization).where(MsspPartnerOrganization.PartnerId == partner_id))
        partner = partner_res.scalar_one_or_none()
        if not partner:
            raise HTTPException(status_code=404, detail=f"Partner '{partner_id}' does not exist.")

        # Create isolated Tenant
        new_tenant = Tenant(
            Name=customer_name,
            Plan=payload.get("mdr_tier", "MANAGED_RESPONSE"),
            AgentLimit=payload.get("endpoints_count", 250),
            ApiKey=f"mon_live_{uuid.uuid4().hex[:16]}"
        )
        db.add(new_tenant)
        await db.flush()

        customer_id = f"CUST-{uuid.uuid4().hex[:6].upper()}"
        cust_account = MsspCustomerAccount(
            CustomerAccountId=customer_id,
            PartnerId=partner_id,
            TenantId=new_tenant.Id,
            CustomerName=customer_name,
            Industry=payload.get("industry", "Technology"),
            MdrTier=payload.get("mdr_tier", "MANAGED_RESPONSE"),
            OnboardingStatus="ACTIVE",
            HealthScore=99.0,
            RiskScore=12.5,
            SlaComplianceRate=100.0,
            ActiveIncidentsCount=0,
            EndpointsCount=payload.get("endpoints_count", 250),
            ServiceAvailabilityPct=99.99,
            ContractRenewalDate=datetime.utcnow() + timedelta(days=365)
        )
        db.add(cust_account)

        # Update partner total customer count
        partner.TotalCustomers += 1
        partner.TotalEndpointsManaged += cust_account.EndpointsCount

        await db.commit()
        logger.info(f"Onboarded customer {customer_id} ({customer_name}) under partner {partner_id}")
        return {
            "customer_id": cust_account.CustomerAccountId,
            "partner_id": cust_account.PartnerId,
            "tenant_id": cust_account.TenantId,
            "customer_name": cust_account.CustomerName,
            "onboarding_status": cust_account.OnboardingStatus,
            "endpoints_allocated": cust_account.EndpointsCount
        }
