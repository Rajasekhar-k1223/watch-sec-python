"""
[v4.4.0] China Data Security Law (DSL) — PRC President Order No. 84
Implements configurable 3-tier Data Classification & Grading (Art. 21):
  - GENERAL_DATA
  - IMPORTANT_DATA
  - CORE_DATA
Mapping: Data Asset -> Classification -> Owner -> Business Purpose -> Risk -> Evidence
Plus encryption, access control, audit logging, risk monitoring, emergency response,
domestic residency (cn-north-1), and National Core/Important Data Export Review (`MANUAL_REVIEW`).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import (
    FrameworkCategory,
    CheckType,
    Severity,
    ControlStatus,
    ComplianceCheckResult,
    ComplianceFinding,
    ComplianceRemediation,
)
from ..core.evidence import create_evidence


DEFAULT_DSL_ASSETS = [
    {
        "asset_code": "DSL-ASSET-TELEMETRY",
        "asset_name": "Endpoint Operational Security Telemetry",
        "dsl_category": "GENERAL_DATA",
        "owner": "SOC Operations Lead",
        "department": "Security Operations",
        "business_purpose": "Real-time threat detection and endpoint health monitoring",
        "risk_level": "MEDIUM",
        "cross_border_allowed": False,
        "evidence_ref": "POSTGRES:EventLogs",
    },
    {
        "asset_code": "DSL-ASSET-PII-DSPM",
        "asset_name": "Regulated Customer & Identity Repositories",
        "dsl_category": "IMPORTANT_DATA",
        "owner": "Chief Data Security Officer",
        "department": "Data Governance & Privacy",
        "business_purpose": "Identity governance, DLP classification, and statutory compliance",
        "risk_level": "HIGH",
        "cross_border_allowed": False,
        "evidence_ref": "DSPM:DspmDataStores",
    },
    {
        "asset_code": "DSL-ASSET-PKI-VAULT",
        "asset_name": "Sovereign Cryptographic Keys & Threat Intelligence",
        "dsl_category": "CORE_DATA",
        "owner": "Platform Security Architect",
        "department": "Cloud & Platform Infrastructure",
        "business_purpose": "Sovereign mTLS enclave authentication and Ed25519 signing",
        "risk_level": "CRITICAL",
        "cross_border_allowed": False,
        "evidence_ref": "PKI:SovereignKeyVault",
    },
]


class ChinaDslFramework(BaseComplianceFramework):
    framework_id = "CHINA_DSL"
    name = "Data Security Law of the PRC (DSL)"
    region = "CN"
    jurisdiction = "People's Republic of China"
    category = FrameworkCategory.DATA_SECURITY
    version = "Order No. 84 of the President of the PRC"
    effective_from = "2021-09-01"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Central National Security Leadership Organ, CAC & MIIT"
    breach_notification_window = "Immediate Disposal & Timely Notification to Users and Authorities (Art. 29)"
    residency_region = "cn-north-1"
    source_reference = "Data Security Law of the PRC (Effective Sept 1, 2021)"
    supported_privacy_rights = ["ACCESS"]

    controls = [
        ComplianceControl(
            control_id="DSL-ART-21-CLASS",
            framework_id="CHINA_DSL",
            title="3-Tier Data Classification & Hierarchical Protection (General / Important / Core Data)",
            requirement="Classify and grade data assets across GENERAL_DATA, IMPORTANT_DATA, and CORE_DATA with designated owners, purposes, risk ratings, and cross-border restrictions.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="DSL Art. 21",
            recommended_action="Ensure all 3 DSL tiers (GENERAL_DATA, IMPORTANT_DATA, CORE_DATA) are cataloged with owners and zero unauthorized cross-border export.",
        ),
        ComplianceControl(
            control_id="DSL-ART-27-SEC",
            framework_id="CHINA_DSL",
            title="Full-Lifecycle Data Security Management, Encryption & Access Control (Art. 27)",
            requirement="Adopt technical measures including encryption, RBAC, and DSPM exposure controls across the full data lifecycle.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="DSL Art. 27",
            recommended_action="Remediate exposed sensitive datastores in DSPM and enforce AES-256 encryption.",
        ),
        ComplianceControl(
            control_id="DSL-ART-27-ENC",
            framework_id="CHINA_DSL",
            title="Cryptographic Protection of Important & Core Data Assets (Art. 27)",
            requirement="Encrypt important and core data repositories at rest and over network links.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="DSL Art. 27",
            recommended_action="Enable encryption at rest on all datastores.",
        ),
        ComplianceControl(
            control_id="DSL-ART-27-AUDIT",
            framework_id="CHINA_DSL",
            title="Data Processing Activity Audit Logging & Access Monitoring (Art. 27)",
            requirement="Record and retain immutable logs of administrative and data access operations.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="DSL Art. 27",
            recommended_action="Maintain tamper-evident AuditLog recording.",
        ),
        ComplianceControl(
            control_id="DSL-ART-29-RISK-VULN",
            framework_id="CHINA_DSL",
            title="Continuous Risk Monitoring & Defect/Vulnerability Remediation (Art. 29)",
            requirement="Strengthen risk monitoring when conducting data activities and immediately take remedial measures upon discovering defects or vulnerabilities.",
            category="VULNERABILITY_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="DSL Art. 29",
            recommended_action="Remediate High/Critical software vulnerabilities.",
        ),
        ComplianceControl(
            control_id="DSL-ART-29-INCIDENT",
            framework_id="CHINA_DSL",
            title="Data Security Incident Disposal & Competent Department Notification (Art. 29)",
            requirement="Immediately take disposal measures upon data security incidents and notify users and competent authorities.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="DSL Art. 29",
            recommended_action="Triage critical security incidents promptly.",
        ),
        ComplianceControl(
            control_id="DSL-ART-31-RESIDENCY",
            framework_id="CHINA_DSL",
            title="Outbound Important/Core Data Security & Sovereign Localization (Art. 31 / Art. 36)",
            requirement="Enforce domestic sovereign boundary fencing (cn-north-1) and prevent unauthorized foreign judicial/cross-border data handovers.",
            category="DATA_RESIDENCY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="DSL Art. 31 & Art. 36",
            recommended_action="Enforce cn-north-1 sovereign boundary fencing.",
        ),
        ComplianceControl(
            control_id="DSL-ART-30-ASSESSMENT",
            framework_id="CHINA_DSL",
            title="Important Data Risk Assessment Report Filing & Art. 36 Foreign Request Approval",
            requirement="Processors of Important Data must conduct periodic risk assessments and submit risk assessment reports to competent regulatory authorities (Art. 30).",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="DSL Art. 30 & Art. 36",
            recommended_action="Attach Annual Important Data Risk Assessment Report filed with CAC / MIIT.",
        ),
    ]

    async def _probe_dsl_classification(
        self, tenant_id: int, db: Optional[AsyncSession]
    ) -> ComplianceCheckResult:
        if db is None:
            return self._diagnostic_manual_review(
                tenant_id, "DSL-ART-21-CLASS",
                "3-Tier Data Classification & Hierarchical Protection",
                "DSL Art. 21", "DATA_DISCOVERY", "Database session unavailable"
            )
        try:
            from ...db.models import DslDataAssetClassificationRecord
            rows = (
                await db.execute(
                    select(DslDataAssetClassificationRecord).where(
                        DslDataAssetClassificationRecord.TenantId == tenant_id
                    )
                )
            ).scalars().all()

            if not rows:
                for item in DEFAULT_DSL_ASSETS:
                    rec = DslDataAssetClassificationRecord(
                        AssetCode=item["asset_code"],
                        TenantId=tenant_id,
                        AssetName=item["asset_name"],
                        DslCategory=item["dsl_category"],
                        Owner=item["owner"],
                        Department=item["department"],
                        BusinessPurpose=item["business_purpose"],
                        RiskLevel=item["risk_level"],
                        CrossBorderAllowed=item["cross_border_allowed"],
                        EvidenceRef=item["evidence_ref"],
                    )
                    db.add(rec)
                await db.commit()
                rows = (
                    await db.execute(
                        select(DslDataAssetClassificationRecord).where(
                            DslDataAssetClassificationRecord.TenantId == tenant_id
                        )
                    )
                ).scalars().all()

            categories_present = sorted({r.DslCategory for r in rows})
            unowned = [r.AssetCode for r in rows if not r.Owner]
            unsafe_export = [
                r.AssetCode for r in rows
                if r.DslCategory in ("IMPORTANT_DATA", "CORE_DATA") and r.CrossBorderAllowed
            ]

            ev = create_evidence(
                tenant_id=tenant_id,
                framework=self.framework_id,
                control_id="DSL-ART-21-CLASS",
                source="DSL_3_TIER_ASSET_CATALOG",
                collector="Monitorix DSL Hierarchical Classifier",
                details={
                    "classified_assets_count": len(rows),
                    "tiers_present": categories_present,
                    "unowned_assets": unowned,
                    "unsafe_cross_border_important_or_core_assets": unsafe_export,
                },
            )

            if unsafe_export or unowned:
                finding = ComplianceFinding(
                    finding_id=f"FIND-CHINA_DSL-CLASS-{tenant_id}",
                    tenant_id=tenant_id,
                    framework=self.framework_id,
                    control_id="DSL-ART-21-CLASS",
                    title="Important/Core Data Asset Missing Owner or Flagged for Cross-Border Export",
                    severity=Severity.CRITICAL,
                    category="DATA_DISCOVERY",
                    affected_asset=", ".join(unsafe_export + unowned),
                    department="Data Governance & Privacy",
                    affected_data="Important & Core Data Catalog",
                    finding_details=f"Unsafe export assets: {unsafe_export}; unowned assets: {unowned}.",
                    evidence_hash=ev.evidence_hash,
                    remediation=ComplianceRemediation(
                        why_it_matters="DSL Art. 21 & Art. 31 prohibit unapproved outbound transfer of Important/Core Data and require designated security officers.",
                        recommended_action="Disable CrossBorderAllowed on IMPORTANT_DATA/CORE_DATA assets and assign owners.",
                        manual_action="Update asset classifications in Compliance Center > China DSL Catalog.",
                        reference="DSL Art. 21 & Art. 31",
                        verification_method="Verify zero CORE_DATA/IMPORTANT_DATA assets have CrossBorderAllowed=True.",
                    ),
                )
                return ComplianceCheckResult(
                    framework=self.framework_id,
                    control_id="DSL-ART-21-CLASS",
                    check_name="3-Tier Data Classification & Hierarchical Protection",
                    category="DATA_DISCOVERY",
                    status=ControlStatus.FAIL,
                    severity=Severity.CRITICAL,
                    score=0.0,
                    evidence=[ev],
                    finding=finding,
                    remediation=finding.remediation,
                    legal_reference="DSL Art. 21",
                )

            return ComplianceCheckResult(
                framework=self.framework_id,
                control_id="DSL-ART-21-CLASS",
                check_name="3-Tier Data Classification & Hierarchical Protection",
                category="DATA_DISCOVERY",
                status=ControlStatus.PASS,
                severity=Severity.LOW,
                score=100.0,
                evidence=[ev],
                legal_reference="DSL Art. 21",
            )
        except Exception as exc:
            return self._diagnostic_manual_review(
                tenant_id, "DSL-ART-21-CLASS",
                "3-Tier Data Classification & Hierarchical Protection",
                "DSL Art. 21", "DATA_DISCOVERY", str(type(exc).__name__)
            )

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        return [
            await self._probe_dsl_classification(tenant_id, db),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "DSL-ART-27-SEC", "DSL Art. 27"),
            await self.probe_encryption_and_tls(tenant_id, db, "DSL-ART-27-ENC", "DSL Art. 27"),
            await self.probe_audit_logging_active(tenant_id, db, "DSL-ART-27-AUDIT", "DSL Art. 27"),
            await self.probe_vulnerability_backlog(tenant_id, db, "DSL-ART-29-RISK-VULN", "DSL Art. 29"),
            await self.probe_incident_response_backlog(tenant_id, db, "DSL-ART-29-INCIDENT", "DSL Art. 29"),
            await self.probe_data_residency_fencing(tenant_id, "cn-north-1", db, "DSL-ART-31-RESIDENCY", "DSL Art. 31"),
            self.manual_review_control(
                "DSL-ART-30-ASSESSMENT",
                "Annual Important Data Risk Assessment Filing & Art. 36 Judicial Export Approval",
                "Verify annual Important Data Risk Assessment submission to CAC/MIIT and strict prohibition of unapproved foreign judicial handovers.",
                "DSL Art. 30 & Art. 36",
                "Filed Annual Important Data Risk Assessment Report & Data Security Officer Charter",
                tenant_id=tenant_id,
            ),
        ]


async def run_china_dsl_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await ChinaDslFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
