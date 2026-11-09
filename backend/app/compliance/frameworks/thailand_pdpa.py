"""
[v4.4.0] Thailand PDPA (Personal Data Protection Act B.E. 2562 / 2019)
Covers Thai 13-digit National ID (Modulo-11) & PII discovery, Lawful Basis & Collection Notice
(Sections 19 & 23), Data Subject Rights (Sections 30–36), PDPC Security Notification B.E. 2565
(Section 37(1): Encryption, RBAC, Audit Logs, Vulnerability Management), Retention & Erasure
System (Section 37(3)), 72-Hour PDPC Breach Notification (Section 37(4)), Cross-Border Transfers
(Section 28, ap-southeast-1), and DPO / RoPA Obligations (Sections 39 & 41 MANUAL_REVIEW).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class ThailandPdpaFramework(BaseComplianceFramework):
    framework_id = "THAILAND_PDPA"
    name = "Thailand Personal Data Protection Act B.E. 2562"
    region = "TH"
    jurisdiction = "Kingdom of Thailand"
    category = FrameworkCategory.PRIVACY
    version = "B.E. 2562 (Effective June 2022)"
    effective_from = "2022-06-01"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Personal Data Protection Committee (PDPC) Thailand"
    breach_notification_window = "Within 72 Hours to Office of the PDPC (Section 37(4))"
    residency_region = "ap-southeast-1"
    source_reference = "Royal Thai Government Gazette, Personal Data Protection Act B.E. 2562"
    supported_privacy_rights = ["ACCESS", "DELETE", "CORRECT", "RECTIFY", "RESTRICT", "OBJECT", "PORTABILITY"]

    controls = [
        ComplianceControl(
            control_id="TH-PDPA-ID-DISC",
            framework_id="THAILAND_PDPA",
            title="Sections 22 & 26: Thai 13-Digit National ID & Sensitive PII Discovery",
            requirement="Discover and classify Thai 13-digit Citizen IDs (Modulo-11), Tax IDs, Passports, and sensitive personal data.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Thailand PDPA Sections 22 & 26",
            recommended_action="Ensure Thailand (TH) PII classifiers are active in DLP/DSPM.",
        ),
        ComplianceControl(
            control_id="TH-PDPA-CONSENT",
            framework_id="THAILAND_PDPA",
            title="Sections 19 & 23: Explicit Consent & Privacy Notice on Collection",
            requirement="Inform data subjects of collection purposes and obtain clear consent where required on monitored endpoints.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Thailand PDPA Sections 19 & 23",
            recommended_action="Enable MonitoringConsentRequired notice banners on visually monitored endpoints.",
        ),
        ComplianceControl(
            control_id="TH-PDPA-DSR",
            framework_id="THAILAND_PDPA",
            title="Sections 30–36: Data Subject Access, Portability, Erasure & Objection Rights",
            requirement="Fulfill data subject requests without delay and within 30 days of receipt.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Thailand PDPA Sections 30–36",
            recommended_action="Fulfill open Thailand PDPA DSR requests within 30 days.",
        ),
        ComplianceControl(
            control_id="TH-PDPA-SEC-37-SEC",
            framework_id="THAILAND_PDPA",
            title="Section 37(1): Appropriate Security Measures & Sensitive Exposure Prevention",
            requirement="Provide appropriate security measures for preventing unauthorized or unlawful loss, access, use, alteration, or disclosure.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="Thailand PDPA Section 37(1) & PDPC Security Notification B.E. 2565",
            recommended_action="Remediate exposed Thai PII datastores in DSPM.",
        ),
        ComplianceControl(
            control_id="TH-PDPA-ENC",
            framework_id="THAILAND_PDPA",
            title="PDPC Security Notification B.E. 2565: Cryptographic Controls & TLS 1.3",
            requirement="Implement cryptographic confidentiality controls at rest and in transit for personal data components.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PDPC Notification on Security Measures of Data Controller B.E. 2565",
            recommended_action="Enable AES-256 encryption at rest and TLS 1.3.",
        ),
        ComplianceControl(
            control_id="TH-PDPA-RBAC",
            framework_id="THAILAND_PDPA",
            title="Section 37(2): Access Control & Prevention of Unauthorized Recipient Use",
            requirement="Enforce role-based access control and identity verification over personal data systems.",
            category="ACCESS_CONTROL",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Thailand PDPA Section 37(1)–(2)",
            recommended_action="Enforce tenant-scoped RBAC least-privilege access.",
        ),
        ComplianceControl(
            control_id="TH-PDPA-AUDIT",
            framework_id="THAILAND_PDPA",
            title="PDPC Security Notification B.E. 2565: User Access Monitoring & Audit Trail",
            requirement="Maintain tamper-evident audit logs enabling retrospective inspection of access, alteration, and erasure.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Thailand PDPA Section 37(1)",
            recommended_action="Ensure AuditLog records all administrative and compliance events.",
        ),
        ComplianceControl(
            control_id="TH-PDPA-SEC-28-MIN",
            framework_id="THAILAND_PDPA",
            title="Section 37(3): Examination System for Deletion & Destruction Upon Expiry",
            requirement="Put in place an automated examination system for erasure or destruction of personal data when retention periods end.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Thailand PDPA Section 37(3)",
            recommended_action="Enforce 90-day automated telemetry pruning.",
        ),
        ComplianceControl(
            control_id="TH-PDPA-SEC-37-BREACH",
            framework_id="THAILAND_PDPA",
            title="Section 37(4) & Section 28: 72-Hour PDPC Breach Notice & Cross-Border Fencing",
            requirement="Notify the Office of the PDPC within 72 hours of becoming aware of a personal data breach and enforce ap-southeast-1 transfer fencing.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="Thailand PDPA Sections 28 & 37(4)",
            recommended_action="Triage critical security incidents within 72h and enforce ap-southeast-1 residency.",
        ),
        ComplianceControl(
            control_id="TH-PDPA-SEC-41-DPO",
            framework_id="THAILAND_PDPA",
            title="Sections 39 & 41: Record of Processing Activities (RoPA) & DPO Designation",
            requirement="Maintain written/electronic Records of Processing Activities (s39) and designate a Data Protection Officer (s41) where core activities involve large-scale monitoring.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="Thailand PDPA Sections 39 & 41",
            recommended_action="Attach Thai PDPC DPO Appointment Notice and Section 39 RoPA Register.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        res_check = await self.probe_data_residency_fencing(tenant_id, "ap-southeast-1", db, "TH-PDPA-SEC-37-BREACH", "Thailand PDPA s28")
        inc_check = await self.probe_incident_response_backlog(tenant_id, db, "TH-PDPA-SEC-37-BREACH", "Thailand PDPA s37(4)")
        combined = inc_check if inc_check.status.value != "PASS" else res_check
        combined.control_id = "TH-PDPA-SEC-37-BREACH"

        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "TH", db, "TH-PDPA-ID-DISC", "Thailand PDPA s22 & s26"),
            await self.probe_visual_privacy_consent(tenant_id, db, "TH-PDPA-CONSENT", "Thailand PDPA s19 & s23"),
            await self.probe_privacy_request_sla(tenant_id, db, "TH-PDPA-DSR", "Thailand PDPA s30–36", sla_days=30),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "TH-PDPA-SEC-37-SEC", "Thailand PDPA s37(1)"),
            await self.probe_encryption_and_tls(tenant_id, db, "TH-PDPA-ENC", "PDPC Security Notification B.E. 2565"),
            await self.probe_access_control_rbac_mfa(tenant_id, db, "TH-PDPA-RBAC", "Thailand PDPA s37(2)"),
            await self.probe_audit_logging_active(tenant_id, db, "TH-PDPA-AUDIT", "Thailand PDPA s37(1)"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "TH-PDPA-SEC-28-MIN", "Thailand PDPA s37(3)"),
            combined,
            self.manual_review_control(
                "TH-PDPA-SEC-41-DPO",
                "Section 39 RoPA & Section 41 DPO Designation",
                "Verify appointment of Data Protection Officer notified to the Thai PDPC and maintained Section 39 RoPA.",
                "Thailand PDPA Sections 39 & 41",
                "Thai PDPC DPO Notification Filing & Section 39 RoPA Ledger",
                tenant_id=tenant_id,
            ),
        ]


async def run_thailand_pdpa_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await ThailandPdpaFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
