"""
[v4.4.0] Nigeria Data Protection Act 2023 (NDPA) & NDPC General Application Directive (GAID)
Covers 11-digit NIN & BVN discovery, Storage Limitation (Section 24), Lawful Basis & Consent
(Sections 25–26), Data Subject Rights (Sections 34–38), Security & Integrity Measures
(Section 39: Encryption, RBAC, Audit Logs, Vulnerability Management), 72-Hour NDPC Breach
Notification (Section 40), Cross-Border Transfers (Section 41, af-south-1), and Data Controller
of Major Importance (DCMI) Registration / Compliance Audit Returns (Sections 32 & 44 MANUAL_REVIEW).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class NdpaFramework(BaseComplianceFramework):
    framework_id = "NDPA"
    name = "Nigeria Data Protection Act 2023 (NDPA)"
    region = "NG"
    jurisdiction = "Federal Republic of Nigeria"
    category = FrameworkCategory.PRIVACY
    version = "Act No. 2023-11"
    effective_from = "2023-06-12"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Nigeria Data Protection Commission (NDPC)"
    breach_notification_window = "Within 72 Hours to NDPC & Immediately to Data Subjects for High Risk (Section 40)"
    residency_region = "af-south-1"
    source_reference = "Nigeria Data Protection Commission (NDPC), Official Gazette No. 119 Vol. 110"
    supported_privacy_rights = ["ACCESS", "DELETE", "CORRECT", "RECTIFY", "RESTRICT", "OBJECT", "PORTABILITY"]

    controls = [
        ComplianceControl(
            control_id="NDPA-NIN-DISC",
            framework_id="NDPA",
            title="Sections 24 & 30: Nigerian NIN, BVN & Sensitive Personal Data Discovery",
            requirement="Discover and classify 11-digit National Identification Numbers (NIN), Bank Verification Numbers (BVN), Passports, and TINs.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="NDPA 2023 Sections 24 & 30",
            recommended_action="Ensure Nigeria (NG) PII classifiers are active across DLP/DSPM.",
        ),
        ComplianceControl(
            control_id="NDPA-SEC-24-MIN",
            framework_id="NDPA",
            title="Section 24(1)(d): Storage Limitation & Automated Erasure",
            requirement="Retain personal data for not longer than is necessary to achieve the lawful purpose for which it was collected.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="NDPA 2023 Section 24(1)(d)",
            recommended_action="Enforce 90-day automated telemetry pruning.",
        ),
        ComplianceControl(
            control_id="NDPA-SEC-26-CONSENT",
            framework_id="NDPA",
            title="Sections 25–27: Lawful Basis, Affirmative Consent & Transparency Notice",
            requirement="Provide clear prior transparency disclosures and obtain affirmative consent for visual workplace monitoring.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="NDPA 2023 Sections 25, 26 & 27",
            recommended_action="Enable MonitoringConsentRequired notice banners on visually monitored endpoints.",
        ),
        ComplianceControl(
            control_id="NDPA-SEC-34-DSR",
            framework_id="NDPA",
            title="Sections 34–38: Data Subject Access, Correction, Erasure & Portability Rights",
            requirement="Fulfill data subject access, rectification, erasure, restriction, objection, and portability requests promptly.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="NDPA 2023 Sections 34–38",
            recommended_action="Fulfill open NDPA DSR requests within 30 days.",
        ),
        ComplianceControl(
            control_id="NDPA-SEC-39-SEC",
            framework_id="NDPA",
            title="Section 39: Security, Integrity & Confidentiality of Personal Data",
            requirement="Implement appropriate technical and organizational measures including pseudonymization and DSPM exposure controls.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="NDPA 2023 Section 39",
            recommended_action="Remediate exposed NIN/BVN datastores in DSPM.",
        ),
        ComplianceControl(
            control_id="NDPA-SEC-39-ENC",
            framework_id="NDPA",
            title="Section 39(2)(a): Encryption of Personal Data at Rest & in Transit",
            requirement="Apply strong cryptographic encryption to stored personal data and network transport channels.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="NDPA 2023 Section 39(2)(a)",
            recommended_action="Enable AES-256 datastore encryption and TLS 1.3.",
        ),
        ComplianceControl(
            control_id="NDPA-SEC-39-RBAC",
            framework_id="NDPA",
            title="Section 39(2): Access Control, Resilience & Vulnerability Testing",
            requirement="Restrict access via RBAC and regularly assess/patch technical vulnerabilities.",
            category="VULNERABILITY_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="NDPA 2023 Section 39(2)(b)–(d)",
            recommended_action="Remediate High and Critical endpoint software vulnerabilities.",
        ),
        ComplianceControl(
            control_id="NDPA-SEC-24-AUDIT",
            framework_id="NDPA",
            title="Section 24(3): Duty of Care & Tamper-Evident Accountability Logs",
            requirement="Demonstrate accountability and compliance with Section 24 principles via immutable audit logging.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="NDPA 2023 Section 24(3)",
            recommended_action="Maintain tamper-evident AuditLog records.",
        ),
        ComplianceControl(
            control_id="NDPA-SEC-40-BREACH",
            framework_id="NDPA",
            title="Section 40 & Section 41: 72-Hour NDPC Breach Notice & Cross-Border Fencing (af-south-1)",
            requirement="Notify the NDPC within 72 hours of a personal data breach likely to pose risk to individuals and enforce af-south-1 cross-border fencing.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="NDPA 2023 Sections 40 & 41",
            recommended_action="Triage critical security incidents within 72h and enforce af-south-1 fencing.",
        ),
        ComplianceControl(
            control_id="NDPA-SEC-32-DPO",
            framework_id="NDPA",
            title="Sections 28, 32 & 44: DPO Appointment, DPIA & NDPC Major Importance (DCMI) Registration",
            requirement="Register as a Data Controller/Processor of Major Importance with the NDPC (s44), designate a DPO (s32), and file annual Compliance Audit Returns via licensed DPCO.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="NDPA 2023 Sections 28, 32 & 44",
            recommended_action="Attach NDPC DCMI Registration Certificate, DPO Credentials, and Annual DPCO Audit Return.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        res_check = await self.probe_data_residency_fencing(tenant_id, "af-south-1", db, "NDPA-SEC-40-BREACH", "NDPA Section 41")
        inc_check = await self.probe_incident_response_backlog(tenant_id, db, "NDPA-SEC-40-BREACH", "NDPA Section 40")
        combined = inc_check if inc_check.status.value != "PASS" else res_check
        combined.control_id = "NDPA-SEC-40-BREACH"

        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "NG", db, "NDPA-NIN-DISC", "NDPA Sections 24 & 30"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "NDPA-SEC-24-MIN", "NDPA Section 24(1)(d)"),
            await self.probe_visual_privacy_consent(tenant_id, db, "NDPA-SEC-26-CONSENT", "NDPA Sections 25–27"),
            await self.probe_privacy_request_sla(tenant_id, db, "NDPA-SEC-34-DSR", "NDPA Sections 34–38", sla_days=30),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "NDPA-SEC-39-SEC", "NDPA Section 39"),
            await self.probe_encryption_and_tls(tenant_id, db, "NDPA-SEC-39-ENC", "NDPA Section 39(2)(a)"),
            await self.probe_vulnerability_backlog(tenant_id, db, "NDPA-SEC-39-RBAC", "NDPA Section 39(2)(d)"),
            await self.probe_audit_logging_active(tenant_id, db, "NDPA-SEC-24-AUDIT", "NDPA Section 24(3)"),
            combined,
            self.manual_review_control(
                "NDPA-SEC-32-DPO",
                "NDPC DCMI Registration, DPO & DPCO Compliance Audit Return",
                "Verify NDPC Data Controller of Major Importance registration (s44), DPO designation (s32), and annual DPCO audit filing.",
                "NDPA 2023 Sections 28, 32 & 44",
                "NDPC DCMI Certificate, DPO Appointment Letter & Filed DPCO Audit Return",
                tenant_id=tenant_id,
            ),
        ]


async def run_ndpa_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await NdpaFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
