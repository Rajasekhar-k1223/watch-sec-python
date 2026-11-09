"""
[v4.4.0] UAE Federal Decree-Law No. 45 of 2021 Regarding the Protection of Personal Data (PDPL)
Covers 15-digit Emirates ID (784-YYYY-NNNNNNN-C Luhn) & UAE TRN/IBAN discovery, Consent & Purpose
Controls (Art. 4 & 5), Data Subject Rights (Art. 13–18), Technical & Organizational Security
(Art. 20: Encryption, Pseudonymization, RBAC, Audit Logs, Vulnerability Management), Immediate
UAE Data Office Breach Notification (Art. 9), Cross-Border Transfers (Art. 22–23, me-central-1),
and DPO Designation / Record of Processing / DPIA (Art. 7, 10 & 21 MANUAL_REVIEW).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class UaeDplFramework(BaseComplianceFramework):
    framework_id = "UAE_DPL"
    name = "UAE Federal Decree-Law No. 45 of 2021 on Personal Data Protection"
    region = "AE"
    jurisdiction = "United Arab Emirates"
    category = FrameworkCategory.PRIVACY
    version = "Federal Decree-Law No. 45 of 2021"
    effective_from = "2022-01-02"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "UAE Data Office"
    breach_notification_window = "Immediately Upon Awareness to UAE Data Office & Data Subjects (Article 9)"
    residency_region = "me-central-1"
    source_reference = "UAE Data Office, Federal Decree-Law No. 45 of 2021 on the Protection of Personal Data"
    supported_privacy_rights = ["ACCESS", "DELETE", "CORRECT", "RECTIFY", "RESTRICT", "OBJECT", "PORTABILITY"]

    controls = [
        ComplianceControl(
            control_id="UAE-DPL-EID-DISC",
            framework_id="UAE_DPL",
            title="Article 1: Emirates ID (784 Luhn), UAE TRN & Personal Data Discovery",
            requirement="Discover and classify 15-digit UAE Emirates IDs (784-YYYY-NNNNNNN-C Luhn), TRN tax IDs, AE IBANs, and Passports.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="UAE Decree-Law No. 45/2021 Article 1",
            recommended_action="Ensure UAE (AE) PII classifiers are active across DLP/DSPM.",
        ),
        ComplianceControl(
            control_id="UAE-DPL-ART-5-MIN",
            framework_id="UAE_DPL",
            title="Article 5(1)(d)–(e): Storage Limitation, Erasure & Anonymization",
            requirement="Do not retain personal data after fulfillment of processing purpose unless anonymized.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="UAE Decree-Law No. 45/2021 Article 5",
            recommended_action="Enforce 90-day automated telemetry pruning.",
        ),
        ComplianceControl(
            control_id="UAE-DPL-ART-4-CONSENT",
            framework_id="UAE_DPL",
            title="Articles 4 & 6: Clear, Simple & Unambiguous Consent Conditions",
            requirement="Obtain clear affirmative consent prior to processing visual workplace telemetry.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="UAE Decree-Law No. 45/2021 Articles 4 & 6",
            recommended_action="Enable MonitoringConsentRequired notice banners on visually monitored endpoints.",
        ),
        ComplianceControl(
            control_id="UAE-DPL-ART-13-DSR",
            framework_id="UAE_DPL",
            title="Articles 13–18: Right to Obtain Info, Portability, Correction, Erasure & Restriction",
            requirement="Provide accessible channels and fulfill data subject rights requests promptly.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="UAE Decree-Law No. 45/2021 Articles 13–18",
            recommended_action="Fulfill open UAE PDPL DSR requests within statutory windows.",
        ),
        ComplianceControl(
            control_id="UAE-DPL-ART-20-SEC",
            framework_id="UAE_DPL",
            title="Article 20: Personal Data Security & Sensitive Exposure Prevention",
            requirement="Establish and take appropriate technical and organizational measures to preserve high information security levels.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="UAE Decree-Law No. 45/2021 Article 20",
            recommended_action="Remediate exposed Emirates ID and PII datastores in DSPM.",
        ),
        ComplianceControl(
            control_id="UAE-DPL-ART-20-ENC",
            framework_id="UAE_DPL",
            title="Article 20(2)(a): Encryption & Pseudonymization of Personal Data",
            requirement="Apply encryption at rest (AES-256) and TLS 1.3 in transit as explicitly mandated under Article 20(2)(a).",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="UAE Decree-Law No. 45/2021 Article 20(2)(a)",
            recommended_action="Enable encryption at rest across all datastores.",
        ),
        ComplianceControl(
            control_id="UAE-DPL-ART-20-RBAC",
            framework_id="UAE_DPL",
            title="Article 20(2)(b)–(d): Confidentiality, Access Control & Vulnerability Testing",
            requirement="Ensure ongoing confidentiality via RBAC and regularly test/evaluate technical security measures.",
            category="VULNERABILITY_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="UAE Decree-Law No. 45/2021 Article 20(2)(b) & (d)",
            recommended_action="Remediate High and Critical endpoint software vulnerabilities.",
        ),
        ComplianceControl(
            control_id="UAE-DPL-ART-7-AUDIT",
            framework_id="UAE_DPL",
            title="Article 7(4): Verification & Tamper-Evident Operational Audit Logs",
            requirement="Maintain auditable system logs enabling UAE Data Office verification of controller compliance.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="UAE Decree-Law No. 45/2021 Article 7",
            recommended_action="Maintain tamper-evident AuditLog records.",
        ),
        ComplianceControl(
            control_id="UAE-DPL-ART-9-BREACH",
            framework_id="UAE_DPL",
            title="Article 9 & Articles 22–23: Immediate UAE Data Office Breach Notice & Residency (me-central-1)",
            requirement="Immediately notify the UAE Data Office upon personal data breach prejudice and enforce me-central-1 cross-border transfer fencing.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="UAE Decree-Law No. 45/2021 Articles 9, 22 & 23",
            recommended_action="Triage critical security incidents immediately and enforce me-central-1 fencing.",
        ),
        ComplianceControl(
            control_id="UAE-DPL-ART-10-DPO",
            framework_id="UAE_DPL",
            title="Articles 7(3), 10 & 21: DPO Appointment, Special Processing Register & DPIA",
            requirement="Appoint a skilled Data Protection Officer (Art. 10), maintain the statutory Special Record of Personal Data (Art. 7(3)), and conduct Art. 21 DPIAs.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="UAE Decree-Law No. 45/2021 Articles 7(3), 10 & 21",
            recommended_action="Attach UAE DPO Appointment Details, Article 7(3) Special Record, and Article 21 DPIA.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        res_check = await self.probe_data_residency_fencing(tenant_id, "me-central-1", db, "UAE-DPL-ART-9-BREACH", "UAE PDPL Articles 22 & 23")
        inc_check = await self.probe_incident_response_backlog(tenant_id, db, "UAE-DPL-ART-9-BREACH", "UAE PDPL Article 9")
        combined = inc_check if inc_check.status.value != "PASS" else res_check
        combined.control_id = "UAE-DPL-ART-9-BREACH"

        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "AE", db, "UAE-DPL-EID-DISC", "UAE PDPL Article 1"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "UAE-DPL-ART-5-MIN", "UAE PDPL Article 5"),
            await self.probe_visual_privacy_consent(tenant_id, db, "UAE-DPL-ART-4-CONSENT", "UAE PDPL Articles 4 & 6"),
            await self.probe_privacy_request_sla(tenant_id, db, "UAE-DPL-ART-13-DSR", "UAE PDPL Articles 13–18", sla_days=30),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "UAE-DPL-ART-20-SEC", "UAE PDPL Article 20"),
            await self.probe_encryption_and_tls(tenant_id, db, "UAE-DPL-ART-20-ENC", "UAE PDPL Article 20(2)(a)"),
            await self.probe_vulnerability_backlog(tenant_id, db, "UAE-DPL-ART-20-RBAC", "UAE PDPL Article 20(2)(d)"),
            await self.probe_audit_logging_active(tenant_id, db, "UAE-DPL-ART-7-AUDIT", "UAE PDPL Article 7"),
            combined,
            self.manual_review_control(
                "UAE-DPL-ART-10-DPO",
                "UAE Data Office DPO Appointment, Article 7(3) Register & DPIA",
                "Verify appointment of Data Protection Officer under Article 10, Article 7(3) processing register, and Article 21 DPIA.",
                "UAE Decree-Law No. 45/2021 Articles 7(3), 10 & 21",
                "UAE DPO Registration Filing, Article 7(3) Processing Register & Signed DPIA",
                tenant_id=tenant_id,
            ),
        ]


async def run_uae_dpl_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await UaeDplFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
