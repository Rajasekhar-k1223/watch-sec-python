"""
[v4.4.0] State of Qatar Personal Data Privacy Protection Law (PDPPL, Law No. 13 of 2016)
Covers 11-digit Qatari ID (QID) & QA IBAN discovery, Transparency, Honesty & Retention Limitation
(Art. 3, 4 & 11), Individual Rights (Art. 4–7), Administrative, Technical & Financial Precautions
(Art. 11 & 13: Encryption, RBAC, Audit Logs, Processor Precautions), 72-Hour NCSA National Privacy
Department Breach Notification (Art. 14), Cross-Border Flow Protection (Art. 15, me-central-1),
and NCSA Special Nature Personal Data Processing Permit (Art. 16 MANUAL_REVIEW).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class QatarPdplFramework(BaseComplianceFramework):
    framework_id = "QATAR_PDPL"
    name = "Qatar Personal Data Privacy Protection Law (Law No. 13 of 2016)"
    region = "QA"
    jurisdiction = "State of Qatar"
    category = FrameworkCategory.PRIVACY
    version = "Law No. 13 of 2016 (NCSA Guidelines)"
    effective_from = "2017-05-29"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "National Cyber Security Agency (NCSA) — National Data Privacy Office Qatar"
    breach_notification_window = "Within 72 Hours to NCSA National Data Privacy Office & Affected Individuals (Art. 14)"
    residency_region = "me-central-1"
    source_reference = "State of Qatar Official Gazette Issue No. 15 (2016), Law No. 13 of 2016"
    supported_privacy_rights = ["ACCESS", "DELETE", "CORRECT", "RECTIFY", "OBJECT", "OPT_OUT"]

    controls = [
        ComplianceControl(
            control_id="QATAR-PDPL-QID-DISC",
            framework_id="QATAR_PDPL",
            title="Articles 1 & 16: Qatari ID (QID), QA IBAN & Special Nature Data Discovery",
            requirement="Discover and classify 11-digit Qatari Identification Numbers (QID), QA IBANs, Passports, and Mobile numbers.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Qatar Law No. 13/2016 Articles 1 & 16",
            recommended_action="Ensure Qatar (QA) PII classifiers are active across DLP/DSPM.",
        ),
        ComplianceControl(
            control_id="QATAR-PDPL-ART-3-MIN",
            framework_id="QATAR_PDPL",
            title="Articles 3 & 11(2): Legitimate Purpose & Retention Period Limitation",
            requirement="Do not keep personal data beyond the period necessary to fulfill the legitimate purpose for which it was collected.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Qatar Law No. 13/2016 Articles 3 & 11(2)",
            recommended_action="Enforce 90-day automated telemetry pruning.",
        ),
        ComplianceControl(
            control_id="QATAR-PDPL-ART-4-CONSENT",
            framework_id="QATAR_PDPL",
            title="Articles 4 & 9: Explicit Prior Individual Consent & Comprehensive Disclosure",
            requirement="Process personal data only after obtaining explicit consent and providing Article 9 prior disclosures on monitored endpoints.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Qatar Law No. 13/2016 Articles 4 & 9",
            recommended_action="Enable MonitoringConsentRequired notice banners on visually monitored endpoints.",
        ),
        ComplianceControl(
            control_id="QATAR-PDPL-ART-5-DSR",
            framework_id="QATAR_PDPL",
            title="Articles 5–7: Individual Rights to Withdraw Consent, Object, Erase, Review & Correct",
            requirement="Enable individuals to review, copy, correct, erase, and withdraw consent for personal data processing.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Qatar Law No. 13/2016 Articles 5, 6 & 7",
            recommended_action="Fulfill open Qatar PDPPL individual rights requests within 30 days.",
        ),
        ComplianceControl(
            control_id="QATAR-PDPL-ART-11-SEC",
            framework_id="QATAR_PDPL",
            title="Articles 11(5) & 13: Administrative, Technical & Financial Security Precautions",
            requirement="Take precautions necessary to protect personal data against loss, damage, modification, disclosure, or illegal access.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="Qatar Law No. 13/2016 Articles 11(5) & 13",
            recommended_action="Remediate exposed QID and PII datastores in DSPM.",
        ),
        ComplianceControl(
            control_id="QATAR-PDPL-ART-13-ENC",
            framework_id="QATAR_PDPL",
            title="Article 13 NCSA Guidelines: Cryptographic Protection at Rest & TLS 1.3",
            requirement="Protect personal data via strong encryption at rest (AES-256) and TLS 1.3 in transit.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Qatar Law No. 13/2016 Article 13 (NCSA Technical Controls)",
            recommended_action="Enable encryption at rest across all datastores.",
        ),
        ComplianceControl(
            control_id="QATAR-PDPL-ART-13-VULN",
            framework_id="QATAR_PDPL",
            title="Articles 11 & 13: Internal System Audits, RBAC & Vulnerability Management",
            requirement="Conduct comprehensive audits and reviews of privacy protection compliance and remediate endpoint vulnerabilities.",
            category="VULNERABILITY_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Qatar Law No. 13/2016 Articles 11(1) & 13",
            recommended_action="Remediate High and Critical endpoint software vulnerabilities.",
        ),
        ComplianceControl(
            control_id="QATAR-PDPL-ART-11-AUDIT",
            framework_id="QATAR_PDPL",
            title="Article 11(4): Processor Supervision & Tamper-Evident Audit Logging",
            requirement="Verify processor compliance and maintain immutable audit logs of personal data operations.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Qatar Law No. 13/2016 Article 11(4)",
            recommended_action="Maintain tamper-evident AuditLog records.",
        ),
        ComplianceControl(
            control_id="QATAR-PDPL-ART-14-BREACH",
            framework_id="QATAR_PDPL",
            title="Article 14 & Article 15: 72-Hour NCSA Breach Notice & Cross-Border Flow Controls (me-central-1)",
            requirement="Notify the Competent Department (NCSA) and individuals of any personal data breach causing serious harm within 72 hours and enforce me-central-1 boundary controls.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="Qatar Law No. 13/2016 Articles 14 & 15",
            recommended_action="Triage critical security incidents within 72h and enforce me-central-1 fencing.",
        ),
        ComplianceControl(
            control_id="QATAR-PDPL-ART-16-SPEC",
            framework_id="QATAR_PDPL",
            title="Articles 11(3), 16 & 22: NCSA Permit for Personal Data of Special Nature & Direct Marketing Opt-In",
            requirement="Obtain prior permit from the NCSA Competent Department before processing Personal Data of a Special Nature (health, children, criminal, religious, biometric) under Article 16.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="Qatar Law No. 13/2016 Articles 11(3), 16 & 22",
            recommended_action="Attach NCSA Article 16 Special Nature Data Processing Permit and Record of Processing Activities.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        res_check = await self.probe_data_residency_fencing(tenant_id, "me-central-1", db, "QATAR-PDPL-ART-14-BREACH", "Qatar PDPPL Article 15")
        inc_check = await self.probe_incident_response_backlog(tenant_id, db, "QATAR-PDPL-ART-14-BREACH", "Qatar PDPPL Article 14")
        combined = inc_check if inc_check.status.value != "PASS" else res_check
        combined.control_id = "QATAR-PDPL-ART-14-BREACH"

        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "QA", db, "QATAR-PDPL-QID-DISC", "Qatar Law 13/2016 Art. 1 & 16"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "QATAR-PDPL-ART-3-MIN", "Qatar Law 13/2016 Art. 3 & 11(2)"),
            await self.probe_visual_privacy_consent(tenant_id, db, "QATAR-PDPL-ART-4-CONSENT", "Qatar Law 13/2016 Art. 4 & 9"),
            await self.probe_privacy_request_sla(tenant_id, db, "QATAR-PDPL-ART-5-DSR", "Qatar Law 13/2016 Art. 5–7", sla_days=30),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "QATAR-PDPL-ART-11-SEC", "Qatar Law 13/2016 Art. 11 & 13"),
            await self.probe_encryption_and_tls(tenant_id, db, "QATAR-PDPL-ART-13-ENC", "Qatar Law 13/2016 Art. 13"),
            await self.probe_vulnerability_backlog(tenant_id, db, "QATAR-PDPL-ART-13-VULN", "Qatar Law 13/2016 Art. 11 & 13"),
            await self.probe_audit_logging_active(tenant_id, db, "QATAR-PDPL-ART-11-AUDIT", "Qatar Law 13/2016 Art. 11(4)"),
            combined,
            self.manual_review_control(
                "QATAR-PDPL-ART-16-SPEC",
                "NCSA Article 16 Special Nature Data Permit & ROPA",
                "Verify NCSA National Data Privacy Office permit for processing Personal Data of a Special Nature under Article 16.",
                "Qatar Law No. 13/2016 Articles 11, 16 & 22",
                "NCSA Article 16 Processing Permit & Privacy Management System Records",
                tenant_id=tenant_id,
            ),
        ]


async def run_qatar_pdpl_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await QatarPdplFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
