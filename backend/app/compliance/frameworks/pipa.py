"""
[v4.4.0] South Korea PIPA (Personal Information Protection Act, Act No. 19234 as amended)
Covers Resident Registration Number (RRN Modulo-11) & Korean PII discovery, Consent & Collection Notice
(Art. 15), Immediate Destruction Upon Expiry (Art. 21), Technical & Managerial Safeguards (Art. 24-2 / 29:
RRN Encryption, Access Control, Connection Record Retention, Vulnerability Management), 72-Hour PIPC
Breach Notification (Art. 34), Cross-Border Transfer Controls (Art. 28-8, ap-northeast-2), Data Subject
Rights (Art. 35–37), and Chief Privacy Officer Designation (Art. 31 MANUAL_REVIEW).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class PipaFramework(BaseComplianceFramework):
    framework_id = "PIPA"
    name = "Personal Information Protection Act (PIPA)"
    region = "KR"
    jurisdiction = "Republic of Korea"
    category = FrameworkCategory.PRIVACY
    version = "Act No. 19234 (2023 Amendment)"
    effective_from = "2023-09-15"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Personal Information Protection Commission (PIPC) Korea"
    breach_notification_window = "Within 72 Hours to PIPC / KISA & Affected Data Subjects (Art. 34)"
    residency_region = "ap-northeast-2"
    source_reference = "Personal Information Protection Commission (PIPC) Korea, Act No. 19234"
    supported_privacy_rights = ["ACCESS", "DELETE", "CORRECT", "RECTIFY", "RESTRICT", "PORTABILITY"]

    controls = [
        ComplianceControl(
            control_id="PIPA-RRN-DISC",
            framework_id="PIPA",
            title="Article 24-2: Resident Registration Number (RRN) & Korean PII Discovery",
            requirement="Strictly restrict and classify 13-digit Korean Resident Registration Numbers (Modulo-11), Alien Registration Numbers, Passports, and BRNs.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="PIPA Articles 24 & 24-2",
            recommended_action="Ensure South Korea (KR) RRN and PII classifiers are enabled across DLP/DSPM.",
        ),
        ComplianceControl(
            control_id="PIPA-ART-15-CONSENT",
            framework_id="PIPA",
            title="Article 15: Lawful Collection & Granular Data Subject Consent",
            requirement="Obtain informed consent specifying collection purpose, items, and retention period prior to endpoint visual telemetry collection.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PIPA Article 15",
            recommended_action="Enable MonitoringConsentRequired on visually monitored endpoints.",
        ),
        ComplianceControl(
            control_id="PIPA-ART-21-DEST",
            framework_id="PIPA",
            title="Article 21: Irreversible Destruction of Personal Information Upon Retention Expiry",
            requirement="Destroy personal information without delay when the retention period expires or the processing purpose is achieved.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PIPA Article 21",
            recommended_action="Enforce 90-day automated telemetry destruction.",
        ),
        ComplianceControl(
            control_id="PIPA-ART-24-RRN",
            framework_id="PIPA",
            title="Articles 24-2 & 29: Technical Safeguards & RRN Exposure Prevention",
            requirement="Implement protective measures against loss, theft, divulgence, falsification, or damage of RRN and personal data.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="PIPA Articles 24-2(2) & 29",
            recommended_action="Remediate any exposed PII/RRN datastores in DSPM.",
        ),
        ComplianceControl(
            control_id="PIPA-ART-29-ENC",
            framework_id="PIPA",
            title="Article 29 PIPC Standards: Mandatory Encryption of RRN, Passwords & Bio Data",
            requirement="Encrypt Resident Registration Numbers, Unique Identification Info, and credentials at rest and over network transit.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="PIPA Article 29 & PIPC Notification on Technical/Managerial Safeguards Art. 7",
            recommended_action="Enable AES-256 datastore encryption and TLS 1.3 mutual auth.",
        ),
        ComplianceControl(
            control_id="PIPA-ART-29-ACCESS",
            framework_id="PIPA",
            title="Article 29 PIPC Standards: Access Authority Management & Least Privilege",
            requirement="Grant minimum necessary access privileges to personal information handlers and enforce role-based access control.",
            category="ACCESS_CONTROL",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PIPA Article 29 & PIPC Safeguards Notification Art. 4–5",
            recommended_action="Enforce RBAC least-privilege scoping across personal data handlers.",
        ),
        ComplianceControl(
            control_id="PIPA-ART-29-LOGS",
            framework_id="PIPA",
            title="Article 29 PIPC Standards: Tamper-Proof Access Connection Record Keeping",
            requirement="Maintain immutable connection and access logs for personal information processing systems against forgery or alteration.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PIPA Article 29 & PIPC Safeguards Notification Art. 8",
            recommended_action="Ensure AuditLog captures all administrative and personal data operations.",
        ),
        ComplianceControl(
            control_id="PIPA-ART-34-BREACH",
            framework_id="PIPA",
            title="Article 34: 72-Hour Mandatory Data Breach Notification to PIPC/KISA",
            requirement="Notify affected data subjects and report to PIPC or KISA within 72 hours of becoming aware of a personal data leak.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="PIPA Article 34 & Enforcement Decree Art. 40",
            recommended_action="Triage critical security incidents within the 72-hour PIPC reporting SLA.",
        ),
        ComplianceControl(
            control_id="PIPA-ART-28-TRANS",
            framework_id="PIPA",
            title="Article 28-8 & Art. 35–37: Cross-Border Transfer Fencing (ap-northeast-2) & DSRs",
            requirement="Restrict unauthorized overseas transfers outside ap-northeast-2 and fulfill data subject inspection, correction, deletion, and portability requests.",
            category="DATA_RESIDENCY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="PIPA Articles 28-8 & 35–37",
            recommended_action="Enforce ap-northeast-2 sovereign boundary fencing and 10-day DSR fulfillment.",
        ),
        ComplianceControl(
            control_id="PIPA-ART-31-CPO",
            framework_id="PIPA",
            title="Articles 30 & 31: Chief Privacy Officer (CPO) Designation & Privacy Policy Publication",
            requirement="Designate a qualified Chief Privacy Officer (CPO) and publish a statutory Korean-language Privacy Policy disclosing委托 (entrustment) processors.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="PIPA Articles 26, 30 & 31",
            recommended_action="Attach CPO Appointment Letter, Published Privacy Policy, and Processor Entrustment Contracts.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "KR", db, "PIPA-RRN-DISC", "PIPA Art. 24-2"),
            await self.probe_visual_privacy_consent(tenant_id, db, "PIPA-ART-15-CONSENT", "PIPA Article 15"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "PIPA-ART-21-DEST", "PIPA Article 21"),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "PIPA-ART-24-RRN", "PIPA Articles 24-2 & 29"),
            await self.probe_encryption_and_tls(tenant_id, db, "PIPA-ART-29-ENC", "PIPA Article 29"),
            await self.probe_access_control_rbac_mfa(tenant_id, db, "PIPA-ART-29-ACCESS", "PIPA Article 29"),
            await self.probe_audit_logging_active(tenant_id, db, "PIPA-ART-29-LOGS", "PIPA Article 29"),
            await self.probe_incident_response_backlog(tenant_id, db, "PIPA-ART-34-BREACH", "PIPA Article 34"),
            await self.probe_data_residency_fencing(tenant_id, "ap-northeast-2", db, "PIPA-ART-28-TRANS", "PIPA Article 28-8"),
            self.manual_review_control(
                "PIPA-ART-31-CPO",
                "CPO Designation, Korean Privacy Policy & Entrustment Contracts",
                "Verify appointment of an independent Chief Privacy Officer (Art. 31), public Art. 30 Privacy Policy, and Art. 26 processor entrustment agreements.",
                "PIPA Articles 26, 30 & 31",
                "Signed CPO Appointment Resolution, Published Privacy Policy URL & Processor Agreements",
                tenant_id=tenant_id,
            ),
        ]


async def run_pipa_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await PipaFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
