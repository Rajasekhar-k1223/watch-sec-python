"""
[v4.4.0] Japan APPI (Act on the Protection of Personal Information, Act No. 57 of 2003 as amended)
Covers My Number (12-digit Modulo-11) & Japanese PII discovery, Purpose Specification & Acquisition Notice
(Art. 17/21), Erasure & Storage Limitation (Art. 22), Security Control Measures (Art. 23: Encryption,
RBAC, Audit Logs, Vulnerability Hygiene), PPC Mandatory Breach Reporting & Individual Notification (Art. 26),
Cross-Border Transfer Restrictions (Art. 28, ap-northeast-1), Retained Personal Data Disclosure/Correction/
Suspension DSRs (Art. 33–35), and Third-Party Provision Record-Keeping (Art. 27/29/30 MANUAL_REVIEW).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class AppiFramework(BaseComplianceFramework):
    framework_id = "APPI"
    name = "Act on the Protection of Personal Information (APPI)"
    region = "JP"
    jurisdiction = "Japan"
    category = FrameworkCategory.PRIVACY
    version = "Act No. 57 of 2003 (2022 Amendment)"
    effective_from = "2022-04-01"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Personal Information Protection Commission (PPC) Japan"
    breach_notification_window = "Prompt Preliminary Report (3–5 Days) & Definitive Report Within 30/60 Days to PPC (Art. 26)"
    residency_region = "ap-northeast-1"
    source_reference = "Personal Information Protection Commission (PPC) Japan, Act No. 57 of 2003"
    supported_privacy_rights = ["ACCESS", "DELETE", "CORRECT", "RECTIFY", "RESTRICT", "OPT_OUT"]

    controls = [
        ComplianceControl(
            control_id="APPI-PII-DISC",
            framework_id="APPI",
            title="Article 2(1) & My Number Act: Japanese Personal Information & Individual Number Discovery",
            requirement="Identify and classify Japanese personal data including 12-digit My Number (Modulo-11), Corporate Numbers, Passports, and Zairyu Cards.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="APPI Article 2 & My Number Act Article 2(5)",
            recommended_action="Ensure Japan (JP) PII classifiers are enabled across DLP/DSPM.",
        ),
        ComplianceControl(
            control_id="APPI-ART-21-NOTICE",
            framework_id="APPI",
            title="Articles 17 & 21: Specification & Notification of Purpose of Utilization",
            requirement="Specify purpose of utilization as explicitly as possible and notify or publicly announce purpose upon acquisition on monitored endpoints.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.MEDIUM,
            legal_reference="APPI Articles 17 & 21",
            recommended_action="Enforce MonitoringConsentRequired notice banners on visually monitored endpoints.",
        ),
        ComplianceControl(
            control_id="APPI-ART-19-MIN",
            framework_id="APPI",
            title="Article 22 (formerly Art. 19): Data Accuracy & Deletion Without Delay",
            requirement="Strive to keep personal data accurate and delete personal data without delay when utilization is no longer necessary.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="APPI Article 22",
            recommended_action="Enforce 90-day automated telemetry retention pruning.",
        ),
        ComplianceControl(
            control_id="APPI-ART-23-SEC",
            framework_id="APPI",
            title="Article 23: Technical Security Control Measures & DSPM Exposure Prevention",
            requirement="Take necessary and appropriate technical and organizational measures for preventing leakage, loss, or damage of personal data.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="APPI Article 23 & My Number Act Article 12",
            recommended_action="Remediate exposed Japanese PII datastores in DSPM.",
        ),
        ComplianceControl(
            control_id="APPI-ART-23-ENC",
            framework_id="APPI",
            title="Article 23 PPC Guidelines: Cryptographic Protection at Rest & TLS 1.3",
            requirement="Encrypt stored personal data and My Number records at rest and protect communications via TLS 1.3.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="APPI Article 23 (PPC Technical Safeguards Guidelines)",
            recommended_action="Enable AES-256 encryption across all datastores.",
        ),
        ComplianceControl(
            control_id="APPI-ART-24-ACCESS",
            framework_id="APPI",
            title="Articles 23 & 24: Employee Supervision & Least-Privilege RBAC Access",
            requirement="Exercise necessary supervision over employees handling personal data via RBAC role scoping and access controls.",
            category="ACCESS_CONTROL",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="APPI Articles 23 & 24",
            recommended_action="Enforce tenant-isolated RBAC least-privilege roles.",
        ),
        ComplianceControl(
            control_id="APPI-ART-23-AUDIT",
            framework_id="APPI",
            title="Article 23 PPC Guidelines: Information System Operation & Access Logging",
            requirement="Record and retain tamper-evident access logs to verify absence of unauthorized handling of personal data.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="APPI Article 23 (PPC Guidelines)",
            recommended_action="Maintain continuous tamper-evident AuditLog records.",
        ),
        ComplianceControl(
            control_id="APPI-ART-26-PPC",
            framework_id="APPI",
            title="Article 26: PPC Mandatory Data Leakage Reporting & Individual Notice",
            requirement="Report data leakage incidents affecting Special Care-Required PII, My Number, improper purpose, or >1,000 subjects to the PPC and notify individuals.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="APPI Article 26 & Enforcement Rules Art. 7–8",
            recommended_action="Triage critical security incidents within PPC preliminary 3–5 day reporting window.",
        ),
        ComplianceControl(
            control_id="APPI-ART-28-TRANS",
            framework_id="APPI",
            title="Article 28 & Art. 33–35: Cross-Border Transfer Fencing (ap-northeast-1) & Retained Data DSRs",
            requirement="Enforce sovereign boundary fencing to ap-northeast-1 for foreign transfers and fulfill disclosure, correction, and utilization suspension requests.",
            category="DATA_RESIDENCY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="APPI Articles 28 & 33–35",
            recommended_action="Enforce ap-northeast-1 sovereign boundary fencing.",
        ),
        ComplianceControl(
            control_id="APPI-ART-20-CONSENT",
            framework_id="APPI",
            title="Articles 27, 29 & 30: Third-Party Provision Consent & Statutory Confirmation Ledger",
            requirement="Obtain advance opt-in consent before third-party provision and maintain statutory trace records of provision dates, recipients, and source confirmation.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="APPI Articles 27, 29 & 30",
            recommended_action="Maintain Statutory Third-Party Data Provision Logbook and Foreign Equivalence Disclosures.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "JP", db, "APPI-PII-DISC", "APPI Art. 2 & My Number Act"),
            await self.probe_visual_privacy_consent(tenant_id, db, "APPI-ART-21-NOTICE", "APPI Art. 17 & 21"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "APPI-ART-19-MIN", "APPI Article 22"),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "APPI-ART-23-SEC", "APPI Article 23"),
            await self.probe_encryption_and_tls(tenant_id, db, "APPI-ART-23-ENC", "APPI Article 23"),
            await self.probe_access_control_rbac_mfa(tenant_id, db, "APPI-ART-24-ACCESS", "APPI Articles 23 & 24"),
            await self.probe_audit_logging_active(tenant_id, db, "APPI-ART-23-AUDIT", "APPI Article 23"),
            await self.probe_incident_response_backlog(tenant_id, db, "APPI-ART-26-PPC", "APPI Article 26"),
            await self.probe_data_residency_fencing(tenant_id, "ap-northeast-1", db, "APPI-ART-28-TRANS", "APPI Article 28"),
            self.manual_review_control(
                "APPI-ART-20-CONSENT",
                "Third-Party Provision Registry & Foreign Equivalence Disclosures",
                "Verify statutory Article 29/30 third-party provision and receipt ledgers and Article 28 foreign legal regime disclosures.",
                "APPI Articles 27, 28(2), 29 & 30",
                "Statutory Third-Party Data Provision Logbook & PPC Opt-Out Filing Records",
                tenant_id=tenant_id,
            ),
        ]


async def run_appi_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await AppiFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
