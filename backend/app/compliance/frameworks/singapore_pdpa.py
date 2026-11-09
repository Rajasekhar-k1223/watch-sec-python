"""
[v4.4.0] Singapore PDPA (Personal Data Protection Act 2012, as amended 2020)
Covers NRIC/FIN (Modulo-11) & Singapore PII discovery (PDPC Advisory Guidelines on NRIC),
Consent & Notification Obligations (s13–20), Access & Correction Obligations (s21–22),
Protection Obligation (s24: Encryption, RBAC, Audit Logs, Vulnerability Management),
Retention Limitation Obligation (s25), Transfer Limitation Obligation (s26, ap-southeast-1),
Mandatory Data Breach Notification Within 3 Calendar Days to PDPC (Part VIA s26A–26E),
and DPO Designation / ACRA BizFile+ Registration (s11(3) MANUAL_REVIEW).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class SingaporePdpaFramework(BaseComplianceFramework):
    framework_id = "SINGAPORE_PDPA"
    name = "Singapore Personal Data Protection Act 2012 (PDPA)"
    region = "SG"
    jurisdiction = "Republic of Singapore"
    category = FrameworkCategory.PRIVACY
    version = "Act 26 of 2012 (2020 Amendment)"
    effective_from = "2021-02-01"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Personal Data Protection Commission (PDPC) Singapore"
    breach_notification_window = "Within 3 Calendar Days of Assessment to PDPC (s26D)"
    residency_region = "ap-southeast-1"
    source_reference = "Personal Data Protection Commission (PDPC) Singapore, Act 26 of 2012"
    supported_privacy_rights = ["ACCESS", "CORRECT", "RECTIFY", "OPT_OUT", "PORTABILITY"]

    controls = [
        ComplianceControl(
            control_id="SG-PDPA-NRIC-DISC",
            framework_id="SINGAPORE_PDPA",
            title="PDPC NRIC Advisory Guidelines: NRIC/FIN, UEN & Singapore PII Discovery",
            requirement="Discover and protect Singapore NRIC/FIN identifiers (S/T/F/G/M Modulo-11), UENs, Passports, and Mobile numbers.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PDPA Part IV & PDPC Advisory Guidelines on NRIC Numbers",
            recommended_action="Ensure Singapore (SG) PII classifiers are enabled across DLP/DSPM.",
        ),
        ComplianceControl(
            control_id="SG-PDPA-CONSENT",
            framework_id="SINGAPORE_PDPA",
            title="Sections 13–20: Consent, Purpose Limitation & Notification Obligations",
            requirement="Notify individuals of purposes and obtain consent prior to collecting visual endpoint telemetry.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PDPA 2012 Sections 13–15, 18 & 20",
            recommended_action="Enforce MonitoringConsentRequired banners on visually monitored endpoints.",
        ),
        ComplianceControl(
            control_id="SG-PDPA-ACCESS-CORR",
            framework_id="SINGAPORE_PDPA",
            title="Sections 21 & 22: Access, Correction & Consent Withdrawal Obligation",
            requirement="Fulfill individual requests to access personal data, correct errors, and withdraw consent within 30 calendar days.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PDPA 2012 Sections 16, 21 & 22",
            recommended_action="Fulfill open Singapore PDPA DSR requests within 30 days.",
        ),
        ComplianceControl(
            control_id="SG-PDPA-PROTECTION",
            framework_id="SINGAPORE_PDPA",
            title="Section 24: Protection Obligation — Sensitive Data Exposure Safeguards",
            requirement="Make reasonable security arrangements to prevent unauthorized access, collection, use, disclosure, copying, modification, or disposal.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="PDPA 2012 Section 24",
            recommended_action="Remediate exposed NRIC/FIN and PII datastores in DSPM.",
        ),
        ComplianceControl(
            control_id="SG-PDPA-ENC",
            framework_id="SINGAPORE_PDPA",
            title="Section 24 PDPC Guide to Securing Personal Data: Encryption at Rest & Transit",
            requirement="Encrypt stored personal data and NRIC records at rest (AES-256) and enforce TLS 1.3 in transit.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PDPA 2012 Section 24 (PDPC Technical Security Guide)",
            recommended_action="Enable encryption at rest across all datastores.",
        ),
        ComplianceControl(
            control_id="SG-PDPA-ACCESS-CTRL",
            framework_id="SINGAPORE_PDPA",
            title="Section 24: Role-Based Access Control & Administrative Audit Trail",
            requirement="Enforce least-privilege RBAC and maintain immutable administrative and data access audit logs.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PDPA 2012 Section 24",
            recommended_action="Maintain tamper-evident AuditLog records and RBAC role boundaries.",
        ),
        ComplianceControl(
            control_id="SG-PDPA-VULN",
            framework_id="SINGAPORE_PDPA",
            title="Section 24: Patch Management & Endpoint Vulnerability Remediation",
            requirement="Maintain up-to-date security patches across systems processing personal data (PDPC frequent enforcement area).",
            category="VULNERABILITY_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PDPA 2012 Section 24",
            recommended_action="Remediate High and Critical software vulnerabilities on endpoints.",
        ),
        ComplianceControl(
            control_id="SG-PDPA-RETENTION",
            framework_id="SINGAPORE_PDPA",
            title="Section 25: Retention Limitation Obligation",
            requirement="Cease to retain documents containing personal data or anonymize them as soon as retention is no longer necessary.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PDPA 2012 Section 25",
            recommended_action="Enforce 90-day automated telemetry pruning.",
        ),
        ComplianceControl(
            control_id="SG-PDPA-BREACH",
            framework_id="SINGAPORE_PDPA",
            title="Part VIA (s26A–26E) & s26: 3-Day PDPC Breach Notification & Transfer Limitation (ap-southeast-1)",
            requirement="Notify PDPC within 3 calendar days of assessing a notifiable data breach (>=500 individuals or significant harm) and enforce ap-southeast-1 transfer fencing.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="PDPA 2012 Sections 26 & 26A–26E",
            recommended_action="Triage critical incidents within 3 days and enforce ap-southeast-1 fencing.",
        ),
        ComplianceControl(
            control_id="SG-PDPA-DPO",
            framework_id="SINGAPORE_PDPA",
            title="Sections 11(3) & 12: Accountability Obligation — DPO Appointment & ACRA BizFile+ Publication",
            requirement="Designate at least one Data Protection Officer (DPO), make business contact info public, and develop documented Data Protection Policies.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="PDPA 2012 Sections 11(3), 11(5) & 12",
            recommended_action="Register DPO via ACRA BizFile+ and attach Data Protection Policy Manual.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        # Evaluate residency + incident checks cleanly across the 10 controls
        res_check = await self.probe_data_residency_fencing(tenant_id, "ap-southeast-1", db, "SG-PDPA-BREACH", "PDPA s26 & s26D")
        inc_check = await self.probe_incident_response_backlog(tenant_id, db, "SG-PDPA-BREACH", "PDPA Part VIA s26A–26E")
        combined_breach_transfer = inc_check if inc_check.status.value != "PASS" else res_check
        combined_breach_transfer.control_id = "SG-PDPA-BREACH"

        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "SG", db, "SG-PDPA-NRIC-DISC", "PDPA NRIC Guidelines"),
            await self.probe_visual_privacy_consent(tenant_id, db, "SG-PDPA-CONSENT", "PDPA Sections 13–20"),
            await self.probe_privacy_request_sla(tenant_id, db, "SG-PDPA-ACCESS-CORR", "PDPA Sections 21 & 22", sla_days=30),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "SG-PDPA-PROTECTION", "PDPA Section 24"),
            await self.probe_encryption_and_tls(tenant_id, db, "SG-PDPA-ENC", "PDPA Section 24"),
            await self.probe_audit_logging_active(tenant_id, db, "SG-PDPA-ACCESS-CTRL", "PDPA Section 24"),
            await self.probe_vulnerability_backlog(tenant_id, db, "SG-PDPA-VULN", "PDPA Section 24"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "SG-PDPA-RETENTION", "PDPA Section 25"),
            combined_breach_transfer,
            self.manual_review_control(
                "SG-PDPA-DPO",
                "Accountability Obligation: DPO Appointment & ACRA Registration",
                "Verify appointment of Data Protection Officer (s11(3)), public contact details, and PDPC Data Protection Management Programme (DPMP).",
                "PDPA 2012 Sections 11(3) & 12",
                "ACRA BizFile+ DPO Filing Receipt & Data Protection Policy Document",
                tenant_id=tenant_id,
            ),
        ]


async def run_singapore_pdpa_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await SingaporePdpaFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
