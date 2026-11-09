"""
[v4.4.0] Kenya Data Protection Act, 2019 (Act No. 24 of 2019) & ODPC Regulations 2021
Covers Kenyan National ID & KRA PIN discovery, Duty to Notify & Lawful Consent (Sections 29, 30 & 32),
Data Subject Rights (Sections 26 & 40), Retention Period Limitation (Section 39), Data Protection by
Design & Security Safeguards (Section 41: Encryption, RBAC, Audit Logs, Vulnerability Remediation),
72-Hour ODPC Breach Notification (Section 43), Cross-Border Transfers & Sensitive Data Localization
(Sections 48–50, af-south-1), and Mandatory ODPC Controller/Processor Registration (Section 18 MANUAL_REVIEW).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class KenyaDpaFramework(BaseComplianceFramework):
    framework_id = "KENYA_DPA"
    name = "Kenya Data Protection Act 2019 (Act No. 24)"
    region = "KE"
    jurisdiction = "Republic of Kenya"
    category = FrameworkCategory.PRIVACY
    version = "Act No. 24 of 2019 (ODPC Regs 2021)"
    effective_from = "2019-11-25"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Office of the Data Protection Commissioner (ODPC) Kenya"
    breach_notification_window = "Within 72 Hours to ODPC & In Writing Reasonably Quickly to Data Subjects (Section 43)"
    residency_region = "af-south-1"
    source_reference = "Kenya Gazette Supplement No. 181 (Acts No. 24 of 2019) & Data Protection (General) Regulations 2021"
    supported_privacy_rights = ["ACCESS", "DELETE", "CORRECT", "RECTIFY", "RESTRICT", "OBJECT", "PORTABILITY"]

    controls = [
        ComplianceControl(
            control_id="KE-DPA-PII-DISC",
            framework_id="KENYA_DPA",
            title="Sections 2 & 25: Kenyan National ID, KRA PIN & Sensitive PII Discovery",
            requirement="Discover and classify Kenyan 7/8-digit National IDs, KRA PINs (A000000000Z), Passports, and Mobile M-Pesa identifiers.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Kenya Data Protection Act 2019 Sections 2 & 25",
            recommended_action="Ensure Kenya (KE) PII classifiers are active across DLP/DSPM.",
        ),
        ComplianceControl(
            control_id="KE-DPA-SEC-39-RET",
            framework_id="KENYA_DPA",
            title="Section 39: Retention of Personal Data & Periodic Deletion Review",
            requirement="Retain personal data only as long as reasonably necessary to satisfy the purpose, then delete, erase, anonymize, or pseudonymize.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Kenya Data Protection Act 2019 Section 39",
            recommended_action="Enforce 90-day automated telemetry pruning.",
        ),
        ComplianceControl(
            control_id="KE-DPA-SEC-29-NOTICE",
            framework_id="KENYA_DPA",
            title="Sections 29, 30 & 32: Duty to Notify & Express Consent Governance",
            requirement="Inform data subjects prior to collection and enforce affirmative consent banners on visually monitored endpoints.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Kenya Data Protection Act 2019 Sections 29, 30 & 32",
            recommended_action="Enable MonitoringConsentRequired notice banners on visually monitored endpoints.",
        ),
        ComplianceControl(
            control_id="KE-DPA-SEC-26-DSR",
            framework_id="KENYA_DPA",
            title="Sections 26, 38 & 40: Rights of Data Subject (Access, Rectification, Deletion — 7/14-Day ODPC SLA)",
            requirement="Fulfill access (7 days), rectification (14 days), erasure (14 days), and portability (30 days) requests per ODPC General Regulations 2021.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Kenya DPA Sections 26, 38, 40 & General Regulations 2021 Regs 9–13",
            recommended_action="Fulfill open Kenyan DSR requests within ODPC statutory windows.",
        ),
        ComplianceControl(
            control_id="KE-DPA-SEC-41-SEC",
            framework_id="KENYA_DPA",
            title="Section 41: Data Protection by Design or Default & Exposure Prevention",
            requirement="Implement appropriate technical and organizational measures designed to implement data protection principles and prevent exposure.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="Kenya Data Protection Act 2019 Section 41",
            recommended_action="Remediate exposed Kenyan PII datastores in DSPM.",
        ),
        ComplianceControl(
            control_id="KE-DPA-SEC-41-ENC",
            framework_id="KENYA_DPA",
            title="Section 41(4): Pseudonymization & Encryption of Personal Data",
            requirement="Encrypt personal data at rest (AES-256) and protect telemetry in transit via TLS 1.3.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Kenya Data Protection Act 2019 Section 41(4)",
            recommended_action="Enable encryption at rest across all datastores.",
        ),
        ComplianceControl(
            control_id="KE-DPA-SEC-41-RBAC",
            framework_id="KENYA_DPA",
            title="Section 41 & Reg 25: Access Control & Vulnerability Remediation",
            requirement="Restrict access to authorized personnel via RBAC and remediate software vulnerabilities.",
            category="VULNERABILITY_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Kenya DPA Section 41 & General Regulations 2021 Part V",
            recommended_action="Remediate High and Critical endpoint software vulnerabilities.",
        ),
        ComplianceControl(
            control_id="KE-DPA-REG-AUDIT",
            framework_id="KENYA_DPA",
            title="ODPC General Regulations Reg 27: Processing Logs & Audit Trail Integrity",
            requirement="Maintain immutable processing logs recording collection, alteration, consultation, disclosure, and erasure events.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Data Protection (General) Regulations 2021 Regulation 27",
            recommended_action="Maintain tamper-evident AuditLog records.",
        ),
        ComplianceControl(
            control_id="KE-DPA-SEC-43-BREACH",
            framework_id="KENYA_DPA",
            title="Section 43 & Sections 48–50: 72-Hour ODPC Breach Notice & Cross-Border Fencing (af-south-1)",
            requirement="Notify the Data Commissioner within 72 hours of unauthorized access (s43) and enforce sovereign localization/transfer safeguards (s48–50, af-south-1).",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="Kenya Data Protection Act 2019 Sections 43, 48 & 50",
            recommended_action="Triage critical incidents within 72h and enforce af-south-1 fencing.",
        ),
        ComplianceControl(
            control_id="KE-DPA-SEC-18-REG",
            framework_id="KENYA_DPA",
            title="Sections 18, 24 & 31: Mandatory ODPC Controller/Processor Registration, DPO & DPIA",
            requirement="Obtain and renew Certificate of Registration from the ODPC (Section 18 / Registration Regulations 2021), designate a DPO (s24), and conduct Section 31 DPIAs.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="Kenya Data Protection Act 2019 Sections 18, 24 & 31",
            recommended_action="Attach Active ODPC Certificate of Registration (2-year validity), DPO Filing, and Section 31 DPIA.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        res_check = await self.probe_data_residency_fencing(tenant_id, "af-south-1", db, "KE-DPA-SEC-43-BREACH", "Kenya DPA Sections 48 & 50")
        inc_check = await self.probe_incident_response_backlog(tenant_id, db, "KE-DPA-SEC-43-BREACH", "Kenya DPA Section 43")
        combined = inc_check if inc_check.status.value != "PASS" else res_check
        combined.control_id = "KE-DPA-SEC-43-BREACH"

        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "KE", db, "KE-DPA-PII-DISC", "Kenya DPA Sections 2 & 25"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "KE-DPA-SEC-39-RET", "Kenya DPA Section 39"),
            await self.probe_visual_privacy_consent(tenant_id, db, "KE-DPA-SEC-29-NOTICE", "Kenya DPA Sections 29 & 32"),
            await self.probe_privacy_request_sla(tenant_id, db, "KE-DPA-SEC-26-DSR", "Kenya DPA Sections 26 & 40", sla_days=14),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "KE-DPA-SEC-41-SEC", "Kenya DPA Section 41"),
            await self.probe_encryption_and_tls(tenant_id, db, "KE-DPA-SEC-41-ENC", "Kenya DPA Section 41(4)"),
            await self.probe_vulnerability_backlog(tenant_id, db, "KE-DPA-SEC-41-RBAC", "Kenya DPA Section 41"),
            await self.probe_audit_logging_active(tenant_id, db, "KE-DPA-REG-AUDIT", "ODPC General Regs Reg 27"),
            combined,
            self.manual_review_control(
                "KE-DPA-SEC-18-REG",
                "Mandatory ODPC Controller/Processor Registration & Section 31 DPIA",
                "Verify valid Certificate of Registration issued by the Office of the Data Protection Commissioner (ODPC) under Section 18.",
                "Kenya Data Protection Act 2019 Sections 18, 24 & 31",
                "Valid ODPC Certificate of Registration, DPO Notification & Section 31 DPIA",
                tenant_id=tenant_id,
            ),
        ]


async def run_kenya_dpa_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await KenyaDpaFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
