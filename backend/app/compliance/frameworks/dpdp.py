"""
[v4.4.0] India Digital Personal Data Protection Act 2023 (DPDP Act 2023)
Implements complete technical controls for data inventory, Indian PII discovery
(Aadhaar Verhoeff, PAN, Voter ID, Passport, DL, Mobile, IFSC, Bank Account, UPI),
purpose limitation, minimization, retention, deletion, access control, consent/notice,
Data Principal request workflows, breach notification (DPBI & CERT-In), processor tracking,
cross-border data residency (ap-south-1), audit logging, and encryption.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class DpdpFramework(BaseComplianceFramework):
    framework_id = "DPDP_INDIA"
    name = "Digital Personal Data Protection Act 2023 (DPDP)"
    region = "IN"
    jurisdiction = "Republic of India"
    category = FrameworkCategory.PRIVACY
    version = "Act No. 22 of 2023"
    effective_from = "2023-08-11"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Data Protection Board of India (DPBI) & MeitY"
    breach_notification_window = "Without Delay to DPBI & CERT-In 6-Hour Cyber Directive (Sec. 8(6))"
    residency_region = "ap-south-1"
    source_reference = "The Gazette of India, CG-DL-E-12082023-248045, Act No. 22 of 2023"
    supported_privacy_rights = ["ACCESS", "DELETE", "CORRECT", "RECTIFY", "OPT_OUT"]

    controls = [
        ComplianceControl(
            control_id="DPDP-SEC-4-INV",
            framework_id="DPDP_INDIA",
            title="Digital Personal Data Inventory & Indian PII Discovery (Aadhaar/PAN/EPIC)",
            requirement="Discover and inventory Indian digital personal identifiers (Aadhaar, PAN, Voter ID, Passport, DL, Mobile, IFSC, Bank, UPI).",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="DPDP Act 2023 Section 4 & Section 8",
            recommended_action="Ensure all 9 Indian PII classifiers are active in DLP and DSPM.",
        ),
        ComplianceControl(
            control_id="DPDP-SEC-6-CONSENT",
            framework_id="DPDP_INDIA",
            title="Notice, Purpose Limitation & Monitoring Consent Governance (Sec. 5 & 6)",
            requirement="Process personal data only for lawful purposes for which the Data Principal has given free, specific, informed, unconditional consent or legitimate use notice.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="DPDP Act 2023 Section 5, Section 6 & Section 7",
            recommended_action="Enforce consent notice flags on monitored endpoints.",
        ),
        ComplianceControl(
            control_id="DPDP-SEC-8-5-SAFEGUARDS",
            framework_id="DPDP_INDIA",
            title="Reasonable Security Safeguards Against Personal Data Breach (Sec. 8(5))",
            requirement="Data Fiduciary shall protect personal data in its possession or control by taking reasonable security safeguards to prevent personal data breach.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="DPDP Act 2023 Section 8(5)",
            recommended_action="Remediate any exposed PII datastores in DSPM.",
            automated_remediation_available=True,
        ),
        ComplianceControl(
            control_id="DPDP-SEC-8-5-ENC",
            framework_id="DPDP_INDIA",
            title="Encryption at Rest & TLS 1.3 Transport Protection (Sec. 8(5))",
            requirement="Protect digital personal data through cryptographic storage and mutual TLS transport encryption.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="DPDP Act 2023 Section 8(5)",
            recommended_action="Encrypt all datastores at rest and enforce mTLS.",
        ),
        ComplianceControl(
            control_id="DPDP-SEC-8-5-IAM",
            framework_id="DPDP_INDIA",
            title="Access Control, Least Privilege & Access Monitoring (Sec. 8(5))",
            requirement="Enforce role-based access control and continuous monitoring over systems processing Data Principal records.",
            category="ACCESS_CONTROL",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="DPDP Act 2023 Section 8(5)",
            recommended_action="Enforce RBAC role boundaries and privileged access logging.",
        ),
        ComplianceControl(
            control_id="DPDP-SEC-8-5-AUDIT",
            framework_id="DPDP_INDIA",
            title="Tamper-Evident Audit Logging & Accountability (Sec. 8(5))",
            requirement="Maintain immutable audit trails of administrative and personal data access operations.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="DPDP Act 2023 Section 8(5) & CERT-In Directions 2022",
            recommended_action="Ensure continuous AuditLog recording for tenant operations.",
        ),
        ComplianceControl(
            control_id="DPDP-SEC-8-6-BREACH",
            framework_id="DPDP_INDIA",
            title="Personal Data Breach Evidence & DPBI / Data Principal Notification (Sec. 8(6))",
            requirement="Intimate the Data Protection Board of India and each affected Data Principal in the event of a personal data breach.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="DPDP Act 2023 Section 8(6)",
            recommended_action="Triage critical incidents immediately to meet DPBI & CERT-In SLAs.",
        ),
        ComplianceControl(
            control_id="DPDP-SEC-8-7-RETENTION",
            framework_id="DPDP_INDIA",
            title="Data Minimization, Retention Expiry & Automated Erasure (Sec. 8(7))",
            requirement="Erase personal data upon withdrawal of consent or as soon as it is reasonable to assume that the specified purpose is no longer being served.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="DPDP Act 2023 Section 8(7)",
            recommended_action="Enforce 90-day automated telemetry pruning and erasure procedures.",
        ),
        ComplianceControl(
            control_id="DPDP-SEC-11-14-RIGHTS",
            framework_id="DPDP_INDIA",
            title="Data Principal Rights: Access, Correction, Erasure & Grievance Workflow (Sec. 11-14)",
            requirement="Provide accessible workflows for Data Principals to obtain data summaries, correct/update/erase personal data, and obtain grievance redressal.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="DPDP Act 2023 Sections 11, 12, 13 & 14",
            recommended_action="Fulfill Data Principal requests within statutory SLA.",
        ),
        ComplianceControl(
            control_id="DPDP-SEC-8-2-PROCESSOR",
            framework_id="DPDP_INDIA",
            title="Data Processor & Vendor Supply Chain Integrity (Sec. 8(2))",
            requirement="Track and verify integrity of software and Data Processor integrations handling personal data on behalf of the Data Fiduciary.",
            category="SUPPLY_CHAIN",
            check_type=CheckType.AUTOMATED,
            severity=Severity.MEDIUM,
            legal_reference="DPDP Act 2023 Section 8(2)",
            recommended_action="Verify signed release packages and processor inventory.",
        ),
        ComplianceControl(
            control_id="DPDP-SEC-16-RESIDENCY",
            framework_id="DPDP_INDIA",
            title="Sovereign Data Residency & Cross-Border Transfer Fencing (Sec. 16)",
            requirement="Enforce sovereign Indian boundary fencing (ap-south-1 / on-prem air-gapped) and restrict transfers to restricted jurisdictions.",
            category="DATA_RESIDENCY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="DPDP Act 2023 Section 16",
            recommended_action="Enforce ap-south-1 sovereign telemetry boundary fencing.",
        ),
        ComplianceControl(
            control_id="DPDP-SEC-10-SDF",
            framework_id="DPDP_INDIA",
            title="Significant Data Fiduciary DPO, Independent Data Auditor & Processor Contracts (Sec. 8(2)/10)",
            requirement="Appoint India-based DPO, independent Data Auditor, DPIA, and valid Data Processor contracts where designated as a Significant Data Fiduciary.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="DPDP Act 2023 Section 8(2), Section 9 & Section 10",
            recommended_action="Attach India DPO appointment, Processor Contracts, and Annual Independent Data Audit Report.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "IN", db, "DPDP-SEC-4-INV", "DPDP Act 2023 Sec. 4 & 8"),
            await self.probe_visual_privacy_consent(tenant_id, db, "DPDP-SEC-6-CONSENT", "DPDP Act 2023 Sec. 5 & 6"),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "DPDP-SEC-8-5-SAFEGUARDS", "DPDP Act 2023 Sec. 8(5)"),
            await self.probe_encryption_and_tls(tenant_id, db, "DPDP-SEC-8-5-ENC", "DPDP Act 2023 Sec. 8(5)"),
            await self.probe_access_control_rbac_mfa(tenant_id, db, "DPDP-SEC-8-5-IAM", "DPDP Act 2023 Sec. 8(5)"),
            await self.probe_audit_logging_active(tenant_id, db, "DPDP-SEC-8-5-AUDIT", "DPDP Act 2023 Sec. 8(5)"),
            await self.probe_incident_response_backlog(tenant_id, db, "DPDP-SEC-8-6-BREACH", "DPDP Act 2023 Sec. 8(6)"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "DPDP-SEC-8-7-RETENTION", "DPDP Act 2023 Sec. 8(7)"),
            await self.probe_privacy_request_sla(tenant_id, db, "DPDP-SEC-11-14-RIGHTS", "DPDP Act 2023 Sec. 11-14", sla_days=30),
            await self.probe_supply_chain_tampering(tenant_id, db, "DPDP-SEC-8-2-PROCESSOR", "DPDP Act 2023 Sec. 8(2)"),
            await self.probe_data_residency_fencing(tenant_id, "ap-south-1", db, "DPDP-SEC-16-RESIDENCY", "DPDP Act 2023 Sec. 16"),
            self.manual_review_control(
                "DPDP-SEC-10-SDF",
                "Significant Data Fiduciary DPO, Independent Data Audit & Processor Contracts",
                "Verify valid Data Processor contracts (Sec. 8(2)), Consent Manager registration, and SDF DPO/DPIA obligations (Sec. 10).",
                "DPDP Act 2023 Sec. 8(2), Sec. 9, Sec. 10",
                "India DPO Appointment Letter, Processor Contracts, and Independent Data Auditor Report",
                tenant_id=tenant_id,
            ),
        ]


async def run_dpdp_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await DpdpFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
