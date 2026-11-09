"""
[v4.4.0] New Zealand Privacy Act 2020 — All 13 Information Privacy Principles (IPP 1–13)
Maps IPP 1 through IPP 13 plus Part 6 Notifiable Privacy Breaches (OPC NotifyUs 72-hour target)
and NZ PII classifiers (IRD Number Modulo-11, NHI Health Index, NZ Passport, Driver Licence).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class NewZealandPrivacyFramework(BaseComplianceFramework):
    framework_id = "NEW_ZEALAND_PRIVACY"
    name = "New Zealand Privacy Act 2020 (IPP 1–13)"
    region = "NZ"
    jurisdiction = "New Zealand"
    category = FrameworkCategory.PRIVACY
    version = "Public Act 2020 No 31"
    effective_from = "2020-12-01"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Office of the Privacy Commissioner (OPC New Zealand)"
    breach_notification_window = "As Soon As Practicable / OPC 72-Hour Expectation (Part 6 s114)"
    residency_region = "ap-southeast-2"
    source_reference = "New Zealand Privacy Act 2020 Section 22 (IPPs 1–13) & Part 6"
    supported_privacy_rights = ["ACCESS", "CORRECT", "RECTIFY"]

    controls = [
        ComplianceControl(
            control_id="NZ-IPP-1-4-COL",
            framework_id="NEW_ZEALAND_PRIVACY",
            title="IPP 1, 2 & 4: Lawful Purpose & Manner of Collection (IRD / NHI Discovery)",
            requirement="Collect personal information only for lawful connected purposes and classify NZ IRD (Modulo-11) and NHI identifiers.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Privacy Act 2020 s22 — IPP 1, IPP 2 & IPP 4",
            recommended_action="Ensure NZ PII classifiers (NZ) are active in DLP and DSPM.",
        ),
        ComplianceControl(
            control_id="NZ-IPP-3-NOTICE",
            framework_id="NEW_ZEALAND_PRIVACY",
            title="IPP 3: Collection Transparency Notice & Workplace Monitoring Consent",
            requirement="Ensure individuals are aware of collection purpose, recipients, and access/correction rights.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.MEDIUM,
            legal_reference="Privacy Act 2020 s22 — IPP 3",
            recommended_action="Enable MonitoringConsentRequired on monitored endpoints.",
        ),
        ComplianceControl(
            control_id="NZ-IPP-5-SEC",
            framework_id="NEW_ZEALAND_PRIVACY",
            title="IPP 5: Storage and Security of Personal Information (DSPM & Encryption)",
            requirement="Protect personal information by security safeguards reasonable in the circumstances against loss, unauthorized access, or misuse.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="Privacy Act 2020 s22 — IPP 5",
            recommended_action="Remediate exposed PII datastores in DSPM and enforce AES-256 encryption.",
        ),
        ComplianceControl(
            control_id="NZ-IPP-6-7-8-RIGHTS",
            framework_id="NEW_ZEALAND_PRIVACY",
            title="IPP 6, IPP 7 & IPP 8: Access, Correction & Accuracy Verification (20 Working Days)",
            requirement="Fulfill individual access (IPP 6) and correction (IPP 7) requests within 20 working days and verify accuracy (IPP 8).",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Privacy Act 2020 s22 — IPP 6, IPP 7, IPP 8 & s44",
            recommended_action="Process open NZ access/correction requests within 20 working days.",
        ),
        ComplianceControl(
            control_id="NZ-IPP-9-RETENTION",
            framework_id="NEW_ZEALAND_PRIVACY",
            title="IPP 9: Agency Not to Keep Personal Information Longer Than Necessary",
            requirement="Do not keep personal information for longer than is required for the purposes for which it may lawfully be used.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Privacy Act 2020 s22 — IPP 9",
            recommended_action="Enforce 90-day automated telemetry pruning.",
        ),
        ComplianceControl(
            control_id="NZ-IPP-10-11-AUDIT",
            framework_id="NEW_ZEALAND_PRIVACY",
            title="IPP 10 & IPP 11: Limits on Use and Disclosure & Audit Accountability",
            requirement="Log and govern internal use and external disclosure of personal information.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Privacy Act 2020 s22 — IPP 10 & IPP 11",
            recommended_action="Maintain tamper-evident AuditLog records.",
        ),
        ComplianceControl(
            control_id="NZ-IPP-12-CROSS",
            framework_id="NEW_ZEALAND_PRIVACY",
            title="IPP 12: Disclosure of Personal Information Outside New Zealand",
            requirement="Ensure foreign disclosures have comparable safeguards or enforce regional sovereign boundary fencing.",
            category="DATA_RESIDENCY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="Privacy Act 2020 s22 — IPP 12",
            recommended_action="Enforce ap-southeast-2 sovereign boundary fencing.",
        ),
        ComplianceControl(
            control_id="NZ-IPP-13-UNIQUE",
            framework_id="NEW_ZEALAND_PRIVACY",
            title="IPP 13: Unique Identifiers Governance & Least-Privilege Access (IRD / NHI)",
            requirement="Prevent unauthorized assignment or exposure of unique identifiers through strict RBAC and encryption.",
            category="ACCESS_CONTROL",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Privacy Act 2020 s22 — IPP 13",
            recommended_action="Enforce RBAC access boundaries over unique identifiers.",
        ),
        ComplianceControl(
            control_id="NZ-PART6-BREACH",
            framework_id="NEW_ZEALAND_PRIVACY",
            title="Part 6 (s112–118): Notifiable Privacy Breach Reporting to OPC (NotifyUs)",
            requirement="Notify the Privacy Commissioner and affected individuals as soon as practicable of breaches causing serious harm.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="Privacy Act 2020 Sections 112–118",
            recommended_action="Triage open critical security incidents promptly.",
        ),
        ComplianceControl(
            control_id="NZ-SEC-201-OFFICER",
            framework_id="NEW_ZEALAND_PRIVACY",
            title="Section 201: Mandatory Appointment of Privacy Officer",
            requirement="Every agency must appoint at least one individual as Privacy Officer responsible for Privacy Act compliance.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="Privacy Act 2020 Section 201",
            recommended_action="Attach NZ Privacy Officer appointment record and IPP 12 contractual clauses.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "NZ", db, "NZ-IPP-1-4-COL", "Privacy Act 2020 IPP 1–4"),
            await self.probe_visual_privacy_consent(tenant_id, db, "NZ-IPP-3-NOTICE", "Privacy Act 2020 IPP 3"),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "NZ-IPP-5-SEC", "Privacy Act 2020 IPP 5"),
            await self.probe_privacy_request_sla(tenant_id, db, "NZ-IPP-6-7-8-RIGHTS", "Privacy Act 2020 IPP 6–8", sla_days=28),
            await self.probe_telemetry_retention(tenant_id, 90, db, "NZ-IPP-9-RETENTION", "Privacy Act 2020 IPP 9"),
            await self.probe_audit_logging_active(tenant_id, db, "NZ-IPP-10-11-AUDIT", "Privacy Act 2020 IPP 10–11"),
            await self.probe_data_residency_fencing(tenant_id, "ap-southeast-2", db, "NZ-IPP-12-CROSS", "Privacy Act 2020 IPP 12"),
            await self.probe_access_control_rbac_mfa(tenant_id, db, "NZ-IPP-13-UNIQUE", "Privacy Act 2020 IPP 13"),
            await self.probe_incident_response_backlog(tenant_id, db, "NZ-PART6-BREACH", "Privacy Act 2020 s114"),
            self.manual_review_control(
                "NZ-SEC-201-OFFICER",
                "Section 201 Privacy Officer Appointment & IPP 12 Foreign Safeguards",
                "Verify appointment of an agency Privacy Officer under s201 and comparable foreign disclosure clauses.",
                "Privacy Act 2020 Section 201 & IPP 12",
                "Privacy Officer Appointment Letter & Overseas Transfer Clauses",
                tenant_id=tenant_id,
            ),
        ]


async def run_new_zealand_privacy_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await NewZealandPrivacyFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
