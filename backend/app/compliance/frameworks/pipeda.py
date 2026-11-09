"""
[v4.4.0] Canada PIPEDA — All 10 Fair Information Principles (Schedule 1) & Breach Safeguards
Maps Schedule 1 Principles 4.1 through 4.10 plus Division 1.1 Breach of Security Safeguards
(RROSR mandatory 24-month breach record-keeping & OPC reporting) and Canadian SIN Luhn validation.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class PipedaFramework(BaseComplianceFramework):
    framework_id = "PIPEDA"
    name = "Canada PIPEDA (10 Fair Information Principles)"
    region = "CA"
    jurisdiction = "Canada"
    category = FrameworkCategory.PRIVACY
    version = "S.C. 2000, c. 5 (Schedule 1 Principles 1–10)"
    effective_from = "2001-01-01"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Office of the Privacy Commissioner of Canada (OPC)"
    breach_notification_window = "As Soon As Feasible to OPC & Affected Individuals (s. 10.1 RROSR)"
    residency_region = "ca-central-1"
    source_reference = "Personal Information Protection and Electronic Documents Act (S.C. 2000, c. 5)"
    supported_privacy_rights = ["ACCESS", "CORRECT", "RECTIFY", "OPT_OUT"]

    controls = [
        ComplianceControl(
            control_id="PIPEDA-P1-ACCOUNTABILITY",
            framework_id="PIPEDA",
            title="Principle 1 (4.1) & Principle 8 (4.8): Designated Privacy Officer, Openness & Cross-Border Accountability",
            requirement="Designate individual(s) accountable for PIPEDA compliance, publish open privacy policies, and ensure contractual protection for third-party transfers.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="PIPEDA Schedule 1 Clauses 4.1 & 4.8",
            recommended_action="Attach Canadian Privacy Officer designation, public Privacy Notice, and processor agreements.",
        ),
        ComplianceControl(
            control_id="PIPEDA-P2-P4-COLLECTION",
            framework_id="PIPEDA",
            title="Principle 2 (4.2) & Principle 4 (4.4): Identifying Purposes, Limiting Collection & SIN Discovery",
            requirement="Identify collection purposes and discover/govern Canadian SIN (Luhn-validated), Passport, Driver's Licence, and Postal Codes.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PIPEDA Schedule 1 Clauses 4.2 & 4.4",
            recommended_action="Ensure Canadian PII classifiers (CA) are active in DLP and DSPM.",
        ),
        ComplianceControl(
            control_id="PIPEDA-P3-CONSENT",
            framework_id="PIPEDA",
            title="Principle 3 (4.3): Meaningful Consent & Workplace Telemetry Notice",
            requirement="Obtain meaningful knowledge and consent for collection, use, or disclosure of personal information.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.MEDIUM,
            legal_reference="PIPEDA Schedule 1 Clause 4.3 & Section 6.1",
            recommended_action="Enable MonitoringConsentRequired on monitored endpoints.",
        ),
        ComplianceControl(
            control_id="PIPEDA-P5-RETENTION",
            framework_id="PIPEDA",
            title="Principle 5 (4.5): Limiting Use, Disclosure, and Retention",
            requirement="Retain personal information only as long as necessary for fulfillment of stated purposes and destroy/erase expired data.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PIPEDA Schedule 1 Clause 4.5",
            recommended_action="Enforce 90-day automated telemetry pruning.",
        ),
        ComplianceControl(
            control_id="PIPEDA-P6-P9-P10-RIGHTS",
            framework_id="PIPEDA",
            title="Principle 6 (4.6), Principle 9 (4.9) & Principle 10 (4.10): Accuracy, Individual Access & Challenging Compliance",
            requirement="Respond to individual access and accuracy/amendment requests within 30 calendar days (s. 8(3)) and log compliance challenges.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PIPEDA Schedule 1 Clauses 4.6, 4.9, 4.10 & Section 8(3)",
            recommended_action="Fulfill open Canadian access and correction requests within 30 days.",
        ),
        ComplianceControl(
            control_id="PIPEDA-P7-SAFEGUARDS",
            framework_id="PIPEDA",
            title="Principle 7 (4.7): Security Safeguards Appropriate to Sensitivity (SIN & Financial PII)",
            requirement="Protect personal information by security safeguards appropriate to the sensitivity of the information.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="PIPEDA Schedule 1 Clause 4.7",
            recommended_action="Remediate exposed PII datastores in DSPM.",
        ),
        ComplianceControl(
            control_id="PIPEDA-P7-ENC-IAM",
            framework_id="PIPEDA",
            title="Principle 7 (4.7.3): Technological Safeguards — Encryption, TLS 1.3 & RBAC",
            requirement="Protect personal information using technological measures including passwords, RBAC, and encryption.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PIPEDA Schedule 1 Clause 4.7.3",
            recommended_action="Enforce AES-256 encryption at rest and mTLS.",
        ),
        ComplianceControl(
            control_id="PIPEDA-RROSR-LOGS",
            framework_id="PIPEDA",
            title="Division 1.1 (s. 10.3): 24-Month Breach of Security Safeguards Record-Keeping & Audit Trail",
            requirement="Keep and maintain a record of every breach of security safeguards for 24 months after the day on which the organization determines the breach occurred.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PIPEDA s. 10.3 & Breach of Security Safeguards Regulations s. 6",
            recommended_action="Maintain immutable AuditLog and incident records.",
        ),
        ComplianceControl(
            control_id="PIPEDA-SEC-10-1-BREACH",
            framework_id="PIPEDA",
            title="Division 1.1 (s. 10.1): OPC Breach Reporting for Real Risk of Significant Harm (RROSH)",
            requirement="Report to the Privacy Commissioner of Canada and notify affected individuals as soon as feasible of any breach posing RROSH.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="PIPEDA Section 10.1 & 10.2",
            recommended_action="Triage open critical security incidents.",
        ),
        ComplianceControl(
            control_id="PIPEDA-P1-RESIDENCY",
            framework_id="PIPEDA",
            title="Principle 4.1.3: Sovereign Canadian Regional Boundary Fencing (ca-central-1)",
            requirement="Enforce sovereign boundary fencing (ca-central-1) to prevent unauthorized cross-border leakage of Canadian PII.",
            category="DATA_RESIDENCY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PIPEDA Schedule 1 Clause 4.1.3",
            recommended_action="Enforce ca-central-1 sovereign telemetry boundary fencing.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        return [
            self.manual_review_control(
                "PIPEDA-P1-ACCOUNTABILITY",
                "Principles 1 & 8: Privacy Officer Designation, Openness Policy & Third-Party Contracts",
                "Verify designated Privacy Officer (4.1), published Privacy Notice (4.8), and comparable third-party contractual clauses (4.1.3).",
                "PIPEDA Schedule 1 Clauses 4.1, 4.1.3 & 4.8",
                "Privacy Officer Charter, Public Privacy Policy, and Processor Addenda",
                tenant_id=tenant_id,
            ),
            await self.probe_dlp_classifier_coverage(tenant_id, "CA", db, "PIPEDA-P2-P4-COLLECTION", "PIPEDA Clauses 4.2 & 4.4"),
            await self.probe_visual_privacy_consent(tenant_id, db, "PIPEDA-P3-CONSENT", "PIPEDA Clause 4.3"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "PIPEDA-P5-RETENTION", "PIPEDA Clause 4.5"),
            await self.probe_privacy_request_sla(tenant_id, db, "PIPEDA-P6-P9-P10-RIGHTS", "PIPEDA Clauses 4.6, 4.9, 4.10", sla_days=30),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "PIPEDA-P7-SAFEGUARDS", "PIPEDA Clause 4.7"),
            await self.probe_encryption_and_tls(tenant_id, db, "PIPEDA-P7-ENC-IAM", "PIPEDA Clause 4.7.3"),
            await self.probe_audit_logging_active(tenant_id, db, "PIPEDA-RROSR-LOGS", "PIPEDA s. 10.3"),
            await self.probe_incident_response_backlog(tenant_id, db, "PIPEDA-SEC-10-1-BREACH", "PIPEDA s. 10.1"),
            await self.probe_data_residency_fencing(tenant_id, "ca-central-1", db, "PIPEDA-P1-RESIDENCY", "PIPEDA Clause 4.1.3"),
        ]


async def run_pipeda_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await PipedaFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
