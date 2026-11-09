"""
[v4.4.0] USA Health Insurance Portability and Accountability Act (HIPAA) — 45 CFR Parts 160 & 164
Preserves and extends existing Monitorix HIPAA Security & Breach Notification Rule checks:
§164.312(a) Access Control, §164.312(b) Audit Controls, EPHI screen-capture exclusions,
PHI classifier protections, §164.312(e) Transmission Security, §164.308(a)(7) Contingency,
§164.404 Breach Notification, and §164.308(b)(1) Business Associate Agreements (Manual Review).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class HipaaFramework(BaseComplianceFramework):
    framework_id = "HIPAA"
    name = "Health Insurance Portability and Accountability Act (HIPAA)"
    region = "US"
    jurisdiction = "United States"
    category = FrameworkCategory.HEALTHCARE
    version = "45 CFR Parts 160, 162, and 164"
    effective_from = "2003-04-14"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "U.S. Department of Health and Human Services (HHS OCR)"
    breach_notification_window = "Without Unreasonable Delay / <= 60 Calendar Days (45 CFR §164.404)"
    residency_region = "us-east-1"
    source_reference = "45 CFR Part 164 Subpart C (Security Rule) & Subpart D (Breach Notification)"
    supported_privacy_rights = ["ACCESS", "RECTIFY", "RESTRICT"]

    controls = [
        ComplianceControl(
            control_id="HIPAA-164-312-A",
            framework_id="HIPAA",
            title="Technical Access Control & Unique User Identification (§164.312(a)(1))",
            requirement="Implement technical policies and procedures for electronic information systems that maintain EPHI to allow access only to authorized persons.",
            category="ACCESS_CONTROL",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="45 CFR § 164.312(a)(1)",
            recommended_action="Enforce RBAC least-privilege scoping and SSO/MFA authentication.",
        ),
        ComplianceControl(
            control_id="HIPAA-164-312-B",
            framework_id="HIPAA",
            title="Hardware, Software & Procedural Audit Controls (§164.312(b))",
            requirement="Implement mechanisms that record and examine activity in information systems that contain or use EPHI.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="45 CFR § 164.312(b)",
            recommended_action="Verify continuous AuditLog capture for all EPHI system access.",
        ),
        ComplianceControl(
            control_id="HIPAA-164-312-EPHI-VIS",
            framework_id="HIPAA",
            title="EPHI Screen-Capture Exclusions & Minimum Necessary Safeguard (§164.502(b))",
            requirement="Prevent unauthorized desktop screen capture of clinical/EPHI applications without privacy exclusions and consent.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="45 CFR § 164.502(b) & § 164.312(a)",
            recommended_action="Configure EPHI window exclusions or disable visual capture on clinical endpoints.",
        ),
        ComplianceControl(
            control_id="HIPAA-164-312-PHI-DSPM",
            framework_id="HIPAA",
            title="Electronic Protected Health Information (EPHI) Exposure Protection (§164.312(a)(2)(iv))",
            requirement="Protect EPHI repositories from unauthorized public access and unencrypted storage.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="45 CFR § 164.312(a)(2)(iv)",
            recommended_action="Remediate exposed PHI_HEALTH findings in DSPM.",
            automated_remediation_available=True,
        ),
        ComplianceControl(
            control_id="HIPAA-164-312-E-ENC",
            framework_id="HIPAA",
            title="Encryption at Rest & Transmission Security (§164.312(e)(1))",
            requirement="Implement technical security measures to guard against unauthorized access to EPHI transmitted over an electronic communications network.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="45 CFR § 164.312(e)(1) & § 164.312(a)(2)(iv)",
            recommended_action="Enforce AES-256 datastore encryption and mTLS/TLS 1.3 transport.",
        ),
        ComplianceControl(
            control_id="HIPAA-164-308-A1-VULN",
            framework_id="HIPAA",
            title="Security Management Process & Technical Vulnerability Remediation (§164.308(a)(1))",
            requirement="Implement policies and procedures to prevent, detect, contain, and correct security violations.",
            category="VULNERABILITY_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="45 CFR § 164.308(a)(1)(ii)(B)",
            recommended_action="Patch High/Critical software vulnerabilities on endpoints accessing EPHI.",
        ),
        ComplianceControl(
            control_id="HIPAA-164-308-A7-CONT",
            framework_id="HIPAA",
            title="Contingency Plan, Data Backup & Disaster Recovery (§164.308(a)(7))",
            requirement="Establish and implement procedures to create and maintain retrievable exact copies of EPHI and restore lost data.",
            category="OPERATIONS_RECOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="45 CFR § 164.308(a)(7)",
            recommended_action="Maintain active-active HA/DR replication readiness.",
        ),
        ComplianceControl(
            control_id="HIPAA-164-404-BREACH",
            framework_id="HIPAA",
            title="Security Incident Procedures & HHS Breach Notification (§164.308(a)(6) / §164.404)",
            requirement="Identify and respond to suspected or known security incidents and notify affected individuals and HHS OCR.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="45 CFR § 164.308(a)(6) & § 164.404",
            recommended_action="Triage open critical security incidents immediately.",
        ),
        ComplianceControl(
            control_id="HIPAA-164-308-B1-BAA",
            framework_id="HIPAA",
            title="Business Associate Agreements (BAA) & Workforce Training (§164.308(b)(1))",
            requirement="Obtain satisfactory written assurances (BAAs) from all business associates handling EPHI and conduct annual HIPAA workforce training.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="45 CFR § 164.308(b)(1) & § 164.308(a)(5)",
            recommended_action="Verify executed Business Associate Agreements and annual HIPAA training completion logs.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        return [
            await self.probe_access_control_rbac_mfa(tenant_id, db, "HIPAA-164-312-A", "45 CFR § 164.312(a)(1)"),
            await self.probe_audit_logging_active(tenant_id, db, "HIPAA-164-312-B", "45 CFR § 164.312(b)"),
            await self.probe_visual_privacy_consent(tenant_id, db, "HIPAA-164-312-EPHI-VIS", "45 CFR § 164.502(b)"),
            await self.probe_dspm_sensitive_exposure(tenant_id, "HEALTH", db, "HIPAA-164-312-PHI-DSPM", "45 CFR § 164.312(a)(2)(iv)"),
            await self.probe_encryption_and_tls(tenant_id, db, "HIPAA-164-312-E-ENC", "45 CFR § 164.312(e)(1)"),
            await self.probe_vulnerability_backlog(tenant_id, db, "HIPAA-164-308-A1-VULN", "45 CFR § 164.308(a)(1)"),
            await self.probe_backup_and_dr_readiness(tenant_id, db, "HIPAA-164-308-A7-CONT", "45 CFR § 164.308(a)(7)"),
            await self.probe_incident_response_backlog(tenant_id, db, "HIPAA-164-404-BREACH", "45 CFR § 164.404"),
            self.manual_review_control(
                "HIPAA-164-308-B1-BAA",
                "Executed Business Associate Agreements (BAA) & Workforce Training",
                "Maintain signed BAAs with cloud/sub-processors and annual HIPAA Security Rule training records.",
                "45 CFR § 164.308(b)(1)",
                "Executed Business Associate Agreement Repository & Workforce Training Attestation",
                tenant_id=tenant_id,
            ),
        ]


async def run_hipaa_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await HipaaFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
