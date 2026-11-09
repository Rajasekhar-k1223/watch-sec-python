"""
[v4.4.0] USA Gramm-Leach-Bliley Act (GLBA) — FTC Safeguards Rule (16 CFR Part 314)
Maps all Safeguards Rule technical controls:
- Risk Assessment & NPI Discovery (Bank/Loan/Financial/Routing/Tax Identifiers)
- Access Control & MFA/RBAC (§314.4(c)(1) & (5))
- Encryption at Rest & Transit (§314.4(c)(3))
- Secure Development & Change Management (§314.4(c)(4) & (7))
- Continuous Monitoring, Logging & Penetration/Vulnerability Testing (§314.4(c)(8) & (d))
- Data Retention & 2-Year Disposal (§314.4(c)(6))
- Incident Response & 30-Day FTC Notification (§314.4(h) & (j))
- Service-Provider Oversight & Qualified Individual Board Report (§314.4(a),(f),(i) Manual Review)
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class GlbaFramework(BaseComplianceFramework):
    framework_id = "GLBA"
    name = "Gramm-Leach-Bliley Act (FTC Safeguards Rule)"
    region = "US"
    jurisdiction = "United States"
    category = FrameworkCategory.FINANCIAL
    version = "16 CFR Part 314 (Amended 2024)"
    effective_from = "2003-05-23"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Federal Trade Commission (FTC) & Federal Banking Agencies"
    breach_notification_window = "As Soon As Possible / <= 30 Days to FTC for >=500 Consumers (16 CFR §314.4(j))"
    residency_region = "us-east-1"
    source_reference = "15 U.S.C. §§ 6801–6809 & 16 CFR Part 314"
    supported_privacy_rights = ["ACCESS", "OPT_OUT"]

    controls = [
        ComplianceControl(
            control_id="GLBA-314-4-B-RISK",
            framework_id="GLBA",
            title="Customer NPI Discovery & Financial Data Inventory (§314.4(b) / §314.4(c)(2))",
            requirement="Identify and inventory Non-Public Personal Information (NPI), bank accounts, ABA routing numbers, loan accounts, financial accounts, and tax IDs.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="16 CFR § 314.4(b) & § 314.4(c)(2)",
            recommended_action="Ensure US GLBA financial classifiers are active in DLP and DSPM.",
        ),
        ComplianceControl(
            control_id="GLBA-314-4-C1-AC",
            framework_id="GLBA",
            title="Access Controls, Least Privilege & Multi-Factor Authentication (§314.4(c)(1) & (5))",
            requirement="Implement technical access controls and authentication safeguards so only authorized individuals can access customer information.",
            category="ACCESS_CONTROL",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="16 CFR § 314.4(c)(1) & § 314.4(c)(5)",
            recommended_action="Enforce RBAC role boundaries and MFA/SSO authentication.",
        ),
        ComplianceControl(
            control_id="GLBA-314-4-C3-ENC",
            framework_id="GLBA",
            title="Encryption of Customer Information at Rest & in Transit (§314.4(c)(3))",
            requirement="Encrypt all customer information held or transmitted by you both in transit over external networks and at rest.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="16 CFR § 314.4(c)(3)",
            recommended_action="Enable AES-256 encryption on all datastores and enforce TLS 1.3.",
        ),
        ComplianceControl(
            control_id="GLBA-314-4-C3-DSPM",
            framework_id="GLBA",
            title="Customer Financial Repository Exposure Protection (§314.4(c)(3))",
            requirement="Prevent public exposure or unencrypted storage of financial and payment repositories.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="16 CFR § 314.4(c)(3)",
            recommended_action="Remediate exposed FINANCIAL/PCI findings in DSPM.",
            automated_remediation_available=True,
        ),
        ComplianceControl(
            control_id="GLBA-314-4-C4-SDLC",
            framework_id="GLBA",
            title="Secure Software Development & Change Management (§314.4(c)(4) & (7))",
            requirement="Adopt secure development practices and change management procedures with cryptographic release verification.",
            category="CHANGE_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="16 CFR § 314.4(c)(4) & § 314.4(c)(7)",
            recommended_action="Verify Ed25519-signed software releases and controlled change logs.",
        ),
        ComplianceControl(
            control_id="GLBA-314-4-C6-RET",
            framework_id="GLBA",
            title="Secure Disposal & Data Retention Schedule (§314.4(c)(6))",
            requirement="Develop and implement procedures for secure disposal of customer information when no longer necessary for legitimate business purposes.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="16 CFR § 314.4(c)(6)",
            recommended_action="Enforce automated telemetry retention pruning.",
        ),
        ComplianceControl(
            control_id="GLBA-314-4-C8-LOG",
            framework_id="GLBA",
            title="Authorized User Activity Logging & Tamper Detection (§314.4(c)(8))",
            requirement="Implement policies, procedures, and controls to monitor and log the activity of authorized users and detect unauthorized access.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="16 CFR § 314.4(c)(8)",
            recommended_action="Maintain continuous immutable AuditLog capture.",
        ),
        ComplianceControl(
            control_id="GLBA-314-4-D1-MON",
            framework_id="GLBA",
            title="Continuous Intrusion Detection & Endpoint Monitoring (§314.4(d)(2))",
            requirement="Maintain continuous monitoring of information systems to detect attacks and intrusions.",
            category="MONITORING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="16 CFR § 314.4(d)(2)",
            recommended_action="Maintain healthy Monitorix endpoint sensor coverage.",
        ),
        ComplianceControl(
            control_id="GLBA-314-4-D2-VULN",
            framework_id="GLBA",
            title="Vulnerability Management & Security Testing (§314.4(d)(2)(ii))",
            requirement="Perform automated vulnerability assessments and remediate identified high/critical system flaws.",
            category="VULNERABILITY_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="16 CFR § 314.4(d)(2)(ii)",
            recommended_action="Remediate High/Critical endpoint software vulnerabilities.",
        ),
        ComplianceControl(
            control_id="GLBA-314-4-H-IR",
            framework_id="GLBA",
            title="Incident Response & FTC 30-Day Notification Event Readiness (§314.4(h) & (j))",
            requirement="Respond promptly to security events and report notification events affecting >=500 consumers to the FTC within 30 days.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="16 CFR § 314.4(h) & § 314.4(j)",
            recommended_action="Triage open critical security incidents.",
        ),
        ComplianceControl(
            control_id="GLBA-314-4-AF-GOV",
            framework_id="GLBA",
            title="Qualified Individual Designation, Service-Provider Contracts & Annual Board Report",
            requirement="Designate a Qualified Individual (§314.4(a)), oversee service providers by contract (§314.4(f)), and submit an annual written report to the Board (§314.4(i)).",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="16 CFR § 314.4(a), § 314.4(f) & § 314.4(i)",
            recommended_action="Attach Qualified Individual appointment, Service-Provider Oversight Assessments, and Annual Board Report.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "US", db, "GLBA-314-4-B-RISK", "16 CFR § 314.4(b)"),
            await self.probe_access_control_rbac_mfa(tenant_id, db, "GLBA-314-4-C1-AC", "16 CFR § 314.4(c)(1)&(5)"),
            await self.probe_encryption_and_tls(tenant_id, db, "GLBA-314-4-C3-ENC", "16 CFR § 314.4(c)(3)"),
            await self.probe_dspm_sensitive_exposure(tenant_id, "FINANCIAL", db, "GLBA-314-4-C3-DSPM", "16 CFR § 314.4(c)(3)"),
            await self.probe_supply_chain_tampering(tenant_id, db, "GLBA-314-4-C4-SDLC", "16 CFR § 314.4(c)(4)&(7)"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "GLBA-314-4-C6-RET", "16 CFR § 314.4(c)(6)"),
            await self.probe_audit_logging_active(tenant_id, db, "GLBA-314-4-C8-LOG", "16 CFR § 314.4(c)(8)"),
            await self.probe_agent_enrollment_health(tenant_id, db, "GLBA-314-4-D1-MON", "16 CFR § 314.4(d)(2)"),
            await self.probe_vulnerability_backlog(tenant_id, db, "GLBA-314-4-D2-VULN", "16 CFR § 314.4(d)(2)(ii)"),
            await self.probe_incident_response_backlog(tenant_id, db, "GLBA-314-4-H-IR", "16 CFR § 314.4(h)&(j)"),
            self.manual_review_control(
                "GLBA-314-4-AF-GOV",
                "Qualified Individual Designation, Service-Provider Oversight & Annual Board Report",
                "Verify Qualified Individual charter, service-provider contractual safeguards, and annual written Board security report.",
                "16 CFR § 314.4(a), (f), (i)",
                "Qualified Individual Charter, Vendor Safeguards Assessments, and Annual Board Report",
                tenant_id=tenant_id,
            ),
        ]


async def run_glba_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await GlbaFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
