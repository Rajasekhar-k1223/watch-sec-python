"""
[v4.4.0] South Africa POPIA (Protection of Personal Information Act, Act No. 4 of 2013)
Maps all 8 Conditions for Lawful Processing of Personal Information:
1. Accountability (s8)
2. Processing Limitation (s9–12)
3. Purpose Specification & Retention (s13–14)
4. Further Processing Limitation (s15)
5. Information Quality (s16)
6. Openness & Information Officer Registration (s17–18 / s55)
7. Security Safeguards & Breach Notification to Information Regulator (s19–22)
8. Data Subject Participation (s23–25)
Plus Section 72 Cross-Border Transfers and 13-digit SA National ID Luhn validation.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class PopiaFramework(BaseComplianceFramework):
    framework_id = "POPIA"
    name = "South Africa POPIA (8 Lawful Processing Conditions)"
    region = "ZA"
    jurisdiction = "Republic of South Africa"
    category = FrameworkCategory.PRIVACY
    version = "Act No. 4 of 2013"
    effective_from = "2020-07-01"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Information Regulator (South Africa)"
    breach_notification_window = "As Soon As Reasonably Possible to Information Regulator & Data Subjects (s22)"
    residency_region = "af-south-1"
    source_reference = "Protection of Personal Information Act 4 of 2013 (Chapter 3 Conditions 1–8)"
    supported_privacy_rights = ["ACCESS", "DELETE", "CORRECT", "RECTIFY", "OBJECT"]

    controls = [
        ComplianceControl(
            control_id="POPIA-COND1-ACCOUNT",
            framework_id="POPIA",
            title="Condition 1 (s8): Accountability & Immutable Governance Audit Logs",
            requirement="Ensure conditions for lawful processing and measures giving effect to them are complied with and auditable.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="POPIA Section 8 (Condition 1)",
            recommended_action="Maintain tamper-evident AuditLog capture.",
        ),
        ComplianceControl(
            control_id="POPIA-COND2-LIMIT",
            framework_id="POPIA",
            title="Condition 2 (s9–12): Processing Limitation, Consent & SA ID Discovery",
            requirement="Process personal information lawfully and minimally with consent/notice, classifying 13-digit SA National IDs (Luhn).",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="POPIA Sections 9–12 (Condition 2)",
            recommended_action="Ensure South African PII classifiers (ZA) and consent banners are active.",
        ),
        ComplianceControl(
            control_id="POPIA-COND3-RETENTION",
            framework_id="POPIA",
            title="Condition 3 (s13–14): Purpose Specification & Destruction of Expired Records",
            requirement="Records of personal information must not be retained any longer than is necessary for achieving the purpose.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="POPIA Sections 13 & 14 (Condition 3)",
            recommended_action="Enforce 90-day automated telemetry pruning.",
        ),
        ComplianceControl(
            control_id="POPIA-COND4-FURTHER",
            framework_id="POPIA",
            title="Condition 4 (s15): Further Processing Limitation via RBAC Scoping",
            requirement="Restrict secondary/unauthorized internal access using role-based access controls.",
            category="ACCESS_CONTROL",
            check_type=CheckType.AUTOMATED,
            severity=Severity.MEDIUM,
            legal_reference="POPIA Section 15 (Condition 4)",
            recommended_action="Enforce RBAC least-privilege scoping.",
        ),
        ComplianceControl(
            control_id="POPIA-COND5-8-RIGHTS",
            framework_id="POPIA",
            title="Condition 5 (s16) & Condition 8 (s23–25): Information Quality & Data Subject Participation",
            requirement="Maintain accurate records and fulfill data subject requests for access, correction, and deletion of personal information.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="POPIA Sections 16 & 23–25 (Conditions 5 & 8)",
            recommended_action="Fulfill open POPIA DSR requests within statutory window.",
        ),
        ComplianceControl(
            control_id="POPIA-COND6-IO",
            framework_id="POPIA",
            title="Condition 6 (s17–18 / s55): Openness, PAIA Manual & Information Officer Registration",
            requirement="Register Information Officer with the Information Regulator (s55), maintain PAIA s51 Manual, and provide s18 collection notices.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="POPIA Sections 17, 18, 55 & PAIA Section 51",
            recommended_action="Attach Information Regulator IO Registration Certificate and PAIA Manual.",
        ),
        ComplianceControl(
            control_id="POPIA-COND7-SEC",
            framework_id="POPIA",
            title="Condition 7 (s19–21): Security Safeguards, Encryption & Operator Integrity",
            requirement="Secure the integrity and confidentiality of personal information via technical measures, encryption, and DSPM exposure controls.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="POPIA Sections 19–21 (Condition 7)",
            recommended_action="Remediate exposed PII datastores in DSPM and enable AES-256 encryption.",
        ),
        ComplianceControl(
            control_id="POPIA-COND7-S22-BREACH",
            framework_id="POPIA",
            title="Condition 7 (s22): Notification of Security Compromises to Information Regulator",
            requirement="Notify the Information Regulator and data subjects as soon as reasonably possible where personal information has been accessed by unauthorized persons.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="POPIA Section 22",
            recommended_action="Triage open critical security incidents promptly.",
        ),
        ComplianceControl(
            control_id="POPIA-SEC-72-TRANS",
            framework_id="POPIA",
            title="Section 72: Transfers of Personal Information Outside Republic (af-south-1 Fencing)",
            requirement="Prohibit unauthorized cross-border transfer of South African personal information outside sovereign af-south-1 boundary.",
            category="DATA_RESIDENCY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="POPIA Section 72",
            recommended_action="Enforce af-south-1 sovereign boundary fencing.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        return [
            await self.probe_audit_logging_active(tenant_id, db, "POPIA-COND1-ACCOUNT", "POPIA s8 Condition 1"),
            await self.probe_dlp_classifier_coverage(tenant_id, "ZA", db, "POPIA-COND2-LIMIT", "POPIA s9–12 Condition 2"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "POPIA-COND3-RETENTION", "POPIA s13–14 Condition 3"),
            await self.probe_access_control_rbac_mfa(tenant_id, db, "POPIA-COND4-FURTHER", "POPIA s15 Condition 4"),
            await self.probe_privacy_request_sla(tenant_id, db, "POPIA-COND5-8-RIGHTS", "POPIA s16 & s23–25", sla_days=30),
            self.manual_review_control(
                "POPIA-COND6-IO",
                "Condition 6: Information Officer Registration & PAIA Manual",
                "Verify registration of the Information Officer with the South African Information Regulator and current PAIA Manual.",
                "POPIA Sections 17, 18, 55 & PAIA s51",
                "Information Regulator IO Registration Certificate & Signed PAIA Manual",
                tenant_id=tenant_id,
            ),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "POPIA-COND7-SEC", "POPIA s19 Condition 7"),
            await self.probe_incident_response_backlog(tenant_id, db, "POPIA-COND7-S22-BREACH", "POPIA s22"),
            await self.probe_data_residency_fencing(tenant_id, "af-south-1", db, "POPIA-SEC-72-TRANS", "POPIA s72"),
        ]


async def run_popia_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await PopiaFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
