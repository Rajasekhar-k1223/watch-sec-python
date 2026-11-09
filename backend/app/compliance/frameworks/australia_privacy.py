"""
[v4.4.0] Australia Privacy Act 1988 & All 13 Australian Privacy Principles (APP 1–13)
Maps every Australian Privacy Principle (APP 1 through APP 13) plus the OAIC Notifiable
Data Breaches (NDB) scheme and Australian PII classifiers (TFN Modulo-11, Medicare, ABN, Passport, DL).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class AustraliaPrivacyFramework(BaseComplianceFramework):
    framework_id = "AUSTRALIA_PRIVACY"
    name = "Australia Privacy Act 1988 & APPs (APP 1–13)"
    region = "AU"
    jurisdiction = "Commonwealth of Australia"
    category = FrameworkCategory.PRIVACY
    version = "Privacy Act 1988 (No. 119, Amended 2024)"
    effective_from = "1988-12-14"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Office of the Australian Information Commissioner (OAIC)"
    breach_notification_window = "Expeditious Assessment <= 30 Days & Prompt OAIC NDB Statement (Part IIIC)"
    residency_region = "ap-southeast-2"
    source_reference = "Privacy Act 1988 Schedule 1 (APPs 1–13) & Part IIIC (Notifiable Data Breaches)"
    supported_privacy_rights = ["ACCESS", "CORRECT", "RECTIFY", "OPT_OUT"]

    controls = [
        ComplianceControl(
            control_id="AU-APP-1-2-GOV",
            framework_id="AUSTRALIA_PRIVACY",
            title="APP 1 & APP 2: Open and Transparent Management & Anonymity/Pseudonymity Policy",
            requirement="Maintain a clearly expressed, up-to-date APP Privacy Policy and allow anonymity/pseudonymity where practicable.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="Privacy Act 1988 Schedule 1 — APP 1 & APP 2",
            recommended_action="Publish current OAIC-aligned APP Privacy Policy and pseudonymity procedures.",
        ),
        ComplianceControl(
            control_id="AU-APP-3-4-COL",
            framework_id="AUSTRALIA_PRIVACY",
            title="APP 3 & APP 4: Solicited/Unsolicited Collection & Australian PII Discovery (TFN/Medicare/ABN)",
            requirement="Collect personal/sensitive information only where reasonably necessary and classify TFN, Medicare, ABN, Passport, and Driver Licence identifiers.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Privacy Act 1988 Schedule 1 — APP 3, APP 4 & TFN Rule 2015",
            recommended_action="Ensure Australian PII classifiers (AU) are active in DLP and DSPM.",
        ),
        ComplianceControl(
            control_id="AU-APP-5-NOTICE",
            framework_id="AUSTRALIA_PRIVACY",
            title="APP 5: Notification of Collection & Workplace Telemetry Consent",
            requirement="Notify individuals of collection purposes and enforce monitoring transparency flags.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.MEDIUM,
            legal_reference="Privacy Act 1988 Schedule 1 — APP 5",
            recommended_action="Enable MonitoringConsentRequired on monitored endpoints.",
        ),
        ComplianceControl(
            control_id="AU-APP-6-7-USE",
            framework_id="AUSTRALIA_PRIVACY",
            title="APP 6 & APP 7: Use/Disclosure Audit Logging & Direct Marketing Opt-Out",
            requirement="Restrict secondary disclosure through RBAC/audit logs and honor direct marketing opt-out preferences.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Privacy Act 1988 Schedule 1 — APP 6 & APP 7",
            recommended_action="Maintain tamper-evident AuditLog capture for all access and disclosures.",
        ),
        ComplianceControl(
            control_id="AU-APP-8-CROSS",
            framework_id="AUSTRALIA_PRIVACY",
            title="APP 8: Cross-Border Disclosure of Personal Information & Sovereign Fencing",
            requirement="Prevent unauthorized overseas disclosure of Australian personal information outside ap-southeast-2.",
            category="DATA_RESIDENCY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="Privacy Act 1988 Schedule 1 — APP 8 & Section 16C",
            recommended_action="Enforce ap-southeast-2 sovereign telemetry boundary fencing.",
        ),
        ComplianceControl(
            control_id="AU-APP-9-GOVID",
            framework_id="AUSTRALIA_PRIVACY",
            title="APP 9: Protection Against Unauthorized Adoption/Disclosure of Government Identifiers (TFN/Medicare)",
            requirement="Restrict access to Australian government-related identifiers (TFN, Medicare) using RBAC least privilege.",
            category="ACCESS_CONTROL",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Privacy Act 1988 Schedule 1 — APP 9",
            recommended_action="Enforce strict RBAC access controls over Australian identifier stores.",
        ),
        ComplianceControl(
            control_id="AU-APP-10-12-13-RIGHTS",
            framework_id="AUSTRALIA_PRIVACY",
            title="APP 10, APP 12 & APP 13: Quality, Access to & Correction of Personal Information",
            requirement="Respond to individual access (APP 12) and correction/quality (APP 10 & APP 13) requests within 30 calendar days.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Privacy Act 1988 Schedule 1 — APP 10, APP 12 & APP 13",
            recommended_action="Fulfill open Australian access and correction DSRs within 30 days.",
        ),
        ComplianceControl(
            control_id="AU-APP-11-1-SEC",
            framework_id="AUSTRALIA_PRIVACY",
            title="APP 11.1: Security of Personal Information (DSPM & Encryption Safeguards)",
            requirement="Take reasonable technical steps to protect personal information from misuse, interference, loss, and unauthorized access.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="Privacy Act 1988 Schedule 1 — APP 11.1",
            recommended_action="Remediate exposed PII datastores in DSPM and enable AES-256 encryption.",
        ),
        ComplianceControl(
            control_id="AU-APP-11-2-DESTROY",
            framework_id="AUSTRALIA_PRIVACY",
            title="APP 11.2: Destruction or De-Identification When No Longer Needed",
            requirement="Take reasonable steps to destroy or de-identify personal information once no longer needed for permitted purposes.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Privacy Act 1988 Schedule 1 — APP 11.2",
            recommended_action="Enforce 90-day automated telemetry pruning.",
        ),
        ComplianceControl(
            control_id="AU-NDB-PART-IIIC",
            framework_id="AUSTRALIA_PRIVACY",
            title="Part IIIC: OAIC Notifiable Data Breaches (NDB) Scheme Readiness",
            requirement="Contain and assess eligible data breaches likely to result in serious harm within 30 days and notify OAIC.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="Privacy Act 1988 Part IIIC (Sections 26WE–26WL)",
            recommended_action="Triage open critical security incidents immediately.",
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
                "AU-APP-1-2-GOV",
                "APP 1 & APP 2: APP Privacy Policy & Anonymity/Pseudonymity Governance",
                "Verify published APP 1 Privacy Policy and APP 2 anonymity option where lawful and practicable.",
                "Privacy Act 1988 APP 1 & APP 2",
                "Published APP Privacy Policy URL & Privacy Governance Charter",
                tenant_id=tenant_id,
            ),
            await self.probe_dlp_classifier_coverage(tenant_id, "AU", db, "AU-APP-3-4-COL", "Privacy Act 1988 APP 3 & APP 4"),
            await self.probe_visual_privacy_consent(tenant_id, db, "AU-APP-5-NOTICE", "Privacy Act 1988 APP 5"),
            await self.probe_audit_logging_active(tenant_id, db, "AU-APP-6-7-USE", "Privacy Act 1988 APP 6 & APP 7"),
            await self.probe_data_residency_fencing(tenant_id, "ap-southeast-2", db, "AU-APP-8-CROSS", "Privacy Act 1988 APP 8"),
            await self.probe_access_control_rbac_mfa(tenant_id, db, "AU-APP-9-GOVID", "Privacy Act 1988 APP 9"),
            await self.probe_privacy_request_sla(tenant_id, db, "AU-APP-10-12-13-RIGHTS", "Privacy Act 1988 APP 10, 12 & 13", sla_days=30),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "AU-APP-11-1-SEC", "Privacy Act 1988 APP 11.1"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "AU-APP-11-2-DESTROY", "Privacy Act 1988 APP 11.2"),
            await self.probe_incident_response_backlog(tenant_id, db, "AU-NDB-PART-IIIC", "Privacy Act 1988 Part IIIC"),
        ]


async def run_australia_privacy_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await AustraliaPrivacyFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
