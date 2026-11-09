"""
[v4.4.0] EU General Data Protection Regulation (GDPR) — Regulation (EU) 2016/679
Preserves and extends existing Monitorix GDPR controls: Art. 5 minimization (90-day pruning),
Art. 6 monitoring consent, Art. 15-20 DSR & SQL erasure, Art. 25/32 security/encryption,
Art. 30/5(2) audit accountability, Art. 33/34 72h breach readiness, Art. 44-49 boundary fencing.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class GdprFramework(BaseComplianceFramework):
    framework_id = "GDPR"
    name = "General Data Protection Regulation (GDPR)"
    region = "EU"
    jurisdiction = "European Union / EEA"
    category = FrameworkCategory.PRIVACY
    version = "Regulation (EU) 2016/679"
    effective_from = "2018-05-25"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "European Data Protection Board (EDPB) & National DPAs"
    breach_notification_window = "72 Hours (Art. 33)"
    residency_region = "eu-central-1"
    source_reference = "Official Journal of the European Union, L 119, 4 May 2016"
    supported_privacy_rights = ["ACCESS", "DELETE", "RECTIFY", "RESTRICT", "OBJECT", "PORTABILITY"]

    controls = [
        ComplianceControl(
            control_id="GDPR-ART-5-1-E",
            framework_id="GDPR",
            title="Storage Limitation & 90-Day Event Pruning (Art. 5(1)(e))",
            requirement="Personal data shall be kept in a form which permits identification of data subjects for no longer than necessary.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="GDPR Art. 5(1)(c) & Art. 5(1)(e)",
            recommended_action="Configure 90-day telemetry pruning schedule.",
            automated_remediation_available=True,
        ),
        ComplianceControl(
            control_id="GDPR-ART-6-CONSENT",
            framework_id="GDPR",
            title="Lawfulness of Processing & Workplace Visual Monitoring Consent (Art. 6)",
            requirement="Processing of employee desktop telemetry requires lawful basis, transparency notice, and consent flags where applicable.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.MEDIUM,
            legal_reference="GDPR Art. 6(1) & Art. 13",
            recommended_action="Enable MonitoringConsentRequired banner on agents with visual telemetry.",
        ),
        ComplianceControl(
            control_id="GDPR-ART-17-DSR",
            framework_id="GDPR",
            title="Data Subject Rights & Right to Erasure Workflow (Art. 15-20)",
            requirement="Fulfill data subject access, rectification, portability, restriction, objection, and SQL erasure requests within 30 days.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="GDPR Art. 15, 16, 17, 18, 20 & 21",
            recommended_action="Process open DSR requests within statutory 30-day SLA.",
        ),
        ComplianceControl(
            control_id="GDPR-ART-25-PII",
            framework_id="GDPR",
            title="Data Protection by Design & PII Discovery Inventory (Art. 25)",
            requirement="Maintain technical capability to discover and classify personal identifiers across telemetry and datastores.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="GDPR Art. 25",
            recommended_action="Ensure European PII classifiers are active in DLP/DSPM.",
        ),
        ComplianceControl(
            control_id="GDPR-ART-32-SEC",
            framework_id="GDPR",
            title="Security of Processing & Sensitive Data Exposure Safeguards (Art. 32)",
            requirement="Implement technical measures including pseudonymisation, encryption, and access controls for personal data.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="GDPR Art. 32(1)",
            recommended_action="Remediate unencrypted or publicly exposed PII datastores in DSPM.",
            automated_remediation_available=True,
        ),
        ComplianceControl(
            control_id="GDPR-ART-32-ENC",
            framework_id="GDPR",
            title="Cryptographic Protection at Rest & TLS 1.3 in Transit (Art. 32(1)(a))",
            requirement="Enforce AES-256 encryption at rest and mTLS/TLS 1.3 transport security.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="GDPR Art. 32(1)(a)",
            recommended_action="Encrypt all datastores at rest and enforce mTLS.",
        ),
        ComplianceControl(
            control_id="GDPR-ART-5-2-AUDIT",
            framework_id="GDPR",
            title="Accountability & Immutable Administrative Audit Trail (Art. 5(2) / Art. 30)",
            requirement="Controller shall be responsible for, and be able to demonstrate compliance with, data protection principles.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="GDPR Art. 5(2) & Art. 30",
            recommended_action="Maintain tamper-evident AuditLog records for all privileged actions.",
        ),
        ComplianceControl(
            control_id="GDPR-ART-33-BREACH",
            framework_id="GDPR",
            title="72-Hour Supervisory Authority Breach Notification Readiness (Art. 33/34)",
            requirement="Notify competent supervisory authority within 72 hours after becoming aware of a personal data breach.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="GDPR Art. 33 & Art. 34",
            recommended_action="Triage critical security incidents within 72-hour notification SLA.",
        ),
        ComplianceControl(
            control_id="GDPR-ART-44-RESIDENCY",
            framework_id="GDPR",
            title="Cross-Border Transfer Restrictions & Sovereign Boundary Fencing (Art. 44-49)",
            requirement="Prevent unauthorized export of raw European personal data outside sovereign EEA boundaries.",
            category="DATA_RESIDENCY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="GDPR Chapter V (Art. 44-49)",
            recommended_action="Enforce sovereign boundary fencing on eu-central-1 gateway.",
        ),
        ComplianceControl(
            control_id="GDPR-ART-28-37-GOV",
            framework_id="GDPR",
            title="DPO Designation, Art. 28 DPAs & Art. 35 DPIA Records (Manual Review)",
            requirement="Maintain signed Data Processing Agreements (Art. 28), DPIAs (Art. 35), and DPO appointment records (Art. 37).",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="GDPR Art. 28, Art. 35 & Art. 37",
            recommended_action="Attach signed Art. 28 DPAs, DPIA sign-off, and DPO registration details.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        return [
            await self.probe_telemetry_retention(tenant_id, 90, db, "GDPR-ART-5-1-E", "GDPR Art. 5(1)(e)"),
            await self.probe_visual_privacy_consent(tenant_id, db, "GDPR-ART-6-CONSENT", "GDPR Art. 6(1)"),
            await self.probe_privacy_request_sla(tenant_id, db, "GDPR-ART-17-DSR", "GDPR Art. 15-20", sla_days=30),
            await self.probe_dlp_classifier_coverage(tenant_id, "EU", db, "GDPR-ART-25-PII", "GDPR Art. 25"),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "GDPR-ART-32-SEC", "GDPR Art. 32(1)"),
            await self.probe_encryption_and_tls(tenant_id, db, "GDPR-ART-32-ENC", "GDPR Art. 32(1)(a)"),
            await self.probe_audit_logging_active(tenant_id, db, "GDPR-ART-5-2-AUDIT", "GDPR Art. 5(2)"),
            await self.probe_incident_response_backlog(tenant_id, db, "GDPR-ART-33-BREACH", "GDPR Art. 33"),
            await self.probe_data_residency_fencing(tenant_id, "eu-central-1", db, "GDPR-ART-44-RESIDENCY", "GDPR Art. 44-49"),
            self.manual_review_control(
                "GDPR-ART-28-37-GOV",
                "DPO Designation, Art. 28 DPAs & Art. 35 DPIA Records",
                "Verify legal contracts with sub-processors, high-risk DPIAs, and DPO contact publication.",
                "GDPR Art. 28, 35, 37",
                "Signed Art. 28 Processor Agreements, Art. 35 DPIA Register, and Art. 37 DPO Filing",
                tenant_id=tenant_id,
            ),
        ]


async def run_gdpr_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await GdprFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
