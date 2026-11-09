"""
[v4.4.0] UK GDPR & Data Protection Act 2018 Implementation
Completes UK-specific compliance controls: UK PII discovery (NINO, NHS Number Modulo-11,
UK Passport, Postcode, Sort Code), Art. 5 minimization, Art. 6 workplace consent,
UK DSR workflows, Art. 32 technical security, ICO 72-hour regulatory breach reporting,
UK IDTA sovereign boundary (eu-west-2), and DPA 2018 Schedule 1 Appropriate Policy Document.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class UkGdprFramework(BaseComplianceFramework):
    framework_id = "UK_GDPR"
    name = "UK GDPR & Data Protection Act 2018"
    region = "GB"
    jurisdiction = "United Kingdom"
    category = FrameworkCategory.PRIVACY
    version = "DPA 2018 c. 12 / Retained EU Law"
    effective_from = "2021-01-01"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Information Commissioner's Office (ICO)"
    breach_notification_window = "72 Hours to ICO (UK GDPR Art. 33)"
    residency_region = "eu-west-2"
    source_reference = "Data Protection Act 2018 (c. 12) & UK GDPR (ICO Guidance)"
    supported_privacy_rights = ["ACCESS", "DELETE", "RECTIFY", "RESTRICT", "OBJECT", "PORTABILITY"]

    controls = [
        ComplianceControl(
            control_id="UK-GDPR-PII-INV",
            framework_id="UK_GDPR",
            title="UK Personal Identifier Discovery (NINO, NHS Modulo-11, Passport, Sort Code)",
            requirement="Maintain technical discovery classifiers for UK National Insurance Numbers (NINO), NHS Numbers (Modulo-11), UK Passports, Postcodes, and Sort Codes.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="UK GDPR Art. 25 & DPA 2018 Part 2",
            recommended_action="Ensure UK PII classifiers (GB) are active in DLP and DSPM.",
        ),
        ComplianceControl(
            control_id="UK-GDPR-ART-5-RET",
            framework_id="UK_GDPR",
            title="Storage Limitation & 90-Day Telemetry Pruning (Art. 5(1)(e))",
            requirement="Retain UK personal data no longer than necessary for specified lawful purposes.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="UK GDPR Art. 5(1)(e)",
            recommended_action="Enforce 90-day retention pruning schedule.",
        ),
        ComplianceControl(
            control_id="UK-GDPR-ART-6-WORK",
            framework_id="UK_GDPR",
            title="ICO Employment Monitoring Transparency & Consent (Art. 6)",
            requirement="Ensure workplace visual monitoring adheres to ICO Employment Practices guidance with notice/consent flags.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.MEDIUM,
            legal_reference="UK GDPR Art. 6 & ICO Employment Monitoring Guidance",
            recommended_action="Enable MonitoringConsentRequired on monitored UK endpoints.",
        ),
        ComplianceControl(
            control_id="UK-GDPR-ART-15-DSR",
            framework_id="UK_GDPR",
            title="UK Data Subject Access, Rectification & Erasure Workflow (Art. 15-22)",
            requirement="Respond to UK Subject Access Requests (SARs) and erasure requests within 1 calendar month.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="UK GDPR Art. 15-22 & DPA 2018 Sec. 45-48",
            recommended_action="Complete open UK DSR/SAR requests within 30 days.",
        ),
        ComplianceControl(
            control_id="UK-GDPR-ART-32-SEC",
            framework_id="UK_GDPR",
            title="Security of Processing for UK NINO / NHS Health & Personal Data (Art. 32)",
            requirement="Protect UK personal and special-category health data against unauthorized exposure.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="UK GDPR Art. 32",
            recommended_action="Remediate exposed PII/PHI findings in DSPM.",
        ),
        ComplianceControl(
            control_id="UK-GDPR-ART-32-ENC",
            framework_id="UK_GDPR",
            title="Encryption at Rest & TLS 1.3 Transport Security (Art. 32(1)(a))",
            requirement="Enforce strong encryption for stored and transmitted UK personal data.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="UK GDPR Art. 32(1)(a)",
            recommended_action="Enable AES-256 encryption at rest across all datastores.",
        ),
        ComplianceControl(
            control_id="UK-GDPR-ART-33-ICO",
            framework_id="UK_GDPR",
            title="ICO 72-Hour Regulatory Breach Reporting Readiness (Art. 33)",
            requirement="Assess and report notifiable personal data breaches to the UK ICO within 72 hours.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="UK GDPR Art. 33 & Art. 34",
            recommended_action="Triage open critical security incidents within ICO 72-hour window.",
        ),
        ComplianceControl(
            control_id="UK-GDPR-ART-44-IDTA",
            framework_id="UK_GDPR",
            title="UK International Data Transfer Restrictions & Boundary Fencing (Art. 44-49)",
            requirement="Enforce UK sovereign boundary fencing (eu-west-2) or approved UK IDTA/Addendum safeguards.",
            category="DATA_RESIDENCY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="UK GDPR Art. 44-49 & UK International Data Transfer Agreement (IDTA)",
            recommended_action="Enforce sovereign boundary fencing for eu-west-2.",
        ),
        ComplianceControl(
            control_id="UK-DPA-SCH1-APD",
            framework_id="UK_GDPR",
            title="ICO Data Protection Fee Registration & DPA 2018 Schedule 1 Policy Document",
            requirement="Maintain active ICO Data Protection Fee registration and Appropriate Policy Document (APD) for special category / criminal offence data.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="DPA 2018 Schedule 1 Part 4 & Data Protection (Charges and Information) Regulations 2018",
            recommended_action="Attach ICO Registration Number and signed Schedule 1 Appropriate Policy Document.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "GB", db, "UK-GDPR-PII-INV", "UK GDPR Art. 25"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "UK-GDPR-ART-5-RET", "UK GDPR Art. 5(1)(e)"),
            await self.probe_visual_privacy_consent(tenant_id, db, "UK-GDPR-ART-6-WORK", "UK GDPR Art. 6"),
            await self.probe_privacy_request_sla(tenant_id, db, "UK-GDPR-ART-15-DSR", "UK GDPR Art. 15-22", sla_days=30),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "UK-GDPR-ART-32-SEC", "UK GDPR Art. 32"),
            await self.probe_encryption_and_tls(tenant_id, db, "UK-GDPR-ART-32-ENC", "UK GDPR Art. 32(1)(a)"),
            await self.probe_incident_response_backlog(tenant_id, db, "UK-GDPR-ART-33-ICO", "UK GDPR Art. 33"),
            await self.probe_data_residency_fencing(tenant_id, "eu-west-2", db, "UK-GDPR-ART-44-IDTA", "UK GDPR Art. 44-49"),
            self.manual_review_control(
                "UK-DPA-SCH1-APD",
                "ICO Registration Certificate & DPA 2018 Schedule 1 Appropriate Policy Document",
                "Verify active ICO controller registration and Schedule 1 Appropriate Policy Document.",
                "DPA 2018 Schedule 1 Part 4",
                "ICO Registration Certificate (ZB/ZA Number) & Schedule 1 APD",
                tenant_id=tenant_id,
            ),
        ]


async def run_uk_gdpr_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await UkGdprFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
