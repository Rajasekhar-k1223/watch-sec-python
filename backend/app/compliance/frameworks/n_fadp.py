"""
[v4.4.0] Switzerland Revised Federal Act on Data Protection (nFADP / revDSG, SR 235.1)
Covers Swiss AHV/AVS 13-digit Social Security Number (EAN-13) & UID discovery, Proportionality
& Storage Limitation (Art. 6), Privacy by Design & Default (Art. 7), Data Security Ordinance
(DSV Art. 1–5 / nFADP Art. 8: Encryption, RBAC, Automated Protocol Logging), Duty to Inform
(Art. 19), FDPIC Breach Notification (Art. 24), Cross-Border Disclosure (Art. 16, eu-central-2),
Right of Access & Data Portability (Art. 25 & 28), and Inventory of Processing / Data Protection
Advisor (Art. 10 & 12 MANUAL_REVIEW).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class NFadpFramework(BaseComplianceFramework):
    framework_id = "N_FADP"
    name = "Switzerland Revised Federal Act on Data Protection (nFADP / revDSG)"
    region = "CH"
    jurisdiction = "Swiss Confederation"
    category = FrameworkCategory.PRIVACY
    version = "SR 235.1 (Effective 1 Sept 2023)"
    effective_from = "2023-09-01"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Federal Data Protection and Information Commissioner (FDPIC / EDÖB)"
    breach_notification_window = "As Quickly As Possible to FDPIC for High-Risk Breaches (Art. 24)"
    residency_region = "eu-central-2"
    source_reference = "Federal Data Protection and Information Commissioner (FDPIC), SR 235.1 & DPO Ordinance SR 235.11"
    supported_privacy_rights = ["ACCESS", "DELETE", "CORRECT", "RECTIFY", "RESTRICT", "OBJECT", "PORTABILITY"]

    controls = [
        ComplianceControl(
            control_id="FADP-AHV-DISC",
            framework_id="N_FADP",
            title="Article 5: Swiss AHV/AVS (EAN-13), UID & Sensitive Personal Data Discovery",
            requirement="Discover and classify 13-digit Swiss AHV/AVS numbers (756.xxxx.xxxx.xx EAN-13), UID enterprise identifiers, IBANs, and Passports.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="nFADP Article 5",
            recommended_action="Ensure Switzerland (CH) PII classifiers are active across DLP/DSPM.",
        ),
        ComplianceControl(
            control_id="FADP-ART-6-MIN",
            framework_id="N_FADP",
            title="Article 6(4): Proportionality, Purpose Binding & Destruction/Anonymization",
            requirement="Destroy or anonymize personal data as soon as it is no longer required for the purpose of processing.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="nFADP Article 6(2)–(4)",
            recommended_action="Enforce 90-day automated telemetry pruning.",
        ),
        ComplianceControl(
            control_id="FADP-ART-19-INFO",
            framework_id="N_FADP",
            title="Articles 7 & 19: Privacy by Default & Duty to Inform Data Subjects",
            requirement="Inform data subjects adequately upon acquisition of personal data and enforce privacy-by-default consent flags on monitored endpoints.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.MEDIUM,
            legal_reference="nFADP Articles 7 & 19",
            recommended_action="Enable MonitoringConsentRequired notice banners on visually monitored endpoints.",
        ),
        ComplianceControl(
            control_id="FADP-ART-25-RIGHTS",
            framework_id="N_FADP",
            title="Articles 25, 28 & 32: Right to Information, Data Portability & Erasure (30-Day SLA)",
            requirement="Provide information and portable data exports free of charge generally within 30 days under DSV Art. 18.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="nFADP Articles 25, 28 & 32; DSV Art. 18",
            recommended_action="Fulfill open Swiss nFADP DSR requests within 30 days.",
        ),
        ComplianceControl(
            control_id="FADP-ART-8-SEC",
            framework_id="N_FADP",
            title="Article 8 & DSV Art. 1–3: Data Security & Sensitive Exposure Prevention",
            requirement="Ensure appropriate technical and organizational data security commensurate with risk (criminal liability up to CHF 250,000 under Art. 61(c) for intentional breach).",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="nFADP Article 8 & Article 61(c); DSV Art. 1–3",
            recommended_action="Remediate exposed Swiss PII datastores in DSPM.",
        ),
        ComplianceControl(
            control_id="FADP-DSV-ENC",
            framework_id="N_FADP",
            title="DSV Article 3: Confidentiality & Cryptographic Transport/Storage Controls",
            requirement="Protect confidentiality and integrity via AES-256 encryption at rest and TLS 1.3 in transit.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Data Protection Ordinance (DSV / VDSG) Article 3",
            recommended_action="Enable encryption at rest across all datastores.",
        ),
        ComplianceControl(
            control_id="FADP-DSV-RBAC",
            framework_id="N_FADP",
            title="DSV Article 3(a): Access, User & Transport Control (RBAC)",
            requirement="Restrict authorized persons' access exclusively to the personal data they need to perform their duties.",
            category="ACCESS_CONTROL",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Data Protection Ordinance (DSV) Article 3(a)",
            recommended_action="Enforce tenant-scoped RBAC least-privilege access.",
        ),
        ComplianceControl(
            control_id="FADP-DSV-ART4-LOG",
            framework_id="N_FADP",
            title="DSV Article 4: Mandatory Automated Processing Protocol Logging",
            requirement="Maintain tamper-evident automated processing logs retained separately for at least 1 year where high-risk sensitive data is processed.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Data Protection Ordinance (DSV) Article 4",
            recommended_action="Maintain tamper-evident AuditLog records.",
        ),
        ComplianceControl(
            control_id="FADP-ART-24-BREACH",
            framework_id="N_FADP",
            title="Article 24 & Article 16: FDPIC Data Breach Portal Notification & Swiss Residency (eu-central-2)",
            requirement="Notify the FDPIC as quickly as possible of any data security breach posing high risk and enforce eu-central-2 cross-border transfer fencing.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="nFADP Articles 16, 17 & 24",
            recommended_action="Triage critical security incidents promptly and enforce eu-central-2 fencing.",
        ),
        ComplianceControl(
            control_id="FADP-ART-12-ROPA",
            framework_id="N_FADP",
            title="Articles 10, 12, 14 & 22: Inventory of Processing Activities, Swiss Representative & DPIA",
            requirement="Maintain an Inventory of Processing Activities (Art. 12), conduct DPIAs (Art. 22), and appoint a Data Protection Advisor (Art. 10) / Swiss Rep (Art. 14) if applicable.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="nFADP Articles 10, 12, 14 & 22",
            recommended_action="Attach Article 12 Verzeichnis der Bearbeitungstätigkeiten (RoPA) and FDPIC Advisor Registration.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        res_check = await self.probe_data_residency_fencing(tenant_id, "eu-central-2", db, "FADP-ART-24-BREACH", "nFADP Article 16")
        inc_check = await self.probe_incident_response_backlog(tenant_id, db, "FADP-ART-24-BREACH", "nFADP Article 24")
        combined = inc_check if inc_check.status.value != "PASS" else res_check
        combined.control_id = "FADP-ART-24-BREACH"

        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "CH", db, "FADP-AHV-DISC", "nFADP Article 5"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "FADP-ART-6-MIN", "nFADP Article 6"),
            await self.probe_visual_privacy_consent(tenant_id, db, "FADP-ART-19-INFO", "nFADP Articles 7 & 19"),
            await self.probe_privacy_request_sla(tenant_id, db, "FADP-ART-25-RIGHTS", "nFADP Articles 25 & 28", sla_days=30),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "FADP-ART-8-SEC", "nFADP Article 8"),
            await self.probe_encryption_and_tls(tenant_id, db, "FADP-DSV-ENC", "DSV Article 3"),
            await self.probe_access_control_rbac_mfa(tenant_id, db, "FADP-DSV-RBAC", "DSV Article 3(a)"),
            await self.probe_audit_logging_active(tenant_id, db, "FADP-DSV-ART4-LOG", "DSV Article 4"),
            combined,
            self.manual_review_control(
                "FADP-ART-12-ROPA",
                "Article 12 Processing Inventory (RoPA), DPIA & FDPIC Advisor",
                "Verify statutory Article 12 Inventory of Processing Activities, Article 22 DPIA documentation, and FDPIC Data Protection Advisor notification.",
                "nFADP Articles 10, 12, 14 & 22",
                "Signed Article 12 Processing Inventory & FDPIC Advisor Registration",
                tenant_id=tenant_id,
            ),
        ]


async def run_nfadp_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await NFadpFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
