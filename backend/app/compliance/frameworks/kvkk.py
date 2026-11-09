"""
[v4.4.0] Türkiye KVKK (Kişisel Verilerin Korunması Kanunu, Law No. 6698 as amended 2024)
Covers 11-digit T.C. Kimlik No (Dual Modulo-10) & Turkish VKN/IBAN discovery, Retention & Periodic
Destruction (Madde 4/7), Explicit Consent & Aydınlatma Metni Obligation to Inform (Madde 5 & 10),
Data Subject Application Rights Within 30 Days (Madde 11 & 13), Technical & Administrative Security
Measures (Madde 12: Encryption, RBAC, Audit Logs, Vulnerability Management), 72-Hour KVKK Board
Breach Notification (Madde 12(5)), Cross-Border Transfers (2024 Amended Madde 9, me-central-1),
and VERBİS Data Controllers' Registry Obligation (Madde 16 MANUAL_REVIEW).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class KvkkFramework(BaseComplianceFramework):
    framework_id = "KVKK"
    name = "Türkiye Kişisel Verilerin Korunması Kanunu (KVKK No. 6698)"
    region = "TR"
    jurisdiction = "Republic of Türkiye"
    category = FrameworkCategory.PRIVACY
    version = "Kanun No. 6698 (2024 Cross-Border Amendment)"
    effective_from = "2016-04-07"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Kişisel Verileri Koruma Kurumu (KVKK)"
    breach_notification_window = "Within 72 Hours to KVKK Board per Decision 2019/10 (Madde 12(5))"
    residency_region = "me-central-1"
    source_reference = "Kişisel Verileri Koruma Kurumu (KVKK), Resmî Gazete Sayı: 29677"
    supported_privacy_rights = ["ACCESS", "DELETE", "CORRECT", "RECTIFY", "OBJECT"]

    controls = [
        ComplianceControl(
            control_id="KVKK-TCKN-DISC",
            framework_id="KVKK",
            title="Madde 3 & 6: T.C. Kimlik Numarası & Özel Nitelikli Kişisel Veri Discovery",
            requirement="Discover and classify 11-digit T.C. Kimlik Numbers (dual Modulo-10 checksum), VKN tax IDs, TR IBANs, and Passports.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="KVKK Madde 3 & Madde 6",
            recommended_action="Ensure Türkiye (TR) PII classifiers are active across DLP/DSPM.",
        ),
        ComplianceControl(
            control_id="KVKK-MADDE-4-MIN",
            framework_id="KVKK",
            title="Madde 4 & Madde 7: Storage Limitation, Deletion, Destruction or Anonymization",
            requirement="Delete, destroy, or anonymize personal data ex officio or upon request when grounds for processing cease to exist.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="KVKK Madde 4(2)(d) & Madde 7",
            recommended_action="Enforce 90-day automated telemetry pruning.",
        ),
        ComplianceControl(
            control_id="KVKK-MADDE-10-NOTICE",
            framework_id="KVKK",
            title="Madde 5 & Madde 10: Açık Rıza (Explicit Consent) & Aydınlatma Yükümlülüğü",
            requirement="Fulfill the controller's obligation to inform (Aydınlatma Metni) and enforce consent banners on visually monitored endpoints.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="KVKK Madde 5 & Madde 10",
            recommended_action="Enable MonitoringConsentRequired notice banners on visually monitored endpoints.",
        ),
        ComplianceControl(
            control_id="KVKK-MADDE-11-DSR",
            framework_id="KVKK",
            title="Madde 11 & Madde 13: İlgili Kişinin Hakları (Data Subject Applications — 30-Day SLA)",
            requirement="Conclude data subject rights applications under Madde 11 free of charge as soon as possible and within 30 days at the latest.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="KVKK Madde 11 & Madde 13(2)",
            recommended_action="Fulfill open KVKK Madde 11 applications within 30 days.",
        ),
        ComplianceControl(
            control_id="KVKK-MADDE-12-SEC",
            framework_id="KVKK",
            title="Madde 12(1): Technical Safeguards Against Unlawful Processing & Access",
            requirement="Take all necessary technical and administrative measures to prevent unlawful processing and unlawful access to personal data.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="KVKK Madde 12(1) & KVKK Technical Measures Guide",
            recommended_action="Remediate exposed Turkish PII datastores in DSPM.",
        ),
        ComplianceControl(
            control_id="KVKK-MADDE-12-ENC",
            framework_id="KVKK",
            title="Madde 12 & Board Decision 2018/10: Cryptographic Storage & Secure Key Protection",
            requirement="Encrypt personal and special-category data at rest using strong cryptographic algorithms and enforce TLS 1.3.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="KVKK Madde 12 & Board Decision 2018/10 (Özel Nitelikli Veriler)",
            recommended_action="Enable AES-256 datastore encryption and TLS 1.3.",
        ),
        ComplianceControl(
            control_id="KVKK-MADDE-12-RBAC",
            framework_id="KVKK",
            title="Madde 12 Technical Guide: Authority Matrix & Role-Based Access Control",
            requirement="Maintain a strict role-based authority matrix limiting user access to personal data.",
            category="ACCESS_CONTROL",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="KVKK Madde 12(1)",
            recommended_action="Enforce tenant-scoped RBAC least-privilege roles.",
        ),
        ComplianceControl(
            control_id="KVKK-MADDE-12-AUDIT",
            framework_id="KVKK",
            title="Madde 12 Technical Guide: Tamper-Proof Transaction & Access Log Records",
            requirement="Record all personal data system transactions in a manner preventing user intervention or modification.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="KVKK Madde 12(1)",
            recommended_action="Maintain tamper-evident AuditLog records.",
        ),
        ComplianceControl(
            control_id="KVKK-MADDE-12-BREACH",
            framework_id="KVKK",
            title="Madde 12(5) & Madde 9: 72-Hour KVKK Board Breach Notice & Cross-Border Transfer Fencing",
            requirement="Notify the KVKK Board within 72 hours of unlawful acquisition of personal data (Decision 2019/10) and enforce Madde 9 sovereign fencing (me-central-1).",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="KVKK Madde 9 (2024 Amendment) & Madde 12(5)",
            recommended_action="Triage critical incidents within 72h and enforce me-central-1 fencing.",
        ),
        ComplianceControl(
            control_id="KVKK-MADDE-16-VERBIS",
            framework_id="KVKK",
            title="Madde 16: VERBİS (Veri Sorumluları Sicili) Registration & Destruction Policy",
            requirement="Register in the Data Controllers' Registry Information System (VERBİS) prior to data processing, appoint Contact Person (İrtibat Kişisi), and maintain a Personal Data Retention & Destruction Policy.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="KVKK Madde 16 & Regulation on Deletion, Destruction or Anonymization",
            recommended_action="Attach VERBİS Registration Certificate, Contact Person Filing, and Signed İmha Politikası.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        res_check = await self.probe_data_residency_fencing(tenant_id, "me-central-1", db, "KVKK-MADDE-12-BREACH", "KVKK Madde 9")
        inc_check = await self.probe_incident_response_backlog(tenant_id, db, "KVKK-MADDE-12-BREACH", "KVKK Madde 12(5)")
        combined = inc_check if inc_check.status.value != "PASS" else res_check
        combined.control_id = "KVKK-MADDE-12-BREACH"

        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "TR", db, "KVKK-TCKN-DISC", "KVKK Madde 3 & 6"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "KVKK-MADDE-4-MIN", "KVKK Madde 4 & 7"),
            await self.probe_visual_privacy_consent(tenant_id, db, "KVKK-MADDE-10-NOTICE", "KVKK Madde 5 & 10"),
            await self.probe_privacy_request_sla(tenant_id, db, "KVKK-MADDE-11-DSR", "KVKK Madde 11 & 13", sla_days=30),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "KVKK-MADDE-12-SEC", "KVKK Madde 12(1)"),
            await self.probe_encryption_and_tls(tenant_id, db, "KVKK-MADDE-12-ENC", "KVKK Madde 12 & Decision 2018/10"),
            await self.probe_access_control_rbac_mfa(tenant_id, db, "KVKK-MADDE-12-RBAC", "KVKK Madde 12(1)"),
            await self.probe_audit_logging_active(tenant_id, db, "KVKK-MADDE-12-AUDIT", "KVKK Madde 12(1)"),
            combined,
            self.manual_review_control(
                "KVKK-MADDE-16-VERBIS",
                "VERBİS Registry Enrollment & Personal Data Destruction Policy",
                "Verify active registration on VERBİS (verbis.kvkk.gov.tr), Madde 9 Standard Contractual Clauses filing with KVKK within 5 business days where applicable, and Retention/Destruction Policy.",
                "KVKK Madde 9 & Madde 16",
                "VERBİS Registration Extract, İrtibat Kişisi Appointment & Veri Saklama ve İmha Politikası",
                tenant_id=tenant_id,
            ),
        ]


async def run_kvkk_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await KvkkFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
