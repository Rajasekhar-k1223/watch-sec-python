"""
[v4.4.0] Indonesia PDP Law (Undang-Undang No. 27 Tahun 2022 tentang Pelindungan Data Pribadi)
Covers 16-digit NIK & NPWP discovery (Pasal 4), Explicit Consent & Purpose (Pasal 20–27),
Data Subject Rights Within 3x24 Hours (Pasal 5–13), Security & Confidentiality Measures
(Pasal 35–39: Encryption, RBAC, Record of Operations / Audit Logs), Retention & Deletion
(Pasal 42–44), 3x24 Hour (72-Hour) Written Breach Notification (Pasal 46), Cross-Border
Transfer Controls (Pasal 56, ap-southeast-3), and DPO Designation / DPIA (Pasal 34 & 53 MANUAL_REVIEW).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class IndonesiaPdpFramework(BaseComplianceFramework):
    framework_id = "INDONESIA_PDP"
    name = "Indonesia Personal Data Protection Law (UU No. 27 Tahun 2022)"
    region = "ID"
    jurisdiction = "Republic of Indonesia"
    category = FrameworkCategory.PRIVACY
    version = "UU No. 27 Tahun 2022 (Full Enforcement Oct 2024)"
    effective_from = "2024-10-17"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Ministry of Communication and Digital Affairs (Komdigi) / PDP Agency Indonesia"
    breach_notification_window = "Within 3 x 24 Hours (72 Hours) Written Notice to Data Subjects & Authority (Pasal 46)"
    residency_region = "ap-southeast-3"
    source_reference = "Lembaran Negara Republik Indonesia Tahun 2022 Nomor 196 (UU PDP)"
    supported_privacy_rights = ["ACCESS", "DELETE", "CORRECT", "RECTIFY", "RESTRICT", "OBJECT", "PORTABILITY"]

    controls = [
        ComplianceControl(
            control_id="ID-PDP-NIK-DISC",
            framework_id="INDONESIA_PDP",
            title="Pasal 4: Specific & General Indonesian Personal Data Discovery (NIK, NPWP)",
            requirement="Classify general and specific personal data including 16-digit NIK (Nomor Induk Kependudukan), 15/16-digit NPWP, Passports, and Mobile numbers.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="UU No. 27/2022 Pasal 4",
            recommended_action="Ensure Indonesia (ID) PII classifiers are active across DLP/DSPM.",
        ),
        ComplianceControl(
            control_id="ID-PDP-PASAL-20-CONSENT",
            framework_id="INDONESIA_PDP",
            title="Pasal 20–24 & 27: Explicit Valid Consent & Transparent Purpose Specification",
            requirement="Obtain valid explicit written/recorded consent in clear language prior to collecting visual endpoint telemetry.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="UU No. 27/2022 Pasal 20–24 & 27",
            recommended_action="Enforce MonitoringConsentRequired notice banners on visually monitored endpoints.",
        ),
        ComplianceControl(
            control_id="ID-PDP-PASAL-5-DSR",
            framework_id="INDONESIA_PDP",
            title="Pasal 5–13 & 32–33: Data Subject Access, Rectification, Termination & Portability",
            requirement="Grant access, correction, suspension, and deletion rights promptly in accordance with statutory 3x24h response windows.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="UU No. 27/2022 Pasal 5–13, 32 & 33",
            recommended_action="Fulfill open Indonesia UU PDP DSR requests without delay.",
        ),
        ComplianceControl(
            control_id="ID-PDP-ART-35-SEC",
            framework_id="INDONESIA_PDP",
            title="Pasal 35 & 39: Technical Security Measures & Prevention of Unlawful Access",
            requirement="Protect personal data from unauthorized processing and ensure security of personal data processed via electronic systems.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="UU No. 27/2022 Pasal 35 & 39",
            recommended_action="Remediate exposed Indonesian PII datastores in DSPM.",
        ),
        ComplianceControl(
            control_id="ID-PDP-PASAL-36-ENC",
            framework_id="INDONESIA_PDP",
            title="Pasal 35 & 36: Confidentiality & Cryptographic Encryption Controls",
            requirement="Maintain confidentiality during personal data processing using encryption at rest and TLS 1.3 in transit.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="UU No. 27/2022 Pasal 35 & 36",
            recommended_action="Enable AES-256 datastore encryption and TLS 1.3.",
        ),
        ComplianceControl(
            control_id="ID-PDP-PASAL-37-SUP",
            framework_id="INDONESIA_PDP",
            title="Pasal 37 & 38: Supervision of Processing Parties & RBAC Access Controls",
            requirement="Supervise every party involved in personal data processing under controller authority via strict RBAC scoping.",
            category="ACCESS_CONTROL",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="UU No. 27/2022 Pasal 37 & 38",
            recommended_action="Enforce tenant-scoped RBAC least-privilege controls.",
        ),
        ComplianceControl(
            control_id="ID-PDP-PASAL-31-AUDIT",
            framework_id="INDONESIA_PDP",
            title="Pasal 31: Mandatory Recording of All Personal Data Processing Activities",
            requirement="Record all personal data processing and administrative operations in a tamper-evident audit trail.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="UU No. 27/2022 Pasal 31",
            recommended_action="Maintain continuous AuditLog capture.",
        ),
        ComplianceControl(
            control_id="ID-PDP-ART-34-RET",
            framework_id="INDONESIA_PDP",
            title="Pasal 42–44: Retention Expiry Termination & Irreversible Deletion",
            requirement="Terminate processing and delete/destroy personal data once the retention period expires.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="UU No. 27/2022 Pasal 42–44",
            recommended_action="Enforce 90-day automated telemetry pruning.",
        ),
        ComplianceControl(
            control_id="ID-PDP-ART-46-BREACH",
            framework_id="INDONESIA_PDP",
            title="Pasal 46 & Pasal 56: 3x24 Hour Breach Notification & Cross-Border Fencing (ap-southeast-3)",
            requirement="Deliver written notification within 3x24 hours (72 hours) upon failure of personal data protection and enforce ap-southeast-3 residency fencing.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="UU No. 27/2022 Pasal 46 & Pasal 56",
            recommended_action="Triage critical incidents within 3x24h and enforce ap-southeast-3 fencing.",
        ),
        ComplianceControl(
            control_id="ID-PDP-ART-53-DPO",
            framework_id="INDONESIA_PDP",
            title="Pasal 34 & Pasal 53: High-Risk DPIA & Data Protection Officer (Pejabat Pelindung Data Pribadi)",
            requirement="Conduct Data Protection Impact Assessments (Pasal 34) for high-risk processing and appoint a qualified DPO (Pasal 53).",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="UU No. 27/2022 Pasal 34 & Pasal 53",
            recommended_action="Attach Signed Indonesian DPO Appointment Letter and Pasal 34 DPIA Report.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        res_check = await self.probe_data_residency_fencing(tenant_id, "ap-southeast-3", db, "ID-PDP-ART-46-BREACH", "UU PDP Pasal 56")
        inc_check = await self.probe_incident_response_backlog(tenant_id, db, "ID-PDP-ART-46-BREACH", "UU PDP Pasal 46")
        combined = inc_check if inc_check.status.value != "PASS" else res_check
        combined.control_id = "ID-PDP-ART-46-BREACH"

        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "ID", db, "ID-PDP-NIK-DISC", "UU PDP Pasal 4"),
            await self.probe_visual_privacy_consent(tenant_id, db, "ID-PDP-PASAL-20-CONSENT", "UU PDP Pasal 20–27"),
            await self.probe_privacy_request_sla(tenant_id, db, "ID-PDP-PASAL-5-DSR", "UU PDP Pasal 5–13 & 32", sla_days=3),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "ID-PDP-ART-35-SEC", "UU PDP Pasal 35 & 39"),
            await self.probe_encryption_and_tls(tenant_id, db, "ID-PDP-PASAL-36-ENC", "UU PDP Pasal 35 & 36"),
            await self.probe_access_control_rbac_mfa(tenant_id, db, "ID-PDP-PASAL-37-SUP", "UU PDP Pasal 37 & 38"),
            await self.probe_audit_logging_active(tenant_id, db, "ID-PDP-PASAL-31-AUDIT", "UU PDP Pasal 31"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "ID-PDP-ART-34-RET", "UU PDP Pasal 42–44"),
            combined,
            self.manual_review_control(
                "ID-PDP-ART-53-DPO",
                "Pejabat Pelindung Data Pribadi (DPO) & Pasal 34 DPIA",
                "Verify formal appointment of Pejabat Pelindung Data Pribadi (Pasal 53) and high-risk Data Protection Impact Assessment (Pasal 34).",
                "UU No. 27/2022 Pasal 34 & Pasal 53",
                "DPO Appointment Decree (SK Penunjukan PPDP) & Pasal 34 DPIA Assessment",
                tenant_id=tenant_id,
            ),
        ]


async def run_indonesia_pdp_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await IndonesiaPdpFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
