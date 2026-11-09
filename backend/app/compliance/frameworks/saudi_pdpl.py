"""
[v4.4.0] Kingdom of Saudi Arabia PDPL (Royal Decree M/19 & Amended M/148, SDAIA Implementing Regs)
Covers 10-digit Saudi National ID / Iqama (Luhn) & KSA IBAN/VAT discovery, Consent & Purpose
Limitation (Art. 5 & 11), Data Subject Rights Within 30 Days (Art. 4), Immediate Destruction Upon
Expiry (Art. 18), Organizational & Technical Security Controls aligned with NCA ECC (Art. 19:
Encryption, RBAC, Audit Logs, Vulnerability Hygiene), 72-Hour SDAIA Breach Notification (Art. 20),
In-Kingdom Data Sovereignty & Cross-Border Transfer Regulation (Art. 29, me-central-1), and
SDAIA National Data Governance Platform Registration / DPO / RoPA (Art. 30–32 MANUAL_REVIEW).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class SaudiPdplFramework(BaseComplianceFramework):
    framework_id = "SAUDI_PDPL"
    name = "Kingdom of Saudi Arabia Personal Data Protection Law (PDPL)"
    region = "SA"
    jurisdiction = "Kingdom of Saudi Arabia"
    category = FrameworkCategory.PRIVACY
    version = "Royal Decree M/19 as amended by M/148 (Full Enforcement Sept 2024)"
    effective_from = "2023-09-14"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Saudi Data and Artificial Intelligence Authority (SDAIA)"
    breach_notification_window = "Within 72 Hours to SDAIA & Without Undue Delay to Data Subjects (Article 20)"
    residency_region = "me-central-1"
    source_reference = "Saudi Data and AI Authority (SDAIA), Royal Decree No. M/19 & Implementing Regulations"
    supported_privacy_rights = ["ACCESS", "DELETE", "CORRECT", "RECTIFY", "RESTRICT", "PORTABILITY"]

    controls = [
        ComplianceControl(
            control_id="KSA-PDPL-ID-DISC",
            framework_id="SAUDI_PDPL",
            title="Article 1: Saudi National ID (Hawiya) / Iqama (Luhn) & Sensitive PII Discovery",
            requirement="Discover and classify 10-digit Saudi National IDs (1xxxxxxxxx) and Iqamas (2xxxxxxxxx) via Luhn validation, SA IBANs, and VAT numbers.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="KSA PDPL Article 1",
            recommended_action="Ensure Saudi Arabia (SA) PII classifiers are active across DLP/DSPM.",
        ),
        ComplianceControl(
            control_id="KSA-PDPL-ART-18-MIN",
            framework_id="SAUDI_PDPL",
            title="Articles 11 & 18: Minimization & Immediate Destruction When Purpose Ends",
            requirement="Limit personal data collection to the minimum necessary and destroy personal data without delay once no longer needed.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="KSA PDPL Articles 11(3) & 18",
            recommended_action="Enforce 90-day automated telemetry pruning.",
        ),
        ComplianceControl(
            control_id="KSA-PDPL-ART-5-CONSENT",
            framework_id="SAUDI_PDPL",
            title="Articles 5, 12 & 13: Explicit Consent & Privacy Policy Notice Prior to Collection",
            requirement="Inform data subjects of collection purposes under Article 13 and enforce explicit consent banners on visually monitored endpoints.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="KSA PDPL Articles 5, 12 & 13",
            recommended_action="Enable MonitoringConsentRequired notice banners on visually monitored endpoints.",
        ),
        ComplianceControl(
            control_id="KSA-PDPL-ART-4-DSR",
            framework_id="SAUDI_PDPL",
            title="Article 4: Data Subject Rights (Access, Readable Copy, Correction & Destruction — 30-Day SLA)",
            requirement="Fulfill data subject rights requests within 30 days under SDAIA Implementing Regulations.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="KSA PDPL Article 4 & Implementing Regulations Art. 4–9",
            recommended_action="Fulfill open KSA PDPL DSR requests within 30 days.",
        ),
        ComplianceControl(
            control_id="KSA-PDPL-ART-19-SEC",
            framework_id="SAUDI_PDPL",
            title="Article 19: NCA-Aligned Organizational & Technical Security Controls",
            requirement="Take all necessary organizational, administrative, and technical measures in accordance with NCA cybersecurity controls to protect personal data.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="KSA PDPL Article 19 & Implementing Regs Art. 23 (NCA ECC alignment)",
            recommended_action="Remediate exposed Saudi PII datastores in DSPM.",
        ),
        ComplianceControl(
            control_id="KSA-PDPL-ART-19-ENC",
            framework_id="SAUDI_PDPL",
            title="Article 19 &NCA ECC-2: Cryptographic Data Protection at Rest & TLS 1.3",
            requirement="Protect sensitive personal data using AES-256 encryption at rest and TLS 1.3 in transit.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="KSA PDPL Article 19 & NCA Essential Cybersecurity Controls",
            recommended_action="Enable encryption at rest across all datastores.",
        ),
        ComplianceControl(
            control_id="KSA-PDPL-ART-19-RBAC",
            framework_id="SAUDI_PDPL",
            title="Article 19: Identity & Access Management (RBAC) & Vulnerability Remediation",
            requirement="Enforce least-privilege RBAC and remediate High/Critical endpoint vulnerabilities per NCA ECC.",
            category="VULNERABILITY_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="KSA PDPL Article 19",
            recommended_action="Remediate High and Critical endpoint software vulnerabilities.",
        ),
        ComplianceControl(
            control_id="KSA-PDPL-ART-31-AUDIT",
            framework_id="SAUDI_PDPL",
            title="Articles 19 & 31: Tamper-Evident Security Event & Operational Audit Logs",
            requirement="Maintain immutable audit logs of personal data access, disclosure, and administrative operations.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="KSA PDPL Articles 19 & 31",
            recommended_action="Maintain tamper-evident AuditLog records.",
        ),
        ComplianceControl(
            control_id="KSA-PDPL-ART-20-BREACH",
            framework_id="SAUDI_PDPL",
            title="Article 20 & Article 29: 72-Hour SDAIA Breach Notice & In-Kingdom Residency (me-central-1)",
            requirement="Notify SDAIA within 72 hours of a personal data breach and enforce sovereign cross-border transfer fencing (Article 29, me-central-1).",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="KSA PDPL Articles 20 & 29; SDAIA Data Transfer Regulations",
            recommended_action="Triage critical incidents within 72h and enforce me-central-1 sovereign fencing.",
        ),
        ComplianceControl(
            control_id="KSA-PDPL-ART-30-DPO",
            framework_id="SAUDI_PDPL",
            title="Articles 22, 30, 31 & 32: SDAIA Portal Registration, DPO Appointment, RoPA & Transfer Assessment",
            requirement="Appoint a DPO (Art. 30), register on SDAIA National Data Governance Platform (Art. 32), maintain Art. 31 RoPA for 5 years past processing, and complete Art. 22/29 DPIA/Transfer Risk Assessments.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="KSA PDPL Articles 22, 29, 30, 31 & 32",
            recommended_action="Attach SDAIA National Data Governance Registration Certificate, DPO Filing, and Art. 31 RoPA.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        res_check = await self.probe_data_residency_fencing(tenant_id, "me-central-1", db, "KSA-PDPL-ART-20-BREACH", "KSA PDPL Article 29")
        inc_check = await self.probe_incident_response_backlog(tenant_id, db, "KSA-PDPL-ART-20-BREACH", "KSA PDPL Article 20")
        combined = inc_check if inc_check.status.value != "PASS" else res_check
        combined.control_id = "KSA-PDPL-ART-20-BREACH"

        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "SA", db, "KSA-PDPL-ID-DISC", "KSA PDPL Article 1"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "KSA-PDPL-ART-18-MIN", "KSA PDPL Articles 11 & 18"),
            await self.probe_visual_privacy_consent(tenant_id, db, "KSA-PDPL-ART-5-CONSENT", "KSA PDPL Articles 5 & 13"),
            await self.probe_privacy_request_sla(tenant_id, db, "KSA-PDPL-ART-4-DSR", "KSA PDPL Article 4", sla_days=30),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "KSA-PDPL-ART-19-SEC", "KSA PDPL Article 19"),
            await self.probe_encryption_and_tls(tenant_id, db, "KSA-PDPL-ART-19-ENC", "KSA PDPL Article 19"),
            await self.probe_vulnerability_backlog(tenant_id, db, "KSA-PDPL-ART-19-RBAC", "KSA PDPL Article 19"),
            await self.probe_audit_logging_active(tenant_id, db, "KSA-PDPL-ART-31-AUDIT", "KSA PDPL Articles 19 & 31"),
            combined,
            self.manual_review_control(
                "KSA-PDPL-ART-30-DPO",
                "SDAIA National Data Governance Registration, DPO & Article 31 RoPA",
                "Verify registration on SDAIA National Data Governance Platform (dgp.sdaia.gov.sa), DPO appointment (Art. 30), and 5-year RoPA retention (Art. 31).",
                "KSA PDPL Articles 22, 30, 31 & 32",
                "SDAIA Registration Certificate, DPO Appointment Letter & Article 31 RoPA",
                tenant_id=tenant_id,
            ),
        ]


async def run_saudi_pdpl_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await SaudiPdplFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
