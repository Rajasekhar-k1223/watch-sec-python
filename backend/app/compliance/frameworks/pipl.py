"""
[v4.4.0] China Personal Information Protection Law (PIPL) — PRC President Order No. 91
Implements PRC PI & SPI inventory (18-digit Resident ID Card ISO 7064 MOD 11-2, Mobile, Bank, Passport),
Art. 6 minimization & Art. 19 retention, Art. 13/29 separate consent, Art. 44-50 individual rights,
Art. 51 encryption/access/audit safeguards, Art. 57 CAC breach notification, Art. 40 localization
fencing (cn-north-1), and Art. 38 CAC Cross-Border Security Assessment (`MANUAL_REVIEW`).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class PiplFramework(BaseComplianceFramework):
    framework_id = "PIPL"
    name = "Personal Information Protection Law (PIPL)"
    region = "CN"
    jurisdiction = "People's Republic of China"
    category = FrameworkCategory.PRIVACY
    version = "Order No. 91 of the President of the PRC"
    effective_from = "2021-11-01"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Cyberspace Administration of China (CAC)"
    breach_notification_window = "Immediate Remedial Action & Prompt CAC Notification (Art. 57)"
    residency_region = "cn-north-1"
    source_reference = "Personal Information Protection Law of the PRC (Effective Nov 1, 2021)"
    supported_privacy_rights = ["ACCESS", "DELETE", "CORRECT", "PORTABILITY", "RESTRICT", "OPT_OUT"]

    controls = [
        ComplianceControl(
            control_id="PIPL-ART-4-INV",
            framework_id="PIPL",
            title="PRC Personal & Sensitive Personal Information Inventory (RIC ISO 7064 MOD 11-2)",
            requirement="Identify and classify PRC Personal Information and Sensitive Personal Information (Art. 28) including Resident ID Cards, mobile numbers, passports, and bank cards.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PIPL Art. 4 & Art. 28",
            recommended_action="Ensure PRC PII classifiers (CN) are active in DLP and DSPM.",
        ),
        ComplianceControl(
            control_id="PIPL-ART-6-MIN",
            framework_id="PIPL",
            title="Minimum Scope & Shortest Retention Period (Art. 6 / Art. 19)",
            requirement="Limit handling of personal information to minimum scope and shortest retention period necessary to achieve purpose.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PIPL Art. 6 & Art. 19",
            recommended_action="Enforce 90-day retention pruning and automated deletion.",
        ),
        ComplianceControl(
            control_id="PIPL-ART-29-CONSENT",
            framework_id="PIPL",
            title="Separate Consent & Workplace Visual Monitoring Notice (Art. 13 / Art. 29)",
            requirement="Obtain informed separate consent where sensitive/visual endpoint telemetry is collected.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PIPL Art. 13, Art. 14 & Art. 29",
            recommended_action="Enable MonitoringConsentRequired on monitored endpoints.",
        ),
        ComplianceControl(
            control_id="PIPL-ART-44-RIGHTS",
            framework_id="PIPL",
            title="Individual Rights: Access, Copy, Correction & Deletion (Art. 44–50)",
            requirement="Establish convenient mechanisms to accept and process individual rights requests including Art. 47 deletion.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PIPL Art. 44–50",
            recommended_action="Process open PRC individual privacy requests promptly.",
        ),
        ComplianceControl(
            control_id="PIPL-ART-51-SEC",
            framework_id="PIPL",
            title="Technical Safeguards & De-Identification for PRC Sensitive PI (Art. 51)",
            requirement="Implement classified management, encryption, de-identification, and strict access permissions.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="PIPL Art. 51",
            recommended_action="Remediate exposed sensitive personal data in DSPM.",
        ),
        ComplianceControl(
            control_id="PIPL-ART-51-ENC-IAM",
            framework_id="PIPL",
            title="Cryptographic Storage, RBAC Access Authorization & Audit Logs (Art. 51)",
            requirement="Enforce AES-256 encryption, TLS 1.3 transport, and immutable operational audit logs.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PIPL Art. 51(3) & (4)",
            recommended_action="Verify datastore encryption and AuditLog recording.",
        ),
        ComplianceControl(
            control_id="PIPL-ART-57-BREACH",
            framework_id="PIPL",
            title="Immediate Breach Containment & CAC Authority Notification (Art. 57)",
            requirement="Immediately take remedial measures and notify departments fulfilling personal information protection duties (CAC) and individuals.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="PIPL Art. 57",
            recommended_action="Triage critical security incidents immediately.",
        ),
        ComplianceControl(
            control_id="PIPL-ART-40-LOCAL",
            framework_id="PIPL",
            title="In-Country Data Localization & Sovereign Boundary Fencing (Art. 40)",
            requirement="Store personal information collected/produced within mainland China domestically (cn-north-1 / local enclave).",
            category="DATA_RESIDENCY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="PIPL Art. 40",
            recommended_action="Enforce cn-north-1 sovereign telemetry boundary fencing.",
        ),
        ComplianceControl(
            control_id="PIPL-ART-38-CAC-REVIEW",
            framework_id="PIPL",
            title="CAC Outbound Data Transfer Security Assessment, Standard Contract & Art. 52/53 Officer",
            requirement="Cross-border transfers require CAC Security Assessment, CAC Standard Contract filing, or certification, plus Art. 52 Protection Officer / Art. 53 PRC representative.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="PIPL Art. 38, Art. 52, Art. 53 &Art. 55 (PIPIA)",
            recommended_action="Attach CAC Security Assessment Approval / Standard Contract Filing Receipt, PIPIA report, and PRC Officer designation.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "CN", db, "PIPL-ART-4-INV", "PIPL Art. 4 & 28"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "PIPL-ART-6-MIN", "PIPL Art. 6 & 19"),
            await self.probe_visual_privacy_consent(tenant_id, db, "PIPL-ART-29-CONSENT", "PIPL Art. 13 & 29"),
            await self.probe_privacy_request_sla(tenant_id, db, "PIPL-ART-44-RIGHTS", "PIPL Art. 44–50", sla_days=15),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "PIPL-ART-51-SEC", "PIPL Art. 51"),
            await self.probe_encryption_and_tls(tenant_id, db, "PIPL-ART-51-ENC-IAM", "PIPL Art. 51(3)"),
            await self.probe_incident_response_backlog(tenant_id, db, "PIPL-ART-57-BREACH", "PIPL Art. 57"),
            await self.probe_data_residency_fencing(tenant_id, "cn-north-1", db, "PIPL-ART-40-LOCAL", "PIPL Art. 40"),
            self.manual_review_control(
                "PIPL-ART-38-CAC-REVIEW",
                "CAC Cross-Border Security Assessment, PIPIA & Art. 52/53 Officer Filing",
                "Monitorix enforces technical localization fencing but cannot automatically determine legal approval of a CAC Outbound Data Transfer Security Assessment or Standard Contract filing.",
                "PIPL Art. 38, Art. 52, Art. 53 & Art. 55",
                "CAC Outbound Security Assessment Notice / Standard Contract Filing, PIPIA, and Officer Appointment",
                tenant_id=tenant_id,
            ),
        ]


async def run_pipl_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await PiplFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
