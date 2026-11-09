"""
[v4.4.0] Brazil LGPD (Lei Geral de Proteção de Dados — Lei Nº 13.709/2018)
Implements Brazilian personal data discovery (CPF, CNPJ, RG, CNH, PIX),
Art. 6 purpose/necessity, Art. 7 lawful basis/consent, Art. 15/16 retention & deletion,
Art. 18 Titular DSR workflows, Art. 33 cross-border fencing (sa-east-1),
Art. 46 encryption & security safeguards, Art. 48 ANPD 3-business-day incident workflow,
and Art. 41 Encarregado / RIPD governance (Manual Review).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class LgpdFramework(BaseComplianceFramework):
    framework_id = "LGPD"
    name = "Lei Geral de Proteção de Dados (LGPD)"
    region = "BR"
    jurisdiction = "Federative Republic of Brazil"
    category = FrameworkCategory.PRIVACY
    version = "Lei Nº 13.709/2018 (ANPD Res. Nº 15/2024)"
    effective_from = "2020-09-18"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Autoridade Nacional de Proteção de Dados (ANPD)"
    breach_notification_window = "3 Business Days to ANPD & Titulares (Resolução CD/ANPD Nº 15/2024)"
    residency_region = "sa-east-1"
    source_reference = "Lei Nº 13.709 de 14 de Agosto de 2018 & Regulamento CD/ANPD Nº 15/2024"
    supported_privacy_rights = ["ACCESS", "DELETE", "RECTIFY", "PORTABILITY", "OPT_OUT", "OBJECT"]

    controls = [
        ComplianceControl(
            control_id="LGPD-ART-5-PII",
            framework_id="LGPD",
            title="Brazilian Personal & Sensitive Data Discovery (CPF, CNPJ, RG, CNH, PIX)",
            requirement="Discover and classify Brazilian personal and sensitive identifiers with Modulo-11 checksum validation.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="LGPD Art. 5, I & II",
            recommended_action="Ensure Brazilian PII classifiers (BR) are active in DLP and DSPM.",
        ),
        ComplianceControl(
            control_id="LGPD-ART-6-MIN",
            framework_id="LGPD",
            title="Purpose, Adequacy, Necessity & Retention Termination (Art. 6, I–III / Art. 15–16)",
            requirement="Limit processing to minimum necessary and eliminate personal data following termination of processing purpose.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="LGPD Art. 6, I-III & Art. 15-16",
            recommended_action="Enforce 90-day automated telemetry pruning.",
        ),
        ComplianceControl(
            control_id="LGPD-ART-7-CONSENT",
            framework_id="LGPD",
            title="Lawful Basis & Workplace Visual Telemetry Consent (Art. 7 / Art. 11)",
            requirement="Verify transparency notice and consent indicators on endpoints capturing employee visual telemetry.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.MEDIUM,
            legal_reference="LGPD Art. 7, I & Art. 11",
            recommended_action="Enable MonitoringConsentRequired on visual-monitored agents.",
        ),
        ComplianceControl(
            control_id="LGPD-ART-18-TITULAR",
            framework_id="LGPD",
            title="Titular Rights Workflow: Confirmation, Access, Correction, Anonymization & Deletion (Art. 18)",
            requirement="Fulfill Titular requests for access, correction, portability, and deletion within statutory ANPD deadlines (15 days for simplified/complete declaration).",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="LGPD Art. 18 & Art. 19",
            recommended_action="Fulfill open Titular DSR requests within 15-day statutory deadline.",
        ),
        ComplianceControl(
            control_id="LGPD-ART-46-SEC",
            framework_id="LGPD",
            title="Technical & Administrative Security Measures for CPF/CNPJ Data (Art. 46)",
            requirement="Adopt security and technical measures capable of protecting personal data from unauthorized accesses and accidental situations.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="LGPD Art. 46",
            recommended_action="Remediate exposed PII datastores in DSPM.",
        ),
        ComplianceControl(
            control_id="LGPD-ART-46-ENC",
            framework_id="LGPD",
            title="Encryption at Rest, TLS 1.3 & Access Governance (Art. 46 / Art. 37)",
            requirement="Enforce cryptographic storage, TLS 1.3 transport, and immutable audit logging of processing operations.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="LGPD Art. 37 & Art. 46",
            recommended_action="Encrypt all datastores at rest and verify mTLS.",
        ),
        ComplianceControl(
            control_id="LGPD-ART-37-AUDIT",
            framework_id="LGPD",
            title="Record of Personal Data Processing Operations & Audit Trail (Art. 37)",
            requirement="Controller and processor must keep records of personal data processing operations carried out.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="LGPD Art. 37",
            recommended_action="Maintain tamper-evident AuditLog records.",
        ),
        ComplianceControl(
            control_id="LGPD-ART-48-ANPD",
            framework_id="LGPD",
            title="ANPD 3-Business-Day Security Incident Communication Workflow (Art. 48)",
            requirement="Communicate security incidents creating relevant risk or damage to the ANPD and affected Titulares within 3 business days.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="LGPD Art. 48 & Resolução CD/ANPD Nº 15/2024",
            recommended_action="Triage open critical security incidents within 3 business days.",
        ),
        ComplianceControl(
            control_id="LGPD-ART-33-TRANS",
            framework_id="LGPD",
            title="International Data Transfer Restrictions & Sovereign Fencing (Art. 33–36)",
            requirement="Enforce Brazilian regional sovereign fencing (sa-east-1) or ANPD Standard Contractual Clauses.",
            category="DATA_RESIDENCY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="LGPD Art. 33–36 & Resolução CD/ANPD Nº 19/2024",
            recommended_action="Enforce sa-east-1 sovereign telemetry boundary fencing.",
        ),
        ComplianceControl(
            control_id="LGPD-ART-41-ENCARREGADO",
            framework_id="LGPD",
            title="Appointment of Encarregado (DPO) & RIPD Impact Report (Art. 38 / Art. 41)",
            requirement="Formally appoint and publicly disclose the Encarregado (DPO) and maintain Relatório de Impacto à Proteção de Dados Pessoais (RIPD).",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="LGPD Art. 38 & Art. 41 (Resolução CD/ANPD Nº 18/2024)",
            recommended_action="Publish Encarregado identity and attach signed RIPD documentation.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "BR", db, "LGPD-ART-5-PII", "LGPD Art. 5"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "LGPD-ART-6-MIN", "LGPD Art. 6 & 16"),
            await self.probe_visual_privacy_consent(tenant_id, db, "LGPD-ART-7-CONSENT", "LGPD Art. 7"),
            await self.probe_privacy_request_sla(tenant_id, db, "LGPD-ART-18-TITULAR", "LGPD Art. 18 & 19", sla_days=15),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "LGPD-ART-46-SEC", "LGPD Art. 46"),
            await self.probe_encryption_and_tls(tenant_id, db, "LGPD-ART-46-ENC", "LGPD Art. 46"),
            await self.probe_audit_logging_active(tenant_id, db, "LGPD-ART-37-AUDIT", "LGPD Art. 37"),
            await self.probe_incident_response_backlog(tenant_id, db, "LGPD-ART-48-ANPD", "LGPD Art. 48"),
            await self.probe_data_residency_fencing(tenant_id, "sa-east-1", db, "LGPD-ART-33-TRANS", "LGPD Art. 33"),
            self.manual_review_control(
                "LGPD-ART-41-ENCARREGADO",
                "Encarregado (DPO) Formal Designation & RIPD Impact Assessment",
                "Verify formal written designation of Encarregado and public disclosure on controller website.",
                "LGPD Art. 38 & Art. 41",
                "Ato Formal de Designação do Encarregado & Relatório RIPD",
                tenant_id=tenant_id,
            ),
        ]


async def run_lgpd_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await LgpdFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
