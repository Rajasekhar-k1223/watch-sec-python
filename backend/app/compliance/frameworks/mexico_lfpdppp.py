"""
[v4.4.0] Mexico LFPDPPP (Ley Federal de Protección de Datos Personales en Posesión de los Particulares)
Covers 18-character CURP, RFC, NSS & CLABE discovery, Blocking & Suppression Retention Period (Art. 11),
Aviso de Privacidad Integral & Consent (Art. 8, 15 & 16), Physical, Administrative & Technical Security
Measures (Art. 19: Encryption, RBAC, Audit Logs, Vulnerability Management), Immediate Breach Notification
(Art. 20), ARCO Rights Workflow Within 20 Business Days (Art. 22–35: Acceso, Rectificación, Cancelación,
Oposición), Domestic/International Transfers (Art. 36–37, sa-east-1), and Privacy Department Designation
(Art. 30 MANUAL_REVIEW).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class MexicoLfpdpppFramework(BaseComplianceFramework):
    framework_id = "MEXICO_LFPDPPP"
    name = "Mexico Ley Federal de Protección de Datos Personales (LFPDPPP)"
    region = "MX"
    jurisdiction = "United Mexican States"
    category = FrameworkCategory.PRIVACY
    version = "LFPDPPP & Reglamento (2010 / 2025 Institutional Reform)"
    effective_from = "2010-07-06"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Secretaría Anticorrupción y Buen Gobierno / Federal Data Protection Authority Mexico"
    breach_notification_window = "Immediately Upon Confirming Significant Breach to Data Subjects (Artículo 20)"
    residency_region = "sa-east-1"
    source_reference = "Diario Oficial de la Federación, LFPDPPP & Reglamento de la LFPDPPP"
    supported_privacy_rights = ["ACCESS", "DELETE", "CORRECT", "RECTIFY", "OBJECT", "OPT_OUT"]

    controls = [
        ComplianceControl(
            control_id="MX-LFPDPPP-PII-DISC",
            framework_id="MEXICO_LFPDPPP",
            title="Artículo 3: CURP, RFC, NSS, CLABE & Sensitive Personal Data Discovery",
            requirement="Discover and classify Mexican CURP (18-char), RFC tax IDs, IMSS NSS, 18-digit CLABE bank accounts, and sensitive data.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="LFPDPPP Artículo 3 fracciones V y VI",
            recommended_action="Ensure Mexico (MX) PII classifiers are active across DLP/DSPM.",
        ),
        ComplianceControl(
            control_id="MX-LFPDPPP-ART-15-NOTICE",
            framework_id="MEXICO_LFPDPPP",
            title="Artículos 8, 15 y 16: Aviso de Privacidad Integral & Consentimiento",
            requirement="Make the Aviso de Privacidad available to data subjects and enforce consent banners on visually monitored endpoints.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="LFPDPPP Artículos 8, 9, 15 y 16",
            recommended_action="Enable MonitoringConsentRequired notice banners on visually monitored endpoints.",
        ),
        ComplianceControl(
            control_id="MX-LFPDPPP-ART-11-RET",
            framework_id="MEXICO_LFPDPPP",
            title="Artículo 11: Periodo de Bloqueo y Supresión de Datos Personales",
            requirement="Block and subsequently suppress personal data once the purpose of processing has been fulfilled.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="LFPDPPP Artículo 11 & Reglamento Art. 37",
            recommended_action="Enforce 90-day automated telemetry pruning.",
        ),
        ComplianceControl(
            control_id="MX-LFPDPPP-ART-28-ARCO",
            framework_id="MEXICO_LFPDPPP",
            title="Artículos 22–35: Ejercicio de Derechos ARCO (Plazo de 20 Días Hábiles)",
            requirement="Communicate determination on Acceso, Rectificación, Cancelación y Oposición (ARCO) requests within 20 business days and execute within 15 days.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="LFPDPPP Artículos 22–35",
            recommended_action="Fulfill open Mexican ARCO requests within 20 business days.",
        ),
        ComplianceControl(
            control_id="MX-LFPDPPP-ART-19-SEC",
            framework_id="MEXICO_LFPDPPP",
            title="Artículo 19: Medidas de Seguridad Administrativas, Físicas y Técnicas",
            requirement="Establish and maintain technical security measures protecting CURP, RFC, financial, and sensitive data against damage, loss, alteration, or unauthorized use.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="LFPDPPP Artículo 19 & Reglamento Art. 57–62",
            recommended_action="Remediate exposed Mexican PII datastores in DSPM.",
        ),
        ComplianceControl(
            control_id="MX-LFPDPPP-REG-ENC",
            framework_id="MEXICO_LFPDPPP",
            title="Reglamento Artículo 61: Controles Criptográficos en Reposo y Tránsito",
            requirement="Protect personal and patrimonial/financial data via AES-256 encryption at rest and TLS 1.3 in transit.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Reglamento de la LFPDPPP Artículo 61",
            recommended_action="Enable encryption at rest across all datastores.",
        ),
        ComplianceControl(
            control_id="MX-LFPDPPP-REG-VULN",
            framework_id="MEXICO_LFPDPPP",
            title="Reglamento Artículo 60–61: Gestión de Vulnerabilidades y Control de Acceso (RBAC)",
            requirement="Maintain an inventory of security controls, enforce RBAC access profiles, and remediate software vulnerabilities.",
            category="VULNERABILITY_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Reglamento de la LFPDPPP Artículos 60 y 61",
            recommended_action="Remediate High and Critical endpoint software vulnerabilities.",
        ),
        ComplianceControl(
            control_id="MX-LFPDPPP-REG-AUDIT",
            framework_id="MEXICO_LFPDPPP",
            title="Reglamento Artículo 61(VI): Bitácoras de Acciones y Trazabilidad Inmutable",
            requirement="Register user actions, privileged operations, and security events in tamper-evident audit bitácoras.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Reglamento de la LFPDPPP Artículo 61 fracción VI",
            recommended_action="Maintain tamper-evident AuditLog records.",
        ),
        ComplianceControl(
            control_id="MX-LFPDPPP-ART-20-BREACH",
            framework_id="MEXICO_LFPDPPP",
            title="Artículo 20 & Artículo 36: Notificación Inmediata de Vulneraciones & Transferencias (sa-east-1)",
            requirement="Immediately notify affected data subjects upon security breaches significantly affecting patrimonial or moral rights and enforce sa-east-1 transfer fencing.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="LFPDPPP Artículos 20, 36 y 37",
            recommended_action="Triage critical security incidents immediately and enforce sa-east-1 fencing.",
        ),
        ComplianceControl(
            control_id="MX-LFPDPPP-DPO-GOV",
            framework_id="MEXICO_LFPDPPP",
            title="Artículo 30 & Reg. Art. 59: Designación de Persona o Departamento de Datos Personales & Documento de Seguridad",
            requirement="Formally designate a Personal Data Person/Department to process ARCO requests (Art. 30) and maintain the statutory Documento de Seguridad.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="LFPDPPP Artículo 30 & Reglamento Artículos 59–61",
            recommended_action="Attach Formal Privacy Department Designation, Published Aviso de Privacidad Integral, and Documento de Seguridad.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        res_check = await self.probe_data_residency_fencing(tenant_id, "sa-east-1", db, "MX-LFPDPPP-ART-20-BREACH", "LFPDPPP Art. 36 & 37")
        inc_check = await self.probe_incident_response_backlog(tenant_id, db, "MX-LFPDPPP-ART-20-BREACH", "LFPDPPP Art. 20")
        combined = inc_check if inc_check.status.value != "PASS" else res_check
        combined.control_id = "MX-LFPDPPP-ART-20-BREACH"

        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "MX", db, "MX-LFPDPPP-PII-DISC", "LFPDPPP Art. 3"),
            await self.probe_visual_privacy_consent(tenant_id, db, "MX-LFPDPPP-ART-15-NOTICE", "LFPDPPP Art. 8, 15 y 16"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "MX-LFPDPPP-ART-11-RET", "LFPDPPP Art. 11"),
            await self.probe_privacy_request_sla(tenant_id, db, "MX-LFPDPPP-ART-28-ARCO", "LFPDPPP Art. 28–35", sla_days=20),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "MX-LFPDPPP-ART-19-SEC", "LFPDPPP Art. 19"),
            await self.probe_encryption_and_tls(tenant_id, db, "MX-LFPDPPP-REG-ENC", "Reglamento Art. 61"),
            await self.probe_vulnerability_backlog(tenant_id, db, "MX-LFPDPPP-REG-VULN", "Reglamento Art. 60–61"),
            await self.probe_audit_logging_active(tenant_id, db, "MX-LFPDPPP-REG-AUDIT", "Reglamento Art. 61(VI)"),
            combined,
            self.manual_review_control(
                "MX-LFPDPPP-DPO-GOV",
                "Designación de Departamento de Datos Personales & Documento de Seguridad",
                "Verificar nombramiento formal de la persona o departamento de datos personales (Art. 30), Aviso de Privacidad Integral y Documento de Seguridad.",
                "LFPDPPP Artículo 30 & Reglamento Art. 59–61",
                "Acta de Designación del Oficial/Departamento ARCO, Aviso de Privacidad Integral & Documento de Seguridad",
                tenant_id=tenant_id,
            ),
        ]


async def run_mexico_lfpdppp_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await MexicoLfpdpppFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
