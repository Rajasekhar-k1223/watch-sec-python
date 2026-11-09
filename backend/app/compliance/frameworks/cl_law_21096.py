"""
[v4.4.0] Chile Personal Data Protection Law (Ley 19.628, Reforma Constitucional Ley 21.096
& Nueva Ley de Protección de Datos Personales Ley 21.719 / Ley Marco Ciberseguridad 21.663)
Covers Chilean RUT/RUN (Modulo-11 check digit 0–9/K) discovery, Lawful Basis & Consent (Art. 12–13),
Proportionality & Suppression Upon Expiry (Art. 3 & 6), ARCO + Portability Rights (Art. 4–9, 30-day SLA),
Duty of Security & Confidentiality (Art. 14 quinquies: Encryption, RBAC, Immutable Audit Logs,
Vulnerability Management), Breach Notification to Agencia de Protección de Datos Personales (Art. 14 sexies),
International Data Transfers (Art. 27–28, sa-east-1), and Crime/Infraction Prevention Model & DPO
Certification (Art. 49–51 MANUAL_REVIEW).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class ClLaw21096Framework(BaseComplianceFramework):
    framework_id = "CHILE_PDPL"
    name = "Chile Personal Data Protection Law (Ley 19.628 / Ley 21.719 Reform)"
    region = "CL"
    jurisdiction = "Republic of Chile"
    category = FrameworkCategory.PRIVACY
    version = "Ley 19.628 reformada por Ley 21.719 (2024)"
    effective_from = "2024-12-13"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Agencia de Protección de Datos Personales (APDP Chile)"
    breach_notification_window = "Without Undue Delay to Agencia de Protección de Datos Personales (Art. 14 sexies)"
    residency_region = "sa-east-1"
    source_reference = "Diario Oficial de la República de Chile — Ley 19.628, Ley 21.096 & Ley 21.719"
    supported_privacy_rights = ["ACCESS", "DELETE", "CORRECT", "RECTIFY", "RESTRICT", "OBJECT", "PORTABILITY"]

    controls = [
        ComplianceControl(
            control_id="CL-PDPL-RUT-DISC",
            framework_id="CHILE_PDPL",
            title="Artículos 2 y 16: RUT / RUN Chileno (Módulo-11) & Datos Sensibles Discovery",
            requirement="Discover and classify Chilean RUT/RUN national identifiers (Modulo-11 check digit 0–9/K), Passports, Mobile numbers, and sensitive personal data.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Ley 19.628 reformada por Ley 21.719 Artículos 2 y 16",
            recommended_action="Ensure Chile (CL) PII classifiers are active across DLP/DSPM.",
        ),
        ComplianceControl(
            control_id="CL-PDPL-ART-3-RET",
            framework_id="CHILE_PDPL",
            title="Artículo 3: Principio de Finalidad, Proporcionalidad y Temporalidad",
            requirement="Retain personal data only for the time necessary to achieve collection purposes, then delete or anonymize.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Ley 21.719 Artículo 3 (Principio de Proporcionalidad)",
            recommended_action="Enforce 90-day automated telemetry pruning.",
        ),
        ComplianceControl(
            control_id="CL-PDPL-ART-12-CONSENT",
            framework_id="CHILE_PDPL",
            title="Artículos 12, 13 y 14 ter: Licitud del Tratamiento, Consentimiento y Transparencia",
            requirement="Obtain free, informed, and specific consent or establish statutory lawful basis with clear transparency notices on monitored endpoints.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Ley 21.719 Artículos 12, 13 y 14 ter",
            recommended_action="Enable MonitoringConsentRequired notice banners on visually monitored endpoints.",
        ),
        ComplianceControl(
            control_id="CL-PDPL-ART-4-ARCOP",
            framework_id="CHILE_PDPL",
            title="Artículos 4–9 y 11: Derechos ARCOP (Acceso, Rectificación, Supresión, Oposición y Portabilidad)",
            requirement="Respond to titular ARCO and Portability requests free of charge within 30 calendar days.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Ley 21.719 Artículos 4 al 11",
            recommended_action="Fulfill open Chilean ARCOP DSR requests within 30 calendar days.",
        ),
        ComplianceControl(
            control_id="CL-PDPL-ART-14Q-SEC",
            framework_id="CHILE_PDPL",
            title="Artículo 14 quinquies: Deber de Seguridad en el Tratamiento de Datos",
            requirement="Adopt appropriate technical and organizational security measures against unauthorized access, destruction, modification, or disclosure.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="Ley 21.719 Artículo 14 quinquies",
            recommended_action="Remediate exposed Chilean RUT and PII datastores in DSPM.",
        ),
        ComplianceControl(
            control_id="CL-PDPL-ENC",
            framework_id="CHILE_PDPL",
            title="Artículo 14 quinquies(a): Cifrado y Seudonimización de Datos Personales",
            requirement="Implement encryption at rest (AES-256) and TLS 1.3 in transit for personal and sensitive records.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Ley 21.719 Artículo 14 quinquies letra a)",
            recommended_action="Enable encryption at rest across all datastores.",
        ),
        ComplianceControl(
            control_id="CL-CYBER-RISK-MGMT",
            framework_id="CHILE_PDPL",
            title="Ley 21.719 Art. 14 quinquies & Ley 21.663 Art. 16: Gestión de Vulnerabilidades y RBAC",
            requirement="Continuously evaluate security controls, enforce RBAC access restrictions, and remediate High/Critical vulnerabilities.",
            category="VULNERABILITY_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Ley 21.719 Art. 14 quinquies & Ley 21.663 Art. 16",
            recommended_action="Remediate High and Critical endpoint software vulnerabilities.",
        ),
        ComplianceControl(
            control_id="CL-CYBER-AUDIT",
            framework_id="CHILE_PDPL",
            title="Artículo 3 (Responsabilidad) & Ley 21.663 Art. 20: Registro Inalterable de Auditoría",
            requirement="Maintain tamper-evident audit logs demonstrating accountability before the APDP and ANCI.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Ley 21.719 Art. 3 & Ley 21.663 Art. 20",
            recommended_action="Maintain tamper-evident AuditLog records.",
        ),
        ComplianceControl(
            control_id="CL-CYBER-CSIRT-NOTIFY",
            framework_id="CHILE_PDPL",
            title="Artículo 14 sexies & Art. 27–28: Reporte de Brechas a la Agencia & Transferencia Internacional (sa-east-1)",
            requirement="Report personal data security breaches without undue delay to the Agencia de Protección de Datos Personales and enforce sa-east-1 international transfer fencing.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="Ley 21.719 Artículos 14 sexies, 27 y 28",
            recommended_action="Triage critical security incidents promptly and enforce sa-east-1 residency fencing.",
        ),
        ComplianceControl(
            control_id="CL-PDPL-ART-49-MODEL",
            framework_id="CHILE_PDPL",
            title="Artículos 15 ter y 49–52: Delegado de Protección de Datos (DPD) & Modelo de Prevención de Infracciones",
            requirement="Designate a Data Protection Officer (DPD) and adopt/certify an Infraction Prevention Programme registered before the Agencia de Protección de Datos Personales.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="Ley 21.719 Artículos 15 ter y 49–52",
            recommended_action="Attach Chilean DPD Appointment Record, EIPD (DPIA), and Certified Modelo de Prevención de Infracciones.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        res_check = await self.probe_data_residency_fencing(tenant_id, "sa-east-1", db, "CL-CYBER-CSIRT-NOTIFY", "Ley 21.719 Art. 27–28")
        inc_check = await self.probe_incident_response_backlog(tenant_id, db, "CL-CYBER-CSIRT-NOTIFY", "Ley 21.719 Art. 14 sexies")
        combined = inc_check if inc_check.status.value != "PASS" else res_check
        combined.control_id = "CL-CYBER-CSIRT-NOTIFY"

        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "CL", db, "CL-PDPL-RUT-DISC", "Ley 21.719 Art. 2 & 16"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "CL-PDPL-ART-3-RET", "Ley 21.719 Art. 3"),
            await self.probe_visual_privacy_consent(tenant_id, db, "CL-PDPL-ART-12-CONSENT", "Ley 21.719 Art. 12 & 14 ter"),
            await self.probe_privacy_request_sla(tenant_id, db, "CL-PDPL-ART-4-ARCOP", "Ley 21.719 Art. 4–11", sla_days=30),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "CL-PDPL-ART-14Q-SEC", "Ley 21.719 Art. 14 quinquies"),
            await self.probe_encryption_and_tls(tenant_id, db, "CL-PDPL-ENC", "Ley 21.719 Art. 14 quinquies(a)"),
            await self.probe_vulnerability_backlog(tenant_id, db, "CL-CYBER-RISK-MGMT", "Ley 21.719 Art. 14 quinquies"),
            await self.probe_audit_logging_active(tenant_id, db, "CL-CYBER-AUDIT", "Ley 21.719 Art. 3"),
            combined,
            self.manual_review_control(
                "CL-PDPL-ART-49-MODEL",
                "Delegado de Protección de Datos (DPD) & Modelo de Prevención de Infracciones",
                "Verificar designación de Delegado de Protección de Datos (Art. 50) y certificación del Programa de Cumplimiento / Modelo de Prevención ante la APDP.",
                "Ley 21.719 Artículos 15 ter y 49–52",
                "Designación de DPD, Evaluación de Impacto (Art. 15 ter) & Certificado APDP del Modelo de Prevención",
                tenant_id=tenant_id,
            ),
        ]


async def run_chile_pdpl_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await ClLaw21096Framework().run_checks(tenant_id=tenant_id, db=db, context=context)
