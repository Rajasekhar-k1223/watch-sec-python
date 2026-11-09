"""
[v4.4.0] Colombia Statutory Law 1581 of 2012 (Ley Estatutaria 1581 de 2012 — Habeas Data)
& Decreto Único Reglamentario 1074 de 2015 (Decreto 1377 de 2013)
Covers Colombian Cédula de Ciudadanía & NIT (DIAN Modulo-11) discovery, Prior Express & Informed
Authorization (Art. 4 & 9), Retention & Suppression (Decreto 1377 Art. 11), Titular Consultas
(10 business days, Art. 14) & Reclamos (15 business days, Art. 15), Duty of Security (Art. 17(d):
Encryption, RBAC, Audit Logs, Vulnerability Remediation), 15-Business-Day SIC Incident Reporting
via RNBD (Art. 17(n)), International Transfers/Transmissions (Art. 26, sa-east-1), and Mandatory
RNBD Registration before the Superintendencia de Industria y Comercio (Art. 25 MANUAL_REVIEW).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class CoLaw1581Framework(BaseComplianceFramework):
    framework_id = "COLOMBIA_LAW_1581"
    name = "Colombia Statutory Law 1581 of 2012 (Protección de Datos Personales)"
    region = "CO"
    jurisdiction = "Republic of Colombia"
    category = FrameworkCategory.PRIVACY
    version = "Ley Estatutaria 1581 de 2012 / Decreto 1377 de 2013"
    effective_from = "2012-10-18"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Superintendencia de Industria y Comercio (SIC) — Delegatura para la Protección de Datos Personales"
    breach_notification_window = "Within 15 Business Days of Detection to SIC via RNBD Portal (Circular Externa 002/2015)"
    residency_region = "sa-east-1"
    source_reference = "Diario Oficial No. 48.587 — Ley Estatutaria 1581 de 2012 & Decreto 1074 de 2015"
    supported_privacy_rights = ["ACCESS", "DELETE", "CORRECT", "RECTIFY", "OBJECT"]

    controls = [
        ComplianceControl(
            control_id="CO-1581-PII-DISC",
            framework_id="COLOMBIA_LAW_1581",
            title="Artículos 3 y 5: Cédula de Ciudadanía, NIT (DIAN Módulo-11) & Datos Sensibles Discovery",
            requirement="Discover and classify Colombian Cédula de Ciudadanía, NIT tax identifiers (Modulo-11), Passports, Mobile numbers, and sensitive personal data.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Ley 1581 de 2012 Artículos 3 y 5",
            recommended_action="Ensure Colombia (CO) PII classifiers are active across DLP/DSPM.",
        ),
        ComplianceControl(
            control_id="CO-1581-RETENTION",
            framework_id="COLOMBIA_LAW_1581",
            title="Decreto 1377 de 2013 Artículo 11: Temporalidad del Tratamiento y Supresión",
            requirement="Retain personal data only during the reasonable and necessary time according to processing purposes, then proceed to suppression.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Decreto 1377 de 2013 Artículo 11 (DUR 1074/2015)",
            recommended_action="Enforce 90-day automated telemetry pruning.",
        ),
        ComplianceControl(
            control_id="CO-1581-ART-9-AUTH",
            framework_id="COLOMBIA_LAW_1581",
            title="Artículos 9 y 12: Autorización Previa, Expresa e Informada del Titular & Aviso de Privacidad",
            requirement="Obtain verifiable prior, express, and informed authorization from the Titular and enforce Aviso de Privacidad banners on monitored endpoints.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Ley 1581 de 2012 Artículos 9, 12 y 17(b)",
            recommended_action="Enable MonitoringConsentRequired notice banners on visually monitored endpoints.",
        ),
        ComplianceControl(
            control_id="CO-1581-ART-14-TITULAR",
            framework_id="COLOMBIA_LAW_1581",
            title="Artículos 8, 14 y 15: Atención de Consultas (10 Días Hábiles) y Reclamos (15 Días Hábiles)",
            requirement="Attend Titular Consultas within 10 business days and Reclamos (corrección, actualización, supresión, revocatoria) within 15 business days.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Ley 1581 de 2012 Artículos 8, 14 y 15",
            recommended_action="Fulfill open Colombian Titular Consultas and Reclamos within 10–15 business days.",
        ),
        ComplianceControl(
            control_id="CO-LEY-1581-SEC",
            framework_id="COLOMBIA_LAW_1581",
            title="Artículo 17(d): Principio y Deber de Seguridad de la Información",
            requirement="Preserve information under necessary security conditions preventing adulteration, loss, unauthorized consultation, use, or fraudulent access.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="Ley 1581 de 2012 Artículo 17 literal d) & Artículo 4(g)",
            recommended_action="Remediate exposed Colombian Cédula/NIT datastores in DSPM.",
        ),
        ComplianceControl(
            control_id="CO-1581-ENC",
            framework_id="COLOMBIA_LAW_1581",
            title="Guía SIC de Responsabilidad Demostrada: Cifrado de Datos en Reposo y Tránsito",
            requirement="Apply strong cryptographic controls (AES-256 at rest, TLS 1.3 in transit) per SIC Accountability Guidelines.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Ley 1581 Art. 17(d) & Guía de Responsabilidad Demostrada SIC",
            recommended_action="Enable encryption at rest across all datastores.",
        ),
        ComplianceControl(
            control_id="CO-1581-VULN-RBAC",
            framework_id="COLOMBIA_LAW_1581",
            title="Artículo 17(d): Control de Acceso (RBAC) y Gestión de Vulnerabilidades",
            requirement="Restrict access to personal databases via RBAC and remediate High/Critical software vulnerabilities.",
            category="VULNERABILITY_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Ley 1581 de 2012 Artículo 17 literal d)",
            recommended_action="Remediate High and Critical endpoint software vulnerabilities.",
        ),
        ComplianceControl(
            control_id="CO-1581-AUDIT",
            framework_id="COLOMBIA_LAW_1581",
            title="Decreto 1377 Art. 26–27: Principio de Responsabilidad Demostrada & Trazabilidad",
            requirement="Maintain verifiable, immutable audit logs proving effective implementation of privacy and security measures to the SIC.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Decreto 1377 de 2013 Artículos 26 y 27",
            recommended_action="Maintain tamper-evident AuditLog records.",
        ),
        ComplianceControl(
            control_id="CO-LEY-1581-NOTIFY",
            framework_id="COLOMBIA_LAW_1581",
            title="Artículo 17(n) & Artículo 26: Reporte de Incidentes a la SIC (15 Días Hábiles) & Transferencias (sa-east-1)",
            requirement="Report security code violations and data administration risks to the SIC within 15 business days via RNBD and enforce Art. 26 sa-east-1 cross-border fencing.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="Ley 1581 Artículos 17(n) y 26; Circular Externa SIC 002 de 2015",
            recommended_action="Triage critical security incidents within 15 business days and enforce sa-east-1 fencing.",
        ),
        ComplianceControl(
            control_id="CO-1581-ART-25-RNBD",
            framework_id="COLOMBIA_LAW_1581",
            title="Artículos 17(k) y 25: Registro Nacional de Bases de Datos (RNBD — SIC) & Política de Tratamiento (PTI)",
            requirement="Adopt a written Política de Tratamiento de la Información (PTI), designate an Oficial de Protección de Datos, and register/update databases annually in the SIC RNBD.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="Ley 1581 de 2012 Artículos 17(k) y 25; Decreto 090 de 2018",
            recommended_action="Attach SIC RNBD Filing Receipt, Signed Política de Tratamiento de Datos Personales, and Officer Appointment.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        res_check = await self.probe_data_residency_fencing(tenant_id, "sa-east-1", db, "CO-LEY-1581-NOTIFY", "Ley 1581 Artículo 26")
        inc_check = await self.probe_incident_response_backlog(tenant_id, db, "CO-LEY-1581-NOTIFY", "Ley 1581 Artículo 17(n)")
        combined = inc_check if inc_check.status.value != "PASS" else res_check
        combined.control_id = "CO-LEY-1581-NOTIFY"

        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "CO", db, "CO-1581-PII-DISC", "Ley 1581 Art. 3 & 5"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "CO-1581-RETENTION", "Decreto 1377 Art. 11"),
            await self.probe_visual_privacy_consent(tenant_id, db, "CO-1581-ART-9-AUTH", "Ley 1581 Art. 9 & 12"),
            await self.probe_privacy_request_sla(tenant_id, db, "CO-1581-ART-14-TITULAR", "Ley 1581 Art. 14 & 15", sla_days=10),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "CO-LEY-1581-SEC", "Ley 1581 Art. 17(d)"),
            await self.probe_encryption_and_tls(tenant_id, db, "CO-1581-ENC", "Guía Responsabilidad Demostrada SIC"),
            await self.probe_vulnerability_backlog(tenant_id, db, "CO-1581-VULN-RBAC", "Ley 1581 Art. 17(d)"),
            await self.probe_audit_logging_active(tenant_id, db, "CO-1581-AUDIT", "Decreto 1377 Art. 26–27"),
            combined,
            self.manual_review_control(
                "CO-1581-ART-25-RNBD",
                "Inscripción RNBD ante la SIC & Política de Tratamiento de Datos",
                "Verificar inscripción y actualización anual en el Registro Nacional de Bases de Datos (RNBD) de la Superintendencia de Industria y Comercio y Política de Tratamiento vigente.",
                "Ley 1581 de 2012 Artículos 17(k) y 25",
                "Radicado RNBD vigente ante la SIC, Política de Tratamiento de la Información & Oficial de Privacidad",
                tenant_id=tenant_id,
            ),
        ]


async def run_colombia_law_1581_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await CoLaw1581Framework().run_checks(tenant_id=tenant_id, db=db, context=context)
