"""
[v4.4.0] Argentina Personal Data Protection Law (Ley 25.326 de Protección de los Datos Personales)
& Resolución AAIP 47/2018 Security Measures
Covers Argentine DNI & CUIT/CUIL (Modulo-11) discovery, Data Quality & Destruction (Art. 4),
Free, Express & Informed Written Consent & Mandatory Notice (Art. 5 & 6), Habeas Data Access
Within 10 Calendar Days & Rectification/Suppression Within 5 Business Days (Art. 14–16),
Technical & Organizational Security Measures per Resolución AAIP 47/2018 (Art. 9: Encryption,
RBAC, Audit Logs, Vulnerability Management), AAIP Security Incident Reporting, International
Transfer Prohibition Without Adequate Protection (Art. 12, sa-east-1), and AAIP Registro Nacional
de Bases de Datos Filing (Art. 21 MANUAL_REVIEW).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class ArPdpaFramework(BaseComplianceFramework):
    framework_id = "ARGENTINA_PDPL"
    name = "Argentina Personal Data Protection Law (Ley 25.326 — Habeas Data)"
    region = "AR"
    jurisdiction = "Argentine Republic"
    category = FrameworkCategory.PRIVACY
    version = "Ley 25.326 / Decreto 1558/2001 / Resol. AAIP 47/2018"
    effective_from = "2000-11-02"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "Agencia de Acceso a la Información Pública (AAIP)"
    breach_notification_window = "Promptly to AAIP with Incident Record per Resolución AAIP 47/2018"
    residency_region = "sa-east-1"
    source_reference = "Boletín Oficial de la República Argentina — Ley 25.326 & Resolución AAIP 47/2018"
    supported_privacy_rights = ["ACCESS", "DELETE", "CORRECT", "RECTIFY", "RESTRICT", "OBJECT"]

    controls = [
        ComplianceControl(
            control_id="AR-PDPL-PII-DISC",
            framework_id="ARGENTINA_PDPL",
            title="Artículos 2 y 7: DNI, CUIT/CUIL (Módulo-11), CBU & Datos Sensibles Discovery",
            requirement="Discover and classify Argentine DNI numbers, 11-digit CUIT/CUIL tax identifiers (Modulo-11), 22-digit CBU bank identifiers, and sensitive personal data.",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Ley 25.326 Artículos 2 y 7",
            recommended_action="Ensure Argentina (AR) PII classifiers are active across DLP/DSPM.",
        ),
        ComplianceControl(
            control_id="AR-PDPL-ART-4-RET",
            framework_id="ARGENTINA_PDPL",
            title="Artículo 4(7): Calidad de los Datos y Destrucción al Cumplirse la Finalidad",
            requirement="Destroy personal data when it ceases to be necessary or pertinent to the purposes for which it was collected.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Ley 25.326 Artículo 4 inciso 7",
            recommended_action="Enforce 90-day automated telemetry pruning.",
        ),
        ComplianceControl(
            control_id="AR-PDPL-ART-5-CONSENT",
            framework_id="ARGENTINA_PDPL",
            title="Artículos 5 y 6: Consentimiento Libre, Expreso e Informado & Información Previa",
            requirement="Obtain free, express, and informed consent and display statutory Art. 6 rights notices on visually monitored endpoints.",
            category="CONSENT_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Ley 25.326 Artículos 5 y 6",
            recommended_action="Enable MonitoringConsentRequired notice banners on visually monitored endpoints.",
        ),
        ComplianceControl(
            control_id="AR-PDPL-ART-14-HABEAS",
            framework_id="ARGENTINA_PDPL",
            title="Artículos 14–16: Derecho de Acceso (10 Días Corridos) y Rectificación/Supresión (5 Días Hábiles)",
            requirement="Fulfill data subject access requests within 10 calendar days and rectification/updating/suppression within 5 business days (Habeas Data SLA).",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Ley 25.326 Artículos 14, 15 y 16",
            recommended_action="Fulfill open Argentine Habeas Data DSR requests within 10 calendar days.",
        ),
        ComplianceControl(
            control_id="AR-LPDP-ART-9-SEC",
            framework_id="ARGENTINA_PDPL",
            title="Artículo 9 & Resol. AAIP 47/2018: Seguridad y Confidencialidad de los Datos",
            requirement="Adopt technical and organizational measures guaranteeing security and confidentiality of personal data to prevent alteration, loss, or unauthorized access.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="Ley 25.326 Artículo 9 & Resolución AAIP 47/2018",
            recommended_action="Remediate exposed Argentine PII datastores in DSPM.",
        ),
        ComplianceControl(
            control_id="AR-PDPL-AAIP-ENC",
            framework_id="ARGENTINA_PDPL",
            title="Resolución AAIP 47/2018 Anexo I–II: Cifrado de Datos en Almacenamiento y Tránsito",
            requirement="Encrypt sensitive and personal databases at rest (AES-256) and protect network transmission via TLS 1.3.",
            category="ENCRYPTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Resolución AAIP 47/2018 (Medidas de Seguridad Nivel Medio/Crítico)",
            recommended_action="Enable encryption at rest across all datastores.",
        ),
        ComplianceControl(
            control_id="AR-PDPL-AAIP-VULN",
            framework_id="ARGENTINA_PDPL",
            title="Resolución AAIP 47/2018: Control de Acceso (RBAC) y Gestión de Vulnerabilidades",
            requirement="Enforce least-privilege RBAC profiles and remediate High/Critical software vulnerabilities.",
            category="VULNERABILITY_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Ley 25.326 Art. 9 & Resolución AAIP 47/2018",
            recommended_action="Remediate High and Critical endpoint software vulnerabilities.",
        ),
        ComplianceControl(
            control_id="AR-PDPL-AAIP-AUDIT",
            framework_id="ARGENTINA_PDPL",
            title="Resolución AAIP 47/2018: Registro de Accesos y Auditoría Inalterable",
            requirement="Maintain immutable audit logs recording user ID, timestamp, file accessed, and type of access.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Resolución AAIP 47/2018",
            recommended_action="Maintain tamper-evident AuditLog records.",
        ),
        ComplianceControl(
            control_id="AR-LPDP-AAIP-NOTIFY",
            framework_id="ARGENTINA_PDPL",
            title="Resolución AAIP 47/2018 & Art. 12: Gestión de Incidentes AAIP & Transferencia Internacional (sa-east-1)",
            requirement="Manage and report security incidents compromising personal data to the AAIP and prohibit unauthorized cross-border transfers outside sa-east-1.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="Ley 25.326 Artículo 12, Disposición 60-E/2016 & Resolución AAIP 47/2018",
            recommended_action="Triage critical security incidents and enforce sa-east-1 residency fencing.",
        ),
        ComplianceControl(
            control_id="AR-PDPL-ART-21-REG",
            framework_id="ARGENTINA_PDPL",
            title="Artículo 21 & Resol. AAIP 132/2018: Inscripción en el Registro Nacional de Bases de Datos (AAIP)",
            requirement="Register every public or private personal database in the Registro Nacional de Bases de Datos Privadas administered by the AAIP via TAD.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="Ley 25.326 Artículo 21 & Resolución AAIP 132/2018",
            recommended_action="Attach AAIP Registro Nacional de Bases de Datos Certificate (Constancia de Inscripción TAD) and Mandatory Art. 6 Poster/Legend.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        res_check = await self.probe_data_residency_fencing(tenant_id, "sa-east-1", db, "AR-LPDP-AAIP-NOTIFY", "Ley 25.326 Art. 12")
        inc_check = await self.probe_incident_response_backlog(tenant_id, db, "AR-LPDP-AAIP-NOTIFY", "Resolución AAIP 47/2018")
        combined = inc_check if inc_check.status.value != "PASS" else res_check
        combined.control_id = "AR-LPDP-AAIP-NOTIFY"

        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "AR", db, "AR-PDPL-PII-DISC", "Ley 25.326 Art. 2 & 7"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "AR-PDPL-ART-4-RET", "Ley 25.326 Art. 4(7)"),
            await self.probe_visual_privacy_consent(tenant_id, db, "AR-PDPL-ART-5-CONSENT", "Ley 25.326 Art. 5 & 6"),
            await self.probe_privacy_request_sla(tenant_id, db, "AR-PDPL-ART-14-HABEAS", "Ley 25.326 Art. 14–16", sla_days=10),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "AR-LPDP-ART-9-SEC", "Ley 25.326 Art. 9"),
            await self.probe_encryption_and_tls(tenant_id, db, "AR-PDPL-AAIP-ENC", "Resolución AAIP 47/2018"),
            await self.probe_vulnerability_backlog(tenant_id, db, "AR-PDPL-AAIP-VULN", "Ley 25.326 Art. 9"),
            await self.probe_audit_logging_active(tenant_id, db, "AR-PDPL-AAIP-AUDIT", "Resolución AAIP 47/2018"),
            combined,
            self.manual_review_control(
                "AR-PDPL-ART-21-REG",
                "Inscripción en el Registro Nacional de Bases de Datos (AAIP)",
                "Verificar inscripción vigente de las bases de datos personales ante la Dirección Nacional de Protección de Datos Personales (AAIP).",
                "Ley 25.326 Artículo 21 & Resolución AAIP 132/2018",
                "Constancia de Inscripción AAIP (Trámites a Distancia — TAD) & Cláusulas Tipo Disp. 60-E/2016",
                tenant_id=tenant_id,
            ),
        ]


async def run_argentina_pdpl_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await ArPdpaFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
