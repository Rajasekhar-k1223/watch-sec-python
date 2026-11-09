"""
[v4.4.0] China Cybersecurity Law (CSL / MLPS 2.0) — PRC President Order No. 53
Implements MLPS 2.0 technical controls: network monitoring, access control,
6-month (180-day) network audit log retention, vulnerability remediation,
emergency response, backup/recovery, CII localization fencing (cn-north-1),
and CIIO / MLPS Level 3 MPS record-filing (`MANUAL_REVIEW`).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class ChinaCslFramework(BaseComplianceFramework):
    framework_id = "CHINA_CSL"
    name = "Cybersecurity Law of the PRC (CSL / MLPS 2.0)"
    region = "CN"
    jurisdiction = "People's Republic of China"
    category = FrameworkCategory.CYBERSECURITY
    version = "Order No. 53 of the President of the PRC (GB/T 22239-2019 MLPS 2.0)"
    effective_from = "2017-06-01"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "CAC & Ministry of Public Security (MPS)"
    breach_notification_window = "Immediate Emergency Plan Activation & Competent Authority Report (Art. 25)"
    residency_region = "cn-north-1"
    source_reference = "Cybersecurity Law of the PRC & GB/T 22239-2019 (MLPS 2.0)"
    supported_privacy_rights = ["ACCESS", "DELETE", "CORRECT"]

    controls = [
        ComplianceControl(
            control_id="CSL-ART-21-1-IAM",
            framework_id="CHINA_CSL",
            title="MLPS 2.0 Identity Authentication & Access Control (Art. 21(1))",
            requirement="Formulate internal security management systems and enforce strict access controls against network intrusion.",
            category="ACCESS_CONTROL",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="CSL Art. 21(1) & GB/T 22239-2019",
            recommended_action="Enforce RBAC role boundaries and MFA/mTLS authentication.",
        ),
        ComplianceControl(
            control_id="CSL-ART-21-2-MON",
            framework_id="CHINA_CSL",
            title="MLPS 2.0 Continuous Network & Endpoint Malware/Intrusion Monitoring (Art. 21(2))",
            requirement="Adopt technical measures to prevent computer viruses, network attacks, and network intrusions.",
            category="MONITORING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="CSL Art. 21(2)",
            recommended_action="Maintain active Monitorix endpoint sensors across network nodes.",
        ),
        ComplianceControl(
            control_id="CSL-ART-21-3-LOGS",
            framework_id="CHINA_CSL",
            title="MLPS 2.0 Network Operational Status & >=6-Month Audit Log Preservation (Art. 21(3))",
            requirement="Monitor and record network operational status and cybersecurity events, preserving relevant web/audit logs for no less than 6 months.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="CSL Art. 21(3)",
            recommended_action="Ensure tamper-evident AuditLog preservation is active.",
        ),
        ComplianceControl(
            control_id="CSL-ART-21-4-BACKUP",
            framework_id="CHINA_CSL",
            title="MLPS 2.0 Important Data Classification, Backup & Encryption (Art. 21(4))",
            requirement="Adopt measures such as data classification, backup of important data, and encryption.",
            category="OPERATIONS_RECOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="CSL Art. 21(4)",
            recommended_action="Verify HA/DR replication and AES-256 datastore encryption.",
        ),
        ComplianceControl(
            control_id="CSL-ART-22-VULN",
            framework_id="CHINA_CSL",
            title="Security Defect & Vulnerability Immediate Remediation (Art. 22)",
            requirement="Immediately take remedial measures upon discovering security defects or vulnerabilities.",
            category="VULNERABILITY_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="CSL Art. 22",
            recommended_action="Patch High/Critical software vulnerabilities promptly.",
        ),
        ComplianceControl(
            control_id="CSL-ART-25-EMERGENCY",
            framework_id="CHINA_CSL",
            title="Cybersecurity Incident Emergency Plan & Authority Reporting (Art. 25)",
            requirement="Immediately initiate emergency plans upon security incidents, take corresponding remedial measures, and report to competent departments.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="CSL Art. 25",
            recommended_action="Resolve open critical security incidents.",
        ),
        ComplianceControl(
            control_id="CSL-ART-37-LOCALIZATION",
            framework_id="CHINA_CSL",
            title="CII Domestic Storage & Sovereign Boundary Fencing (Art. 37)",
            requirement="Personal information and important data gathered or produced by CII operators within mainland China shall be stored domestically.",
            category="DATA_RESIDENCY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="CSL Art. 37",
            recommended_action="Enforce cn-north-1 sovereign boundary fencing.",
        ),
        ComplianceControl(
            control_id="CSL-ART-31-CII-MLPS",
            framework_id="CHINA_CSL",
            title="CIIO Applicability Tracking & MPS MLPS 2.0 Level 2/3 Filing Certificate",
            requirement="Determine Critical Information Infrastructure Operator (CIIO) status and maintain Ministry of Public Security (MPS) MLPS grading filing.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="CSL Art. 31, Art. 34 & CII Security Protection Regulations (State Council Order No. 745)",
            recommended_action="Upload MPS MLPS Level 2/3 Record-Filing Certificate and CIIO annual security review.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        return [
            await self.probe_access_control_rbac_mfa(tenant_id, db, "CSL-ART-21-1-IAM", "CSL Art. 21(1)"),
            await self.probe_agent_enrollment_health(tenant_id, db, "CSL-ART-21-2-MON", "CSL Art. 21(2)"),
            await self.probe_audit_logging_active(tenant_id, db, "CSL-ART-21-3-LOGS", "CSL Art. 21(3)"),
            await self.probe_backup_and_dr_readiness(tenant_id, db, "CSL-ART-21-4-BACKUP", "CSL Art. 21(4)"),
            await self.probe_vulnerability_backlog(tenant_id, db, "CSL-ART-22-VULN", "CSL Art. 22"),
            await self.probe_incident_response_backlog(tenant_id, db, "CSL-ART-25-EMERGENCY", "CSL Art. 25"),
            await self.probe_data_residency_fencing(tenant_id, "cn-north-1", db, "CSL-ART-37-LOCALIZATION", "CSL Art. 37"),
            self.manual_review_control(
                "CSL-ART-31-CII-MLPS",
                "CIIO Applicability Tracking & MPS MLPS 2.0 Grading Filing",
                "Verify Ministry of Public Security (MPS) MLPS 2.0 grading record-filing and CIIO sector regulator designation.",
                "CSL Art. 31 & State Council Order No. 745",
                "MPS MLPS Level 2/3 Record-Filing Certificate & Annual Accredited Testing Report",
                tenant_id=tenant_id,
            ),
        ]


async def run_china_csl_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await ChinaCslFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
