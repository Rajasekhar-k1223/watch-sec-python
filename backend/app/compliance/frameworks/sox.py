"""
[v4.4.0] USA Sarbanes-Oxley Act of 2002 (SOX) — Automated IT General Controls (ITGC) Framework
Implements SOX Section 404 & Section 802 ITGC domains:
- Access Control (Logical access, RBAC segregation of duties)
- Change Management (Cryptographically signed releases & patch integrity)
- Backup & Computer Operations (HA/DR RPO=0 continuity, incident operations, endpoint monitoring)
- Audit Logging (Tamper-evident AuditLog retention & immutability)
- Financial Data Safeguards (Encryption & DSPM exposure checks)
- Section 302 Executive Financial Disclosure Certification (Manual Review)
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class SoxFramework(BaseComplianceFramework):
    framework_id = "SOX"
    name = "Sarbanes-Oxley Act (SOX ITGC §404 / §802)"
    region = "US"
    jurisdiction = "United States"
    category = FrameworkCategory.FINANCIAL
    version = "Pub.L. 107-204 (PCAOB AS 2201 ITGC)"
    effective_from = "2002-07-30"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "U.S. SEC & Public Company Accounting Oversight Board (PCAOB)"
    breach_notification_window = "4 Business Days for Material Cybersecurity Incidents (SEC Item 1.05)"
    residency_region = "us-east-1"
    source_reference = "15 U.S.C. § 7262 (SOX §404), 18 U.S.C. § 1519 (SOX §802), PCAOB AS 2201"
    supported_privacy_rights = ["ACCESS"]

    controls = [
        ComplianceControl(
            control_id="SOX-ITGC-AC-01",
            framework_id="SOX",
            title="ITGC Logical Access Control & Role Segregation (§404)",
            requirement="Restrict access to financial reporting infrastructure through role-based access control and least-privilege authentication.",
            category="ACCESS_CONTROL",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="SOX Section 404 / PCAOB AS 2201 (Access to Programs and Data)",
            recommended_action="Enforce RBAC role boundaries and revoke unauthorized administrative accounts.",
        ),
        ComplianceControl(
            control_id="SOX-ITGC-CM-01",
            framework_id="SOX",
            title="ITGC Program Change Management & Signed Release Integrity (§404)",
            requirement="Ensure production software deployments and updates are cryptographically signed, authorized, and version-tracked.",
            category="CHANGE_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="SOX Section 404 / PCAOB AS 2201 (Program Changes)",
            recommended_action="Deploy only Ed25519-signed SoftwareReleases and record change history.",
        ),
        ComplianceControl(
            control_id="SOX-ITGC-CM-02",
            framework_id="SOX",
            title="ITGC Patch & Vulnerability Hygiene on Production Hosts (§404)",
            requirement="Prevent unauthorized exploitation of financial systems by remediating critical/high software vulnerabilities.",
            category="VULNERABILITY_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="SOX Section 404 (System Integrity)",
            recommended_action="Remediate High/Critical vulnerabilities on monitored servers.",
        ),
        ComplianceControl(
            control_id="SOX-ITGC-OPS-01",
            framework_id="SOX",
            title="ITGC Computer Operations: Backup, Failover & Disaster Recovery (§404)",
            requirement="Maintain resilient backup and active-active failover capability to prevent loss or corruption of financial audit records.",
            category="OPERATIONS_RECOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="SOX Section 404 / PCAOB AS 2201 (Computer Operations)",
            recommended_action="Verify active-active replication health and zero-RPO recovery readiness.",
        ),
        ComplianceControl(
            control_id="SOX-ITGC-OPS-02",
            framework_id="SOX",
            title="ITGC Computer Operations: Incident Management & SEC Materiality Triage (§404)",
            requirement="Detect, log, and resolve operational and cybersecurity incidents affecting internal controls over financial reporting.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="SOX Section 404 & SEC Form 8-K Item 1.05",
            recommended_action="Resolve open critical operational/security incidents promptly.",
        ),
        ComplianceControl(
            control_id="SOX-ITGC-AUD-802",
            framework_id="SOX",
            title="ITGC Tamper-Evident Audit Trail & Record Preservation (§802)",
            requirement="Preserve immutable administrative, access, and compliance audit logs against alteration or destruction.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="SOX Section 802 (18 U.S.C. § 1519) & Section 404",
            recommended_action="Ensure tamper-evident AuditLog recording is active.",
        ),
        ComplianceControl(
            control_id="SOX-ITGC-SEC-FIN",
            framework_id="SOX",
            title="ITGC Financial Data Repository Encryption & Exposure Protection (§404)",
            requirement="Protect financial databases and billing datastores with encryption at rest and restricted access.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="SOX Section 404 (Data Integrity & Confidentiality)",
            recommended_action="Remediate exposed financial datastores in DSPM.",
        ),
        ComplianceControl(
            control_id="SOX-SEC-302-EXEC",
            framework_id="SOX",
            title="Section 302 CEO/CFO Quarterly Internal Control Certification & External Audit",
            requirement="Principal executive and financial officers must review and certify internal controls over financial reporting (ICFR) alongside external PCAOB auditor attestation.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="SOX Section 302 & Section 404(b)",
            recommended_action="Attach signed quarterly Section 302 executive certifications and external auditor ICFR report.",
        ),
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        return [
            await self.probe_access_control_rbac_mfa(tenant_id, db, "SOX-ITGC-AC-01", "SOX §404 Access Control"),
            await self.probe_supply_chain_tampering(tenant_id, db, "SOX-ITGC-CM-01", "SOX §404 Change Management"),
            await self.probe_vulnerability_backlog(tenant_id, db, "SOX-ITGC-CM-02", "SOX §404 Patch Management"),
            await self.probe_backup_and_dr_readiness(tenant_id, db, "SOX-ITGC-OPS-01", "SOX §404 Backup & Operations"),
            await self.probe_incident_response_backlog(tenant_id, db, "SOX-ITGC-OPS-02", "SOX §404 Incident Operations"),
            await self.probe_audit_logging_active(tenant_id, db, "SOX-ITGC-AUD-802", "SOX §802 Tamper-Evident Audit"),
            await self.probe_dspm_sensitive_exposure(tenant_id, "FINANCIAL", db, "SOX-ITGC-SEC-FIN", "SOX §404 Financial Data Safeguards"),
            self.manual_review_control(
                "SOX-SEC-302-EXEC",
                "Section 302 CEO/CFO Certification & PCAOB External Audit Attestation",
                "Verify signed quarterly executive ICFR certifications and independent registered public accounting firm attestation.",
                "SOX Section 302 & Section 404(b)",
                "Signed SOX §302 Certification & External PCAOB AS 2201 Audit Opinion",
                tenant_id=tenant_id,
            ),
        ]


async def run_sox_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await SoxFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
