"""
[v2.8.0] CISA Cross-Sector Cybersecurity Performance Goals (CPGs)
Covers baseline cybersecurity goals established by CISA for critical infrastructure sectors.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class CisaCrossSectorFramework(BaseComplianceFramework):
    framework_id = "CISA_CPG"
    name = "CISA Cross-Sector Cybersecurity Performance Goals"
    region = "US"
    jurisdiction = "United States"
    category = FrameworkCategory.CYBERSECURITY
    version = "v1.0.1"
    source_reference = "Cybersecurity and Infrastructure Security Agency (CISA) CPGs"

    controls = [
        ComplianceControl(
            control_id="CPG-1-ACCOUNT-SECURITY",
            framework_id="CISA_CPG",
            title="CPG 1.1: Account Security & Multi-Factor Authentication",
            requirement="Implement MFA for all administrative and remote access pathways.",
            category="ACCESS_CONTROL",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="CISA CPG 1.1",
            recommended_action="Enforce strict authentication and audit trails for privileged access."
        ),
        ComplianceControl(
            control_id="CPG-2-VULN-REMEDIATION",
            framework_id="CISA_CPG",
            title="CPG 2.1: Known Exploited Vulnerabilities (KEV) Remediation",
            requirement="Mitigate all known exploited vulnerabilities in accordance with CISA Binding Operational Directives.",
            category="VULNERABILITY_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="CISA CPG 2.1",
            recommended_action="Resolve any vulnerabilities currently catalogued as known exploited."
        ),
        ComplianceControl(
            control_id="CPG-3-LOGGING",
            framework_id="CISA_CPG",
            title="CPG 3.1: Centralized Incident & Audit Logging",
            requirement="Ensure essential security logs are collected, aggregated, and retained securely.",
            category="LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="CISA CPG 3.1",
            recommended_action="Maintain continuous audit logging and log storage integrity."
        )
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ComplianceCheckResult]:
        results = []
        results.append(await self.probe_audit_logging_active(tenant_id, db, "CPG-1-ACCOUNT-SECURITY", "CISA CPG 1.1"))
        results.append(await self.probe_vulnerability_backlog(tenant_id, db, "CPG-2-VULN-REMEDIATION", "CISA CPG 2.1"))
        results.append(await self.probe_audit_logging_active(tenant_id, db, "CPG-3-LOGGING", "CISA CPG 3.1"))
        return results
