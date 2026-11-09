"""
[v2.8.0] FedRAMP (Federal Risk and Authorization Management Program) Implementation
Evaluates NIST SP 800-53 Rev. 5 controls baseline for federal cloud systems.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class FedrampFramework(BaseComplianceFramework):
    framework_id = "FEDRAMP"
    name = "Federal Risk and Authorization Management Program (FedRAMP)"
    region = "US"
    jurisdiction = "United States Federal Government"
    category = FrameworkCategory.GOVERNMENT
    version = "Rev. 5 Baseline (High/Moderate)"
    source_reference = "FedRAMP Security Assessment Framework based on NIST SP 800-53 Rev. 5"

    controls = [
        ComplianceControl(
            control_id="FEDRAMP-AC-2-ACCOUNT",
            framework_id="FEDRAMP",
            title="AC-2: Account Management & Least Privilege",
            requirement="Manage information system accounts, including establishing, activating, modifying, disabling, and removing accounts in accordance with procedures.",
            category="ACCESS_CONTROL",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="NIST SP 800-53 Rev. 5 AC-2",
            recommended_action="Regularly audit inactive accounts and enforce MFA."
        ),
        ComplianceControl(
            control_id="FEDRAMP-AU-2-AUDIT",
            framework_id="FEDRAMP",
            title="AU-2: Event Logging & Audit Generation",
            requirement="Identify events that require logging and ensure audit records contain sufficient information to establish what events occurred and who initiated them.",
            category="AUDIT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="NIST SP 800-53 Rev. 5 AU-2",
            recommended_action="Maintain centralized, tamper-evident audit logging."
        ),
        ComplianceControl(
            control_id="FEDRAMP-RA-5-VULN",
            framework_id="FEDRAMP",
            title="RA-5: Vulnerability Monitoring and Scanning",
            requirement="Monitor system components for vulnerabilities and remediate in accordance with risk assessments (30 days for High/Critical).",
            category="VULNERABILITY_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="NIST SP 800-53 Rev. 5 RA-5",
            recommended_action="Remediate open critical and high vulnerability CVEs within 30 days."
        ),
        ComplianceControl(
            control_id="FEDRAMP-SI-4-MONITOR",
            framework_id="FEDRAMP",
            title="SI-4: Information System Monitoring",
            requirement="Monitor the information system to detect attacks, indicators of compromise, and unauthorized local, network, and remote connections.",
            category="MONITORING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="NIST SP 800-53 Rev. 5 SI-4",
            recommended_action="Maintain continuous agent telemetry and endpoint monitoring."
        )
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ComplianceCheckResult]:
        results = []
        results.append(await self.probe_audit_logging_active(tenant_id, db, "FEDRAMP-AC-2-ACCOUNT", "NIST SP 800-53 AC-2"))
        results.append(await self.probe_audit_logging_active(tenant_id, db, "FEDRAMP-AU-2-AUDIT", "NIST SP 800-53 AU-2"))
        results.append(await self.probe_vulnerability_backlog(tenant_id, db, "FEDRAMP-RA-5-VULN", "NIST SP 800-53 RA-5"))
        results.append(await self.probe_agent_enrollment_health(tenant_id, db, "FEDRAMP-SI-4-MONITOR", "NIST SP 800-53 SI-4"))
        return results
