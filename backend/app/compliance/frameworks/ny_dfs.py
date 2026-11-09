"""
[v2.8.0] New York Department of Financial Services (NYDFS 23 NYCRR 500) Implementation
Financial services cybersecurity requirements as amended in 2023.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class NyDfsFramework(BaseComplianceFramework):
    framework_id = "NYDFS_500"
    name = "NYDFS Cybersecurity Regulation (23 NYCRR 500)"
    region = "US"
    jurisdiction = "New York, United States"
    category = FrameworkCategory.FINANCIAL
    version = "23 NYCRR Part 500 (2023 Amendment)"
    source_reference = "New York Codes, Rules and Regulations (23 NYCRR 500)"

    controls = [
        ComplianceControl(
            control_id="NYDFS-500-02-PROGRAM",
            framework_id="NYDFS_500",
            title="Section 500.02: Cybersecurity Program",
            requirement="Maintain a cybersecurity program designed to protect the confidentiality, integrity and availability of Information Systems.",
            category="GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="23 NYCRR § 500.02",
            recommended_action="Ensure continuous vulnerability scanning and asset monitoring."
        ),
        ComplianceControl(
            control_id="NYDFS-500-06-AUDIT",
            framework_id="NYDFS_500",
            title="Section 500.06: Audit Trail & Log Retention",
            requirement="Securely maintain systems that produce and maintain audit trails sufficient to track and document transactions and unauthorized access.",
            category="AUDIT_TRAIL",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="23 NYCRR § 500.06",
            recommended_action="Maintain at least three years of immutable audit log records."
        ),
        ComplianceControl(
            control_id="NYDFS-500-17-NOTICES",
            framework_id="NYDFS_500",
            title="Section 500.17: Notices to Superintendent (72-Hour Breach)",
            requirement="Notify the superintendent as promptly as possible but in no event later than 72 hours from a determination that a Cybersecurity Event has occurred.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="23 NYCRR § 500.17",
            recommended_action="Resolve or escalate critical security incidents within SLA."
        )
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ComplianceCheckResult]:
        results = []
        results.append(await self.probe_vulnerability_backlog(tenant_id, db, "NYDFS-500-02-PROGRAM", "23 NYCRR § 500.02"))
        results.append(await self.probe_audit_logging_active(tenant_id, db, "NYDFS-500-06-AUDIT", "23 NYCRR § 500.06"))
        results.append(await self.probe_incident_response_backlog(tenant_id, db, "NYDFS-500-17-NOTICES", "23 NYCRR § 500.17"))
        return results
