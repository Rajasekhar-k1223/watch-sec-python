"""
[v2.8.0] CMMC 2.0 (Cybersecurity Maturity Model Certification) Implementation
Department of Defense defense industrial base cybersecurity requirements (NIST SP 800-171).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class CmmcFramework(BaseComplianceFramework):
    framework_id = "CMMC"
    name = "Cybersecurity Maturity Model Certification (CMMC 2.0)"
    region = "US"
    jurisdiction = "United States Department of Defense"
    category = FrameworkCategory.GOVERNMENT
    version = "CMMC 2.0 (Level 2 / NIST SP 800-171 Rev. 2)"
    source_reference = "DoD 32 CFR Part 170 / CMMC 2.0 Program"

    controls = [
        ComplianceControl(
            control_id="CMMC-AC-L2-3-1-1",
            framework_id="CMMC",
            title="AC.L2-3.1.1: Authorized System Access & Least Privilege",
            requirement="Limit system access to authorized users, processes acting on behalf of authorized users, and devices.",
            category="ACCESS_CONTROL",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="CMMC AC.L2-3.1.1 (NIST SP 800-171 3.1.1)",
            recommended_action="Enforce strict authentication and enrollment validation."
        ),
        ComplianceControl(
            control_id="CMMC-AU-L2-3-3-1",
            framework_id="CMMC",
            title="AU.L2-3.3.1: System Audit Logging & Review",
            requirement="Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity.",
            category="AUDIT_ACCOUNTABILITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="CMMC AU.L2-3.3.1 (NIST SP 800-171 3.3.1)",
            recommended_action="Maintain centralized audit trails with integrity validation."
        ),
        ComplianceControl(
            control_id="CMMC-IR-L2-3-6-1",
            framework_id="CMMC",
            title="IR.L2-3.6.1: Incident Handling & Reporting",
            requirement="Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="CMMC IR.L2-3.6.1 (NIST SP 800-171 3.6.1)",
            recommended_action="Ensure rapid response and triage of critical security incidents."
        ),
        ComplianceControl(
            control_id="CMMC-SI-L2-3-14-1",
            framework_id="CMMC",
            title="SI.L2-3.14.1: Flaw Remediation & Vulnerability Mitigation",
            requirement="Identify, report, and correct system flaws in a timely manner.",
            category="SYSTEM_INTEGRITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="CMMC SI.L2-3.14.1 (NIST SP 800-171 3.14.1)",
            recommended_action="Remediate detected CVE flaws within established SLAs."
        )
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ComplianceCheckResult]:
        results = []
        results.append(await self.probe_agent_enrollment_health(tenant_id, db, "CMMC-AC-L2-3-1-1", "NIST SP 800-171 3.1.1"))
        results.append(await self.probe_audit_logging_active(tenant_id, db, "CMMC-AU-L2-3-3-1", "NIST SP 800-171 3.3.1"))
        results.append(await self.probe_incident_response_backlog(tenant_id, db, "CMMC-IR-L2-3-6-1", "NIST SP 800-171 3.6.1"))
        results.append(await self.probe_vulnerability_backlog(tenant_id, db, "CMMC-SI-L2-3-14-1", "NIST SP 800-171 3.14.1"))
        return results
