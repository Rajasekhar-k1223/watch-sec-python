"""
[v2.8.0] NIST Cybersecurity Framework 2.0 (CSF 2.0) Implementation
NIST CSWP 29 covering GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class NistCsfFramework(BaseComplianceFramework):
    framework_id = "NIST_CSF"
    name = "NIST Cybersecurity Framework 2.0"
    region = "US"
    jurisdiction = "United States"
    category = FrameworkCategory.CYBERSECURITY
    version = "NIST CSF 2.0 (CSWP 29)"
    source_reference = "National Institute of Standards and Technology Cybersecurity Framework 2.0"

    controls = [
        ComplianceControl(
            control_id="CSF2-GV-OC-01",
            framework_id="NIST_CSF",
            title="GV.OC-01: Organizational Context & Risk Management",
            requirement="The organizational context, mission, and cybersecurity risk governance are understood and inform cybersecurity risk management.",
            category="GOVERN",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="NIST CSF 2.0 GV.OC-01",
            recommended_action="Ensure continuous vulnerability and risk posture tracking."
        ),
        ComplianceControl(
            control_id="CSF2-PR-AC-01",
            framework_id="NIST_CSF",
            title="PR.AC-01: Identity Management & Access Control",
            requirement="Identities and credentials for authorized users, services, and hardware are managed by the organization.",
            category="PROTECT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="NIST CSF 2.0 PR.AC-01",
            recommended_action="Enforce strict role-based access control and zero lingering unauthenticated agents."
        ),
        ComplianceControl(
            control_id="CSF2-DE-CM-01",
            framework_id="NIST_CSF",
            title="DE.CM-01: Continuous Monitoring & Threat Detection",
            requirement="Networks and assets are monitored to find potentially adverse events and unauthorized activity.",
            category="DETECT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="NIST CSF 2.0 DE.CM-01",
            recommended_action="Maintain active agent telemetry and real-time event streaming."
        ),
        ComplianceControl(
            control_id="CSF2-RS-MA-01",
            framework_id="NIST_CSF",
            title="RS.MA-01: Incident Response Management & Triage",
            requirement="Incident response processes and procedures are executed and maintained to support incident management.",
            category="RESPOND",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="NIST CSF 2.0 RS.MA-01",
            recommended_action="Triage open high-severity incidents promptly."
        )
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ComplianceCheckResult]:
        results = []
        results.append(await self.probe_vulnerability_backlog(tenant_id, db, "CSF2-GV-OC-01", "NIST CSF 2.0 GV.OC-01"))
        results.append(await self.probe_audit_logging_active(tenant_id, db, "CSF2-PR-AC-01", "NIST CSF 2.0 PR.AC-01"))
        results.append(await self.probe_agent_enrollment_health(tenant_id, db, "CSF2-DE-CM-01", "NIST CSF 2.0 DE.CM-01"))
        results.append(await self.probe_incident_response_backlog(tenant_id, db, "CSF2-RS-MA-01", "NIST CSF 2.0 RS.MA-01"))
        return results
