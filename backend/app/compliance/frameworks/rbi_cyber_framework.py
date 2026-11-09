"""
[v2.8.0] RBI Cyber Security Framework for Banks Implementation
Reserve Bank of India (RBI) Cyber Security Framework (DBS.CO/CSITE/BC.11/33.01.001/2015-16).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class RbiCyberFramework(BaseComplianceFramework):
    framework_id = "RBI_CYBER_SECURITY"
    name = "RBI Cyber Security Framework for Banks"
    region = "IN"
    jurisdiction = "India"
    category = FrameworkCategory.FINANCIAL
    version = "RBI/2015-16/418"
    source_reference = "Reserve Bank of India Cyber Security Framework Circular"

    controls = [
        ComplianceControl(
            control_id="RBI-ANNEX-1-SOC",
            framework_id="RBI_CYBER_SECURITY",
            title="Annex 1: Continuous Security Operations Center (C-SOC)",
            requirement="Banks shall set up a Cyber Security Operation Centre (C-SOC) for continuous surveillance and proactive threat monitoring.",
            category="SOC_OPERATIONS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="RBI Circular Annex 1 Item 1",
            recommended_action="Ensure continuous real-time agent telemetry stream and active alert correlation."
        ),
        ComplianceControl(
            control_id="RBI-ANNEX-1-VULN-PATCH",
            framework_id="RBI_CYBER_SECURITY",
            title="Annex 1: Vulnerability Management & Patch Management",
            requirement="Periodic vulnerability assessments, penetration testing, and timely patching of critical vulnerabilities.",
            category="VULNERABILITY_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="RBI Circular Annex 1 Item 4",
            recommended_action="Remediate all High and Critical CVE vulnerabilities within banking patch SLA."
        ),
        ComplianceControl(
            control_id="RBI-ANNEX-1-INCIDENT-LOG",
            framework_id="RBI_CYBER_SECURITY",
            title="Annex 1: Incident Reporting to RBI (2 to 6 Hours)",
            requirement="Immediate reporting of cyber security incidents to RBI within 2 to 6 hours.",
            category="INCIDENT_REPORTING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="RBI Circular Annex 1 Item 6",
            recommended_action="Resolve or escalate critical banking threat alerts immediately."
        )
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ComplianceCheckResult]:
        results = []
        results.append(await self.probe_agent_enrollment_health(tenant_id, db, "RBI-ANNEX-1-SOC", "RBI Annex 1 Item 1"))
        results.append(await self.probe_vulnerability_backlog(tenant_id, db, "RBI-ANNEX-1-VULN-PATCH", "RBI Annex 1 Item 4"))
        results.append(await self.probe_incident_response_backlog(tenant_id, db, "RBI-ANNEX-1-INCIDENT-LOG", "RBI Annex 1 Item 6"))
        return results
