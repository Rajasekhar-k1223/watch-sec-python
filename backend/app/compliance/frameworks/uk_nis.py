"""
[v2.8.0] UK Network and Information Systems Regulations 2018 Implementation
Covers Operators of Essential Services (OES) and Relevant Digital Service Providers (RDSP) in the UK.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class UkNisFramework(BaseComplianceFramework):
    framework_id = "UK_NIS"
    name = "UK Network and Information Systems Regulations 2018"
    region = "GB"
    jurisdiction = "United Kingdom"
    category = FrameworkCategory.CYBERSECURITY
    version = "S.I. 2018/506 as amended"
    source_reference = "The Network and Information Systems Regulations 2018 (SI 2018 No. 506)"

    controls = [
        ComplianceControl(
            control_id="UK-NIS-REG-10-SECURITY",
            framework_id="UK_NIS",
            title="Regulation 10: Security Duties of Operators of Essential Services",
            requirement="Operators of essential services must take appropriate and proportionate technical and organisational measures to manage risks posed to security of network and information systems.",
            category="SECURITY_MEASURES",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="UK NIS Reg. 10(1)",
            recommended_action="Ensure continuous vulnerability scanning and asset monitoring."
        ),
        ComplianceControl(
            control_id="UK-NIS-REG-11-INCIDENT",
            framework_id="UK_NIS",
            title="Regulation 11: Duty to Notify Incidents (Within 72 Hours)",
            requirement="Notify the designated competent authority about any incident which has a significant impact on the continuity of the essential service without undue delay and at the latest within 72 hours.",
            category="INCIDENT_REPORTING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="UK NIS Reg. 11",
            recommended_action="Maintain zero unresolved critical incident backlog exceeding triage SLA."
        )
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ComplianceCheckResult]:
        results = []
        results.append(await self.probe_vulnerability_backlog(tenant_id, db, "UK-NIS-REG-10-SECURITY", "UK NIS Reg. 10"))
        results.append(await self.probe_incident_response_backlog(tenant_id, db, "UK-NIS-REG-11-INCIDENT", "UK NIS Reg. 11"))
        return results
