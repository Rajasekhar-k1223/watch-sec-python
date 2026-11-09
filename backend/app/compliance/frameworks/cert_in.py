"""
[v2.8.0] India CERT-In Cyber Security Directions 2022 Implementation
Evaluates directions under sub-section (6) of section 70B of the Information Technology Act, 2000.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class CertInFramework(BaseComplianceFramework):
    framework_id = "CERT_IN"
    name = "India CERT-In Cyber Security Directions 2022"
    region = "IN"
    jurisdiction = "India"
    category = FrameworkCategory.CYBERSECURITY
    version = "No. 20(3)/2022-CERT-In"
    source_reference = "Indian Computer Emergency Response Team (CERT-In) Cyber Security Directions under Section 70B(6) IT Act 2000"

    controls = [
        ComplianceControl(
            control_id="CERT-IN-6HR-MANDATORY-REPORT",
            framework_id="CERT_IN",
            title="Direction (i): Mandatory 6-Hour Cyber Incident Reporting",
            requirement="Any service provider, intermediary, data centre, body corporate and Government organisation shall report cyber incidents to CERT-In within 6 hours of noticing them.",
            category="INCIDENT_REPORTING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="CERT-In Direction 20(3)/2022-CERT-In Annexure I",
            recommended_action="Ensure 0 unresolved critical security incident backlog exceeding 6-hour triage."
        ),
        ComplianceControl(
            control_id="CERT-IN-NTP-SYNC",
            framework_id="CERT_IN",
            title="Direction (ii): Mandatory NTP Synchronization with NPL/NIC",
            requirement="All service providers and entities shall connect to the Network Time Protocol (NTP) Server of National Physical Laboratory (NPL) or NIC to synchronize system clocks.",
            category="SYSTEM_CLOCK",
            check_type=CheckType.AUTOMATED,
            severity=Severity.MEDIUM,
            legal_reference="CERT-In Direction 20(3)/2022-CERT-In §(ii)",
            recommended_action="Verify NTP synchronization status across all telemetry collectors."
        ),
        ComplianceControl(
            control_id="CERT-IN-LOG-RETENTION-180D",
            framework_id="CERT_IN",
            title="Direction (v): Mandatory 180-Day System & Access Log Retention",
            requirement="All organisations shall mandatorily enable logs of all their ICT systems and maintain them securely for a rolling period of 180 days within the Indian jurisdiction.",
            category="LOG_RETENTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="CERT-In Direction 20(3)/2022-CERT-In §(v)",
            recommended_action="Configure database and event streaming retention to minimum 180 days with tamper verification."
        )
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ComplianceCheckResult]:
        results = []
        results.append(await self.probe_incident_response_backlog(tenant_id, db, "CERT-IN-6HR-MANDATORY-REPORT", "CERT-In 6-Hour Rule"))
        results.append(await self.probe_agent_enrollment_health(tenant_id, db, "CERT-IN-NTP-SYNC", "CERT-In NTP Directives"))
        results.append(await self.probe_audit_logging_active(tenant_id, db, "CERT-IN-LOG-RETENTION-180D", "CERT-In 180-Day Log Rule"))
        return results
