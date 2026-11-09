"""
[v2.8.0] UK Data Protection Act 2018 Implementation
Evaluates statutory requirements under the Data Protection Act 2018 (c. 12).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class UkDataProtectionFramework(BaseComplianceFramework):
    framework_id = "UK_DPA_2018"
    name = "United Kingdom Data Protection Act 2018"
    region = "GB"
    jurisdiction = "United Kingdom"
    category = FrameworkCategory.PRIVACY
    version = "2018 c. 12"
    source_reference = "Data Protection Act 2018 (United Kingdom Parliament)"

    controls = [
        ComplianceControl(
            control_id="UK-DPA-SEC-66",
            framework_id="UK_DPA_2018",
            title="Section 66: Technical & Organisational Security Measures",
            requirement="Implement appropriate technical and organisational measures to evaluate and ensure the security of processing.",
            category="DATA_SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Data Protection Act 2018 s. 66",
            recommended_action="Ensure continuous vulnerability mitigation and active agent telemetry."
        ),
        ComplianceControl(
            control_id="UK-DPA-SEC-67-NOTIFY",
            framework_id="UK_DPA_2018",
            title="Section 67: Notification of Personal Data Breach to the Commissioner (72 Hours)",
            requirement="In the case of a personal data breach, the controller must notify the Information Commissioner without undue delay and not later than 72 hours.",
            category="BREACH_NOTIFICATION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="Data Protection Act 2018 s. 67",
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
        results.append(await self.probe_vulnerability_backlog(tenant_id, db, "UK-DPA-SEC-66", "DPA 2018 s. 66"))
        results.append(await self.probe_incident_response_backlog(tenant_id, db, "UK-DPA-SEC-67-NOTIFY", "DPA 2018 s. 67"))
        return results
