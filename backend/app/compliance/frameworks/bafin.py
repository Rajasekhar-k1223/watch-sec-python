"""
[v2.8.0] BaFin BAIT (Bankaufsichtliche Anforderungen an die IT) Implementation
German Federal Financial Supervisory Authority IT supervisory requirements.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class BafinBaitFramework(BaseComplianceFramework):
    framework_id = "BAFIN_BAIT"
    name = "BaFin Banking Supervisory Requirements for IT (BAIT)"
    region = "DE"
    jurisdiction = "Germany"
    category = FrameworkCategory.FINANCIAL
    version = "BAIT Circular 10/2017 (BA) as amended"
    source_reference = "Bundesanstalt für Finanzdienstleistungsaufsicht (BaFin) BAIT"

    controls = [
        ComplianceControl(
            control_id="BAIT-SEC-MGMT",
            framework_id="BAFIN_BAIT",
            title="Section 4: Information Security Management",
            requirement="Institutions must establish an information security management system and determine internal security requirements.",
            category="SECURITY_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="BaFin BAIT Section 4",
            recommended_action="Continuously monitor endpoint posture and security configurations."
        ),
        ComplianceControl(
            control_id="BAIT-ACCESS-CONTROL",
            framework_id="BAFIN_BAIT",
            title="Section 5: Identity & Access Management",
            requirement="Access privileges must only be granted in accordance with the need-to-know principle and strictly authenticated.",
            category="ACCESS_CONTROL",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="BaFin BAIT Section 5",
            recommended_action="Audit privileged operations and administrative session records."
        ),
        ComplianceControl(
            control_id="BAIT-OPERATIONS",
            framework_id="BAFIN_BAIT",
            title="Section 6: IT Operations & Logging Integrity",
            requirement="IT systems must ensure reliable transaction processing, data integrity, and complete logging of critical system operations.",
            category="AUDIT_OPERATIONS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="BaFin BAIT Section 6",
            recommended_action="Maintain continuous immutable audit logging."
        )
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ComplianceCheckResult]:
        results = []
        results.append(await self.probe_vulnerability_backlog(tenant_id, db, "BAIT-SEC-MGMT", "BaFin BAIT Section 4"))
        results.append(await self.probe_agent_enrollment_health(tenant_id, db, "BAIT-ACCESS-CONTROL", "BaFin BAIT Section 5"))
        results.append(await self.probe_audit_logging_active(tenant_id, db, "BAIT-OPERATIONS", "BaFin BAIT Section 6"))
        return results
