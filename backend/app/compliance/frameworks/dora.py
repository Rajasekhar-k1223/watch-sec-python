"""
[v2.8.0] EU Digital Operational Resilience Act (DORA) Implementation
Regulation (EU) 2022/2554 for financial entities and ICT third-party service providers.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class DoraFramework(BaseComplianceFramework):
    framework_id = "DORA"
    name = "Digital Operational Resilience Act (DORA)"
    region = "EU"
    jurisdiction = "European Union"
    category = FrameworkCategory.FINANCIAL
    version = "Regulation (EU) 2022/2554"
    source_reference = "Regulation (EU) 2022/2554 on digital operational resilience for the financial sector"

    controls = [
        ComplianceControl(
            control_id="DORA-ART-6-ICT-RISK",
            framework_id="DORA",
            title="Article 6: ICT Risk Management Framework",
            requirement="Financial entities shall maintain a sound, comprehensive and well-documented ICT risk management framework.",
            category="RISK_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="DORA Article 6",
            recommended_action="Ensure continuous vulnerability scanning and asset inventory tracking."
        ),
        ComplianceControl(
            control_id="DORA-ART-17-INCIDENTS",
            framework_id="DORA",
            title="Article 17: ICT-Related Incident Classification & Logging",
            requirement="Entities shall record all ICT-related incidents and significant cyber threats and classify them according to criteria in Article 18.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="DORA Article 17",
            recommended_action="Audit open high-severity security incidents to prevent unmanaged outages."
        ),
        ComplianceControl(
            control_id="DORA-ART-24-TESTING",
            framework_id="DORA",
            title="Article 24: Digital Operational Resilience Testing (TLPT)",
            requirement="Financial entities shall establish and maintain a sound and comprehensive digital operational resilience testing programme.",
            category="SECURITY_TESTING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="DORA Article 24",
            recommended_action="Conduct regular threat-led penetration testing and automated breach validation."
        ),
        ComplianceControl(
            control_id="DORA-ART-28-THIRD-PARTY",
            framework_id="DORA",
            title="Article 28: ICT Third-Party Risk Management",
            requirement="Entities shall manage ICT third-party risk as an integral component of ICT risk within their risk management framework.",
            category="SUPPLY_CHAIN",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="DORA Article 28",
            recommended_action="Verify cryptographic integrity of third-party dependencies and agent binaries."
        )
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ComplianceCheckResult]:
        results = []
        results.append(await self.probe_vulnerability_backlog(tenant_id, db, "DORA-ART-6-ICT-RISK", "DORA Article 6"))
        results.append(await self.probe_incident_response_backlog(tenant_id, db, "DORA-ART-17-INCIDENTS", "DORA Article 17"))
        results.append(await self.probe_audit_logging_active(tenant_id, db, "DORA-ART-24-TESTING", "DORA Article 24"))
        results.append(await self.probe_supply_chain_tampering(tenant_id, db, "DORA-ART-28-THIRD-PARTY", "DORA Article 28"))
        return results
