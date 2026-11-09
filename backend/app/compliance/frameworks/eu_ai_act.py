"""
[v2.8.0] EU Artificial Intelligence Act (AI Act) Implementation
Regulation (EU) 2024/1689 laying down harmonised rules on artificial intelligence.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class EuAiActFramework(BaseComplianceFramework):
    framework_id = "EU_AI_ACT"
    name = "European Union Artificial Intelligence Act"
    region = "EU"
    jurisdiction = "European Union"
    category = FrameworkCategory.CYBERSECURITY
    version = "Regulation (EU) 2024/1689"
    source_reference = "Regulation (EU) 2024/1689 of the European Parliament and of the Council on Artificial Intelligence"

    controls = [
        ComplianceControl(
            control_id="AIA-ART-9-RISK-MGMT",
            framework_id="EU_AI_ACT",
            title="Article 9: Risk Management System for High-Risk AI",
            requirement="A risk management system shall be established, implemented, documented and maintained in relation to high-risk AI systems.",
            category="AI_GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="EU AI Act Article 9",
            recommended_action="Continuously evaluate security threats and adversarial ML robustness."
        ),
        ComplianceControl(
            control_id="AIA-ART-12-LOGGING",
            framework_id="EU_AI_ACT",
            title="Article 12: Record-Keeping & Automated Logging",
            requirement="High-risk AI systems shall technically allow for the automatic recording of events ('logs') over the duration of the lifecycle of the system.",
            category="LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="EU AI Act Article 12",
            recommended_action="Ensure immutable audit logging for all automated security and AI decisions."
        ),
        ComplianceControl(
            control_id="AIA-ART-15-CYBERSECURITY",
            framework_id="EU_AI_ACT",
            title="Article 15: Accuracy, Robustness and Cybersecurity",
            requirement="High-risk AI systems shall be resilient against attempts by unauthorized third parties to alter their use, behavior or performance by exploiting system vulnerabilities.",
            category="CYBERSECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="EU AI Act Article 15",
            recommended_action="Mitigate high-severity vulnerabilities in AI pipelines and model inference runtime."
        )
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ComplianceCheckResult]:
        results = []
        results.append(await self.probe_vulnerability_backlog(tenant_id, db, "AIA-ART-9-RISK-MGMT", "EU AI Act Article 9"))
        results.append(await self.probe_audit_logging_active(tenant_id, db, "AIA-ART-12-LOGGING", "EU AI Act Article 12"))
        results.append(await self.probe_supply_chain_tampering(tenant_id, db, "AIA-ART-15-CYBERSECURITY", "EU AI Act Article 15"))
        return results
