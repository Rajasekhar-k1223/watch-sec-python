"""
[v2.8.0] EU Cyber Resilience Act (CRA) Implementation
Regulation (EU) on horizontal cybersecurity requirements for products with digital elements.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class CraFramework(BaseComplianceFramework):
    framework_id = "CRA"
    name = "Cyber Resilience Act (CRA)"
    region = "EU"
    jurisdiction = "European Union"
    category = FrameworkCategory.CYBERSECURITY
    version = "Regulation (EU) 2024/2847"
    source_reference = "EU Regulation on horizontal cybersecurity requirements for products with digital elements (CRA)"

    controls = [
        ComplianceControl(
            control_id="CRA-ANNEX-I-SEC-BY-DESIGN",
            framework_id="CRA",
            title="Annex I Part I: Security by Design & Vulnerability Handling",
            requirement="Products with digital elements shall be designed, developed and produced in such a way that they ensure an appropriate level of cybersecurity.",
            category="SECURITY_BY_DESIGN",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="CRA Annex I Part I(1)",
            recommended_action="Ensure continuous vulnerability mitigation and automated patching."
        ),
        ComplianceControl(
            control_id="CRA-ANNEX-I-SBOM",
            framework_id="CRA",
            title="Annex I Part II: Software Bill of Materials (SBOM)",
            requirement="Manufacturers shall identify and document components and vulnerabilities, including drawing up a software bill of materials in a commonly used machine-readable format.",
            category="SUPPLY_CHAIN",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="CRA Annex I Part II(1)",
            recommended_action="Generate machine-readable CycloneDX SBOM for all released packages."
        ),
        ComplianceControl(
            control_id="CRA-ART-14-DISCLOSURE",
            framework_id="CRA",
            title="Article 14: Reporting of Actively Exploited Vulnerabilities",
            requirement="Manufacturers shall notify CSIRTs and ENISA within 24 hours of becoming aware of an actively exploited vulnerability.",
            category="VULNERABILITY_DISCLOSURE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="CRA Article 14",
            recommended_action="Resolve active exploit CVEs immediately."
        )
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ComplianceCheckResult]:
        results = []
        results.append(await self.probe_vulnerability_backlog(tenant_id, db, "CRA-ANNEX-I-SEC-BY-DESIGN", "CRA Annex I Part I(1)"))
        results.append(await self.probe_supply_chain_tampering(tenant_id, db, "CRA-ANNEX-I-SBOM", "CRA Annex I Part II(1)"))
        results.append(await self.probe_incident_response_backlog(tenant_id, db, "CRA-ART-14-DISCLOSURE", "CRA Article 14"))
        return results
