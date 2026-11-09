"""
[v2.8.0] EU NIS2 Directive Implementation
Evaluates Network and Information Systems Directive (Directive EU 2022/2555).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class Nis2Framework(BaseComplianceFramework):
    framework_id = "NIS2"
    name = "Network and Information Systems Directive (NIS2)"
    region = "EU"
    jurisdiction = "European Union"
    category = FrameworkCategory.CYBERSECURITY
    version = "Directive (EU) 2022/2555"
    source_reference = "Directive (EU) 2022/2555 of the European Parliament and of the Council on measures for a high common level of cybersecurity across the Union"

    controls = [
        ComplianceControl(
            control_id="NIS2-ART-21-HYGIENE",
            framework_id="NIS2",
            title="Article 21(2)(e): Basic Cyber Hygiene & Vulnerability Management",
            requirement="Essential and important entities shall establish basic cyber hygiene practices and cybersecurity training.",
            category="CYBER_HYGIENE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="NIS2 Article 21(2)(e)",
            recommended_action="Remediate open critical and high vulnerability CVEs on enterprise assets."
        ),
        ComplianceControl(
            control_id="NIS2-ART-21-SUPPLY",
            framework_id="NIS2",
            title="Article 21(2)(d): Supply Chain Security",
            requirement="Entities shall assess and maintain the overall quality and resilience of products and cybersecurity practices of suppliers.",
            category="SUPPLY_CHAIN",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="NIS2 Article 21(2)(d)",
            recommended_action="Ensure SBOM inventory and signature verification for all software components."
        ),
        ComplianceControl(
            control_id="NIS2-ART-23-NOTIFY",
            framework_id="NIS2",
            title="Article 23: Early Warning & Incident Reporting (24h/72h)",
            requirement="Entities shall submit an early warning within 24 hours of becoming aware of a significant incident, followed by an incident notification within 72 hours.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="NIS2 Article 23",
            recommended_action="Maintain zero unresolved critical incident backlog exceeding reporting SLAs."
        ),
        ComplianceControl(
            control_id="NIS2-ART-21-ENCRYPT",
            framework_id="NIS2",
            title="Article 21(2)(h): Cryptography & Encryption Standards",
            requirement="Policies and procedures regarding the use of cryptography and encryption shall be applied across networks.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="NIS2 Article 21(2)(h)",
            recommended_action="Ensure all external communications enforce TLS 1.3/AES-256."
        )
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ComplianceCheckResult]:
        results = []
        results.append(await self.probe_vulnerability_backlog(tenant_id, db, "NIS2-ART-21-HYGIENE", "NIS2 Article 21(2)(e)"))
        results.append(await self.probe_supply_chain_tampering(tenant_id, db, "NIS2-ART-21-SUPPLY", "NIS2 Article 21(2)(d)"))
        results.append(await self.probe_incident_response_backlog(tenant_id, db, "NIS2-ART-23-NOTIFY", "NIS2 Article 23"))
        results.append(await self.probe_audit_logging_active(tenant_id, db, "NIS2-ART-21-ENCRYPT", "NIS2 Article 21(2)(h)"))
        return results
