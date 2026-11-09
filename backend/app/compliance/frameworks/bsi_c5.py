"""
[v2.8.0] BSI C5 (Cloud Computing Compliance Criteria Catalogue) Implementation
German Federal Office for Information Security (BSI) cloud security standard.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class BsiC5Framework(BaseComplianceFramework):
    framework_id = "BSI_C5"
    name = "BSI Cloud Computing Compliance Criteria Catalogue (C5)"
    region = "DE"
    jurisdiction = "Germany"
    category = FrameworkCategory.CYBERSECURITY
    version = "C5:2020"
    source_reference = "Bundesamt für Sicherheit in der Informationstechnik (BSI) C5:2020"

    controls = [
        ComplianceControl(
            control_id="BSI-C5-OIS-01",
            framework_id="BSI_C5",
            title="OIS-01: Organization of Information Security",
            requirement="Security policies and procedures shall be defined, approved by management, and communicated to employees.",
            category="GOVERNANCE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="BSI C5:2020 OIS-01",
            recommended_action="Ensure policy framework adherence and continuous risk tracking."
        ),
        ComplianceControl(
            control_id="BSI-C5-COS-08",
            framework_id="BSI_C5",
            title="COS-08: Cryptographic Safeguards & Key Management",
            requirement="Cryptographic controls and key management procedures must be implemented for sensitive customer data.",
            category="CRYPTOGRAPHY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="BSI C5:2020 COS-08",
            recommended_action="Enforce TLS 1.3/AES-256 for all external and internal communication channels."
        ),
        ComplianceControl(
            control_id="BSI-C5-SIM-01",
            framework_id="BSI_C5",
            title="SIM-01: Security Incident Management & Auditing",
            requirement="Procedures for detecting, logging, analyzing, and handling security incidents must be established.",
            category="INCIDENT_MANAGEMENT",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="BSI C5:2020 SIM-01",
            recommended_action="Maintain zero unresolved critical security incidents beyond standard triage SLAs."
        )
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ComplianceCheckResult]:
        results = []
        results.append(await self.probe_vulnerability_backlog(tenant_id, db, "BSI-C5-OIS-01", "BSI C5:2020 OIS-01"))
        results.append(await self.probe_audit_logging_active(tenant_id, db, "BSI-C5-COS-08", "BSI C5:2020 COS-08"))
        results.append(await self.probe_incident_response_backlog(tenant_id, db, "BSI-C5-SIM-01", "BSI C5:2020 SIM-01"))
        return results
