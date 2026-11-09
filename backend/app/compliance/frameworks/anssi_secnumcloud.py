"""
[v2.8.0] ANSSI SecNumCloud Implementation
French National Cybersecurity Agency (ANSSI) SecNumCloud qualification repository.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class AnssiSecnumcloudFramework(BaseComplianceFramework):
    framework_id = "ANSSI_SECNUMCLOUD"
    name = "ANSSI SecNumCloud 3.2"
    region = "FR"
    jurisdiction = "France"
    category = FrameworkCategory.GOVERNMENT
    version = "SecNumCloud 3.2 (2022)"
    source_reference = "Agence nationale de la sécurité des systèmes d'information (ANSSI) SecNumCloud"

    controls = [
        ComplianceControl(
            control_id="SNC-SOV-01",
            framework_id="ANSSI_SECNUMCLOUD",
            title="Requirement 19: European Sovereignty & Immunity from Extra-EU Laws",
            requirement="The cloud service provider must guarantee legal immunity against extraterritorial laws outside the European Union.",
            category="SOVEREIGNTY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="ANSSI SecNumCloud 3.2 §19",
            recommended_action="Ensure on-premises air-gapped deployment with zero external SaaS dependencies."
        ),
        ComplianceControl(
            control_id="SNC-IAM-01",
            framework_id="ANSSI_SECNUMCLOUD",
            title="Requirement 08: Identity & Privileged Access Control",
            requirement="Strict multi-factor authentication and role separation must govern all administrative operations.",
            category="ACCESS_CONTROL",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="ANSSI SecNumCloud 3.2 §8",
            recommended_action="Enforce strict role-based access control and enrollment validation."
        ),
        ComplianceControl(
            control_id="SNC-LOG-01",
            framework_id="ANSSI_SECNUMCLOUD",
            title="Requirement 12: Logging, Centralization & Integrity",
            requirement="All access, security events, and administrative interventions must be logged immutably and analyzed.",
            category="LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="ANSSI SecNumCloud 3.2 §12",
            recommended_action="Maintain audit trail logs with cryptographic integrity verification."
        )
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ComplianceCheckResult]:
        results = []
        results.append(await self.probe_audit_logging_active(tenant_id, db, "SNC-SOV-01", "ANSSI SecNumCloud §19"))
        results.append(await self.probe_agent_enrollment_health(tenant_id, db, "SNC-IAM-01", "ANSSI SecNumCloud §8"))
        results.append(await self.probe_audit_logging_active(tenant_id, db, "SNC-LOG-01", "ANSSI SecNumCloud §12"))
        return results
