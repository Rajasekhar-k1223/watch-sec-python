"""
[v2.8.0] CIS Critical Security Controls v8.1 Implementation
Evaluates Center for Internet Security (CIS) Controls v8.1 (IG1, IG2, IG3).
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class CisControlsFramework(BaseComplianceFramework):
    framework_id = "CIS_CONTROLS"
    name = "CIS Critical Security Controls v8.1"
    region = "GLOBAL"
    jurisdiction = "Center for Internet Security (CIS)"
    category = FrameworkCategory.CYBERSECURITY
    version = "CIS Controls v8.1"
    source_reference = "Center for Internet Security, CIS Critical Security Controls Version 8.1"

    controls = [
        ComplianceControl(
            control_id="CIS-8-LOG",
            framework_id="CIS_CONTROLS",
            title="Control 8: Audit Log Management (8.2 / 8.5)",
            requirement="Collect, review, and retain audit logs that could help detect, understand, or recover from an attack.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="CIS Controls v8.1 Control 8",
            recommended_action="Ensure continuous audit log generation is enabled."
        ),
        ComplianceControl(
            control_id="CIS-3-DATA",
            framework_id="CIS_CONTROLS",
            title="Control 3: Data Protection & Sensitive Asset Encryption (3.3 / 3.11)",
            requirement="Configure data access control lists, establish data protection processes, and encrypt sensitive data at rest and in transit.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="CIS Controls v8.1 Control 3.3, 3.11",
            recommended_action="Remediate any exposed sensitive assets in DSPM."
        ),
        ComplianceControl(
            control_id="CIS-17-IR",
            framework_id="CIS_CONTROLS",
            title="Control 17: Incident Response Management (17.3 / 17.5)",
            requirement="Establish and maintain an incident response capability to prepare, detect, analyze, contain, and eradicate threats.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="CIS Controls v8.1 Control 17",
            recommended_action="Triage open critical security incidents."
        ),
        ComplianceControl(
            control_id="CIS-3-RET",
            framework_id="CIS_CONTROLS",
            title="Control 3.1: Establish and Maintain a Data Retention Schedule",
            requirement="Establish and maintain a data retention process that aligns with enterprise sensitivity and legal/regulatory requirements.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="CIS Controls v8.1 Control 3.1",
            recommended_action="Configure 90-day retention pruning for telemetry data."
        ),
        ComplianceControl(
            control_id="CIS-1-INV",
            framework_id="CIS_CONTROLS",
            title="Control 1: Inventory and Control of Enterprise Assets",
            requirement="Actively manage all enterprise assets connected to the infrastructure physically, virtually, remotely, and within cloud environments.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="CIS Controls v8.1 Control 1.1 & 1.2",
            recommended_action="Maintain accurate enterprise asset register and CIS Controls self-assessment score."
        )
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ComplianceCheckResult]:
        results = []
        # Control 1: Audit log collection (Control 8)
        results.append(await self.probe_audit_logging_active(tenant_id, db, "CIS-8-LOG", "CIS Controls v8.1 Control 8"))
        # Control 2: Data protection in DSPM (Control 3)
        results.append(await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "CIS-3-DATA", "CIS Controls v8.1 Control 3"))
        # Control 3: Incident response capability (Control 17)
        results.append(await self.probe_incident_response_backlog(tenant_id, db, "CIS-17-IR", "CIS Controls v8.1 Control 17"))
        # Control 4: Data retention schedule (Control 3.1)
        results.append(await self.probe_telemetry_retention(tenant_id, 90, db, "CIS-3-RET", "CIS Controls v8.1 Control 3.1"))
        # Control 5: Asset Inventory (Manual review)
        results.append(self.manual_review_control(
            "CIS-1-INV",
            "CIS Controls CSAT Assessment & Asset Inventory",
            "Perform periodic CIS CSAT assessment and maintain complete asset inventory.",
            "CIS Controls v8.1 Control 1",
            "CIS CSAT Assessment Report and Enterprise Hardware/Software Asset Register"
        ))
        return results
