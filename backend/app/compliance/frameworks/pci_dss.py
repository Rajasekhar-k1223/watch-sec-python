"""
[v2.8.0] PCI DSS v4.0.1 (Payment Card Industry Data Security Standard) Implementation
Evaluates PCI DSS v4.0.1 core requirements: Primary Account Number (PAN) protection, Logging, IR.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class PciDssFramework(BaseComplianceFramework):
    framework_id = "PCI_DSS"
    name = "Payment Card Industry Data Security Standard (PCI DSS)"
    region = "GLOBAL"
    jurisdiction = "Global Payment Card Industry"
    category = FrameworkCategory.FINANCIAL
    version = "PCI DSS v4.0.1 (June 2024)"
    source_reference = "PCI Security Standards Council, PCI DSS v4.0.1"

    controls = [
        ComplianceControl(
            control_id="PCI-REQ-3-4-PAN",
            framework_id="PCI_DSS",
            title="Render PAN Unreadable Anywhere Stored (Req 3.4)",
            requirement="Render Primary Account Number (PAN) unreadable anywhere it is stored using strong cryptography with key management.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="PCI DSS v4.0.1 Requirement 3.4.1 & 3.4.2",
            recommended_action="Remediate any exposed Credit Card PAN numbers in DSPM."
        ),
        ComplianceControl(
            control_id="PCI-REQ-10-2-AUDIT",
            framework_id="PCI_DSS",
            title="Audit Log Generation & User Activity Monitoring (Req 10.2)",
            requirement="Audit logs are generated and capture all individual user access to cardholder data, administrative actions, and invalid access attempts.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PCI DSS v4.0.1 Requirement 10.2.1",
            recommended_action="Ensure administrative and user authentication audit logs are actively recorded."
        ),
        ComplianceControl(
            control_id="PCI-REQ-12-10-IR",
            framework_id="PCI_DSS",
            title="Incident Response Plan & Rapid Breach Containment (Req 12.10)",
            requirement="Suspected and confirmed security incidents are responded to immediately in accordance with documented incident response plan.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="PCI DSS v4.0.1 Requirement 12.10.1 & 12.10.5",
            recommended_action="Triage open critical security incidents."
        ),
        ComplianceControl(
            control_id="PCI-REQ-3-1-RET",
            framework_id="PCI_DSS",
            title="Cardholder Data Retention & Secure Disposal (Req 3.1)",
            requirement="Cardholder data storage is kept to a minimum necessary through documented retention policy and automated quarterly deletion.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="PCI DSS v4.0.1 Requirement 3.1.1",
            recommended_action="Configure 90-day retention pruning for telemetry data."
        ),
        ComplianceControl(
            control_id="PCI-REQ-12-1-POL",
            framework_id="PCI_DSS",
            title="Annual Risk Assessment & Attestation of Compliance (AOC) (Req 12.1)",
            requirement="Maintain overall information security policy and complete annual formal risk assessment and AOC / SAQ.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="PCI DSS v4.0.1 Requirement 12.1 & 12.3",
            recommended_action="Complete annual QSA Report on Compliance (ROC) or Self-Assessment Questionnaire (SAQ-D)."
        )
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ComplianceCheckResult]:
        results = []
        # Control 1: PAN exposure in DSPM
        results.append(await self.probe_dspm_sensitive_exposure(tenant_id, "FINANCIAL", db, "PCI-REQ-3-4-PAN", "PCI DSS v4.0.1 Req 3.4"))
        # Control 2: Audit log generation (Req 10.2)
        results.append(await self.probe_audit_logging_active(tenant_id, db, "PCI-REQ-10-2-AUDIT", "PCI DSS v4.0.1 Req 10.2"))
        # Control 3: Incident response SLA (Req 12.10)
        results.append(await self.probe_incident_response_backlog(tenant_id, db, "PCI-REQ-12-10-IR", "PCI DSS v4.0.1 Req 12.10"))
        # Control 4: Retention probe (Req 3.1)
        results.append(await self.probe_telemetry_retention(tenant_id, 90, db, "PCI-REQ-3-1-RET", "PCI DSS v4.0.1 Req 3.1"))
        # Control 5: Attestation of Compliance (Manual review)
        results.append(self.manual_review_control(
            "PCI-REQ-12-1-POL",
            "Attestation of Compliance (AOC) & SAQ-D",
            "Maintain current signed Attestation of Compliance and annual QSA assessment.",
            "PCI DSS v4.0.1 Req 12.1",
            "Signed PCI DSS v4.0.1 Attestation of Compliance (AOC) by Qualified Security Assessor (QSA)"
        ))
        return results
