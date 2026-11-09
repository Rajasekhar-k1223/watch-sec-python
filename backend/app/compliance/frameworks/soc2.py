"""
[v2.8.0] SOC 2 Type II (AICPA Trust Services Criteria) Implementation
Evaluates AICPA Trust Services Criteria for Security, Availability, and Confidentiality.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class Soc2Framework(BaseComplianceFramework):
    framework_id = "SOC_2"
    name = "SOC 2 Type II (AICPA Trust Services Criteria)"
    region = "GLOBAL"
    jurisdiction = "American Institute of CPAs (AICPA)"
    category = FrameworkCategory.CYBERSECURITY
    version = "AICPA TSP Section 100 (2017 Revised)"
    source_reference = "AICPA Trust Services Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy"

    controls = [
        ComplianceControl(
            control_id="SOC2-CC-7-2-LOG",
            framework_id="SOC_2",
            title="CC7.2 Security Event Monitoring & Audit Logging",
            requirement="The entity monitors system components and the operation of controls to detect anomalies, security events, and unauthorized activity.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="AICPA TSC CC7.2",
            recommended_action="Ensure continuous audit log generation is enabled."
        ),
        ComplianceControl(
            control_id="SOC2-CC-6-1-ENC",
            framework_id="SOC_2",
            title="CC6.1 Logical Access Controls & Cryptographic Data Protection",
            requirement="The entity implements logical access security software, infrastructure, and architectures over protected information assets.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="AICPA TSC CC6.1 & CC6.7",
            recommended_action="Remediate any exposed unencrypted confidential data in DSPM."
        ),
        ComplianceControl(
            control_id="SOC2-CC-7-3-IR",
            framework_id="SOC_2",
            title="CC7.3 Incident Detection, Evaluation, and Remediation",
            requirement="The entity evaluates and responds to identified security incidents and suspected incidents in a timely manner.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="AICPA TSC CC7.3 & CC7.4",
            recommended_action="Triage open critical security incidents."
        ),
        ComplianceControl(
            control_id="SOC2-CC-6-5-DISP",
            framework_id="SOC_2",
            title="CC6.5 Data Disposal & Retention Governance",
            requirement="The entity implements controls to prevent the unauthorized disclosure of data during disposal or destruction.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="AICPA TSC CC6.5",
            recommended_action="Configure 90-day retention pruning for telemetry data."
        ),
        ComplianceControl(
            control_id="SOC2-CC-1-1-GOV",
            framework_id="SOC_2",
            title="CC1.1 Independent Auditor SOC 2 Type II Attestation Report",
            requirement="Obtain an independent CPA examination of design and operating effectiveness of controls over a minimum 6-month period.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="AICPA AT-C Section 205",
            recommended_action="Maintain current annual SOC 2 Type II attestation report from accredited CPA firm."
        )
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ComplianceCheckResult]:
        results = []
        # Control 1: Event logging (CC7.2)
        results.append(await self.probe_audit_logging_active(tenant_id, db, "SOC2-CC-7-2-LOG", "AICPA TSC CC7.2"))
        # Control 2: Data protection in DSPM (CC6.1)
        results.append(await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "SOC2-CC-6-1-ENC", "AICPA TSC CC6.1"))
        # Control 3: Incident remediation (CC7.3)
        results.append(await self.probe_incident_response_backlog(tenant_id, db, "SOC2-CC-7-3-IR", "AICPA TSC CC7.3"))
        # Control 4: Disposal & retention (CC6.5)
        results.append(await self.probe_telemetry_retention(tenant_id, 90, db, "SOC2-CC-6-5-DISP", "AICPA TSC CC6.5"))
        # Control 5: SOC 2 Type II Report (Manual review)
        results.append(self.manual_review_control(
            "SOC2-CC-1-1-GOV",
            "Independent CPA SOC 2 Type II Attestation Report",
            "Maintain current unqualified SOC 2 Type II examination report.",
            "AICPA AT-C Section 205",
            "Annual SOC 2 Type II Service Auditor's Report by Licensed CPA Assessor"
        ))
        return results
