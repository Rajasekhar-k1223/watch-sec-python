"""
[v2.8.0] ISO/IEC 27001:2022 Implementation
Evaluates ISO/IEC 27001:2022 Information Security Management System (ISMS) Annex A controls.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


class Iso27001Framework(BaseComplianceFramework):
    framework_id = "ISO_27001"
    name = "ISO/IEC 27001:2022 ISMS"
    region = "GLOBAL"
    jurisdiction = "International Organization for Standardization"
    category = FrameworkCategory.CYBERSECURITY
    version = "ISO/IEC 27001:2022"
    source_reference = "International Organization for Standardization, ISO/IEC 27001:2022"

    controls = [
        ComplianceControl(
            control_id="ISO-A-8-15-LOG",
            framework_id="ISO_27001",
            title="Control A.8.15 Logging & User Activity Monitoring",
            requirement="Logs that record activities, exceptions, faults, and other relevant events shall be produced, stored, protected, and analyzed.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="ISO/IEC 27001:2022 Annex A.8.15",
            recommended_action="Ensure continuous audit log generation is enabled."
        ),
        ComplianceControl(
            control_id="ISO-A-8-24-CRYPTO",
            framework_id="ISO_27001",
            title="Control A.8.24 Use of Cryptography & A.8.11 Data Masking",
            requirement="Rules for the effective use of cryptography and data masking shall be defined and implemented to protect sensitive assets.",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="ISO/IEC 27001:2022 Annex A.8.24 & A.8.11",
            recommended_action="Remediate any exposed unencrypted sensitive data in DSPM."
        ),
        ComplianceControl(
            control_id="ISO-A-5-24-INCIDENT",
            framework_id="ISO_27001",
            title="Control A.5.24 Information Security Incident Management",
            requirement="Establish responsibilities and procedures for responding to, reporting, and evaluating security events.",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="ISO/IEC 27001:2022 Annex A.5.24 & A.5.28",
            recommended_action="Triage open critical security incidents."
        ),
        ComplianceControl(
            control_id="ISO-A-8-10-DISPOSAL",
            framework_id="ISO_27001",
            title="Control A.8.10 Information Deletion & Data Retention",
            requirement="Data stored in information systems, devices, or in any other storage media shall be deleted when no longer required.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="ISO/IEC 27001:2022 Annex A.8.10",
            recommended_action="Configure 90-day retention pruning for telemetry data."
        ),
        ComplianceControl(
            control_id="ISO-A-5-1-POLICY",
            framework_id="ISO_27001",
            title="Control A.5.1 Policies for Information Security & ISMS Scope",
            requirement="Information security policy and topic-specific policies shall be defined, approved by management, published, and communicated.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="ISO/IEC 27001:2022 Clause 5.2 & Annex A.5.1",
            recommended_action="Maintain valid ISO/IEC 27001:2022 accredited certificate and Statement of Applicability (SoA)."
        )
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None
    ) -> List[ComplianceCheckResult]:
        results = []
        # Control 1: Logging (A.8.15)
        results.append(await self.probe_audit_logging_active(tenant_id, db, "ISO-A-8-15-LOG", "ISO/IEC 27001:2022 A.8.15"))
        # Control 2: Cryptography & data masking in DSPM (A.8.24)
        results.append(await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "ISO-A-8-24-CRYPTO", "ISO/IEC 27001:2022 A.8.24"))
        # Control 3: Incident response backlog (A.5.24)
        results.append(await self.probe_incident_response_backlog(tenant_id, db, "ISO-A-5-24-INCIDENT", "ISO/IEC 27001:2022 A.5.24"))
        # Control 4: Information deletion (A.8.10)
        results.append(await self.probe_telemetry_retention(tenant_id, 90, db, "ISO-A-8-10-DISPOSAL", "ISO/IEC 27001:2022 A.8.10"))
        # Control 5: ISO 27001 Certificate & SoA (Manual review)
        results.append(self.manual_review_control(
            "ISO-A-5-1-POLICY",
            "ISO 27001:2022 Certificate & Statement of Applicability",
            "Maintain accredited ISO/IEC 27001:2022 certification and approved Statement of Applicability.",
            "ISO/IEC 27001:2022 Clause 5.2",
            "Accredited ISO/IEC 27001:2022 Certificate and current Statement of Applicability (SoA)"
        ))
        return results
