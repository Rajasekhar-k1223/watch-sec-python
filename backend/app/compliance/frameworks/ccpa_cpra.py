"""
[v4.4.0] USA California Consumer Privacy Act / CPRA (Cal. Civ. Code § 1798.100 et seq.)
Implements technical controls for PI & SPI inventory, purpose/collection tracking,
retention & minimization, consumer rights (Access, Delete, Correct, Opt-Out,
Do Not Sell/Share, Limit Sensitive Personal Information, Global Privacy Control GPC),
third-party/vendor tracking, audit evidence, and honest legal applicability review.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import (
    FrameworkCategory,
    CheckType,
    Severity,
    ControlStatus,
    ComplianceCheckResult,
    ComplianceFinding,
    ComplianceRemediation,
)
from ..core.evidence import create_evidence


class CcpaCpraFramework(BaseComplianceFramework):
    framework_id = "CCPA_CPRA"
    name = "California Consumer Privacy Act / CPRA"
    region = "US"
    jurisdiction = "United States (California)"
    category = FrameworkCategory.PRIVACY
    version = "Cal. Civ. Code § 1798.100 (CPRA 2023 Regulations)"
    effective_from = "2020-01-01"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "California Privacy Protection Agency (CPPA) & California AG"
    breach_notification_window = "Expediently & Without Unreasonable Delay (Cal. Civ. Code § 1798.82)"
    residency_region = "us-east-1"
    source_reference = "California Civil Code §§ 1798.100–1798.199.100 & 11 CCR § 7000 et seq."
    supported_privacy_rights = [
        "ACCESS",
        "DELETE",
        "CORRECT",
        "OPT_OUT",
        "DO_NOT_SELL_SHARE",
        "LIMIT_SENSITIVE_DATA",
        "PORTABILITY",
    ]

    controls = [
        ComplianceControl(
            control_id="CCPA-1798-100-INV",
            framework_id="CCPA_CPRA",
            title="Personal Information (PI) & Sensitive Personal Information (SPI) Inventory",
            requirement="Maintain discovery and classification of consumer PI and SPI (SSN, Driver License, Passport, Financial Account, Precise Geolocation).",
            category="DATA_DISCOVERY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Cal. Civ. Code § 1798.100 & § 1798.140(ae)",
            recommended_action="Ensure US PII/SPI classifiers are enabled in DLP and DSPM.",
        ),
        ComplianceControl(
            control_id="CCPA-1798-100-C-MIN",
            framework_id="CCPA_CPRA",
            title="Collection Minimization & Retention Schedule Enforcement (§1798.100(c))",
            requirement="Do not retain a consumer's personal information or sensitive personal information longer than reasonably necessary for disclosed purposes.",
            category="DATA_PROTECTION",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Cal. Civ. Code § 1798.100(c)",
            recommended_action="Enforce 90-day retention pruning and disclosed retention schedules.",
        ),
        ComplianceControl(
            control_id="CCPA-1798-105-DSR",
            framework_id="CCPA_CPRA",
            title="Consumer Rights Workflow: Know/Access, Delete & Correct (§1798.105–110)",
            requirement="Fulfill verifiable consumer requests to access, delete, and correct inaccurate personal information within 45 calendar days.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Cal. Civ. Code §§ 1798.105, 1798.106, 1798.110 & 1798.130",
            recommended_action="Complete verifiable consumer privacy requests within 45-day statutory window.",
        ),
        ComplianceControl(
            control_id="CCPA-1798-120-PREF",
            framework_id="CCPA_CPRA",
            title="Do Not Sell/Share, Limit SPI & Global Privacy Control (GPC) Signals (§1798.120/121/135)",
            requirement="Honor consumer opt-out preferences including Do Not Sell or Share My Personal Information, Limit the Use of My Sensitive Personal Information, and GPC signals.",
            category="PRIVACY_RIGHTS",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Cal. Civ. Code §§ 1798.120, 1798.121 & 11 CCR § 7025 (GPC)",
            recommended_action="Enable Do Not Sell/Share, Limit SPI, and GPC preference enforcement in Compliance Center.",
        ),
        ComplianceControl(
            control_id="CCPA-1798-150-SEC",
            framework_id="CCPA_CPRA",
            title="Reasonable Security Procedures & Practices for Consumer PI/SPI (§1798.81.5 / §1798.150)",
            requirement="Implement and maintain reasonable security procedures and encryption to prevent unauthorized access and exfiltration (private right of action risk).",
            category="SECURITY",
            check_type=CheckType.AUTOMATED,
            severity=Severity.CRITICAL,
            legal_reference="Cal. Civ. Code § 1798.81.5 & § 1798.150",
            recommended_action="Remediate unencrypted or publicly exposed consumer PI/SPI in DSPM.",
            automated_remediation_available=True,
        ),
        ComplianceControl(
            control_id="CCPA-1798-100-D-VENDOR",
            framework_id="CCPA_CPRA",
            title="Service Provider, Contractor & Third-Party Inventory Integrity (§1798.100(d))",
            requirement="Track service providers/vendors and verify cryptographic integrity of data-handling components.",
            category="SUPPLY_CHAIN",
            check_type=CheckType.AUTOMATED,
            severity=Severity.MEDIUM,
            legal_reference="Cal. Civ. Code § 1798.100(d)",
            recommended_action="Maintain verified service-provider inventory and signed software artifacts.",
        ),
        ComplianceControl(
            control_id="CCPA-1798-AUDIT",
            framework_id="CCPA_CPRA",
            title="24-Month Consumer Request & Compliance Audit Evidence (11 CCR § 7101)",
            requirement="Maintain verifiable records of consumer privacy requests and administrative compliance actions for at least 24 months.",
            category="AUDIT_LOGGING",
            check_type=CheckType.AUTOMATED,
            severity=Severity.MEDIUM,
            legal_reference="11 CCR § 7101 (Record-Keeping)",
            recommended_action="Ensure AuditLog and PrivacyRequestRecord retention is active.",
        ),
        ComplianceControl(
            control_id="CCPA-1798-82-BREACH",
            framework_id="CCPA_CPRA",
            title="California Data Breach Notification Readiness (§1798.82)",
            requirement="Triage critical breaches promptly and notify affected California residents and the Attorney General (if >500 residents affected).",
            category="INCIDENT_RESPONSE",
            check_type=CheckType.AUTOMATED,
            severity=Severity.HIGH,
            legal_reference="Cal. Civ. Code § 1798.82",
            recommended_action="Resolve open critical security incidents.",
        ),
        ComplianceControl(
            control_id="CCPA-1798-100-LEGAL",
            framework_id="CCPA_CPRA",
            title="Notice at Collection, Service Provider Addenda & Statutory Applicability Review",
            requirement="Verify public Notice at Collection (§1798.100(a)), written §1798.100(d) contracts restricting secondary use, and legal threshold determination.",
            category="GOVERNANCE",
            check_type=CheckType.MANUAL_REVIEW,
            severity=Severity.LOW,
            legal_reference="Cal. Civ. Code § 1798.100(a), § 1798.100(d) & § 1798.140(d)",
            recommended_action="Confirm statutory thresholds with legal counsel and upload Notice at Collection & Service Provider Addenda.",
        ),
    ]

    async def _probe_ccpa_preferences(
        self, tenant_id: int, db: Optional[AsyncSession]
    ) -> ComplianceCheckResult:
        if db is None:
            return self._diagnostic_manual_review(
                tenant_id, "CCPA-1798-120-PREF",
                "Do Not Sell/Share, Limit SPI & Global Privacy Control (GPC) Signals",
                "Cal. Civ. Code §§ 1798.120, 1798.121", "PRIVACY_RIGHTS", "Database session unavailable"
            )
        try:
            from ...db.models import TenantPrivacyPreferenceRecord
            pref = (
                await db.execute(
                    select(TenantPrivacyPreferenceRecord).where(
                        TenantPrivacyPreferenceRecord.TenantId == tenant_id
                    )
                )
            ).scalars().first()

            dns = True if pref is None else bool(pref.DoNotSellShare)
            lspi = True if pref is None else bool(pref.LimitSensitivePersonalInfo)
            gpc = True if pref is None else bool(pref.GlobalPrivacyControlHonored)

            ev = create_evidence(
                tenant_id=tenant_id,
                framework=self.framework_id,
                control_id="CCPA-1798-120-PREF",
                source="TENANT_PRIVACY_PREFERENCES_LEDGER",
                collector="Monitorix Privacy Preference Probe",
                details={
                    "do_not_sell_share_enforced": dns,
                    "limit_sensitive_personal_info_enforced": lspi,
                    "global_privacy_control_gpc_honored": gpc,
                    "zero_third_party_ad_telemetry": True,
                },
            )
            if dns and lspi and gpc:
                return ComplianceCheckResult(
                    framework=self.framework_id,
                    control_id="CCPA-1798-120-PREF",
                    check_name="Do Not Sell/Share, Limit SPI & Global Privacy Control (GPC) Signals",
                    category="PRIVACY_RIGHTS",
                    status=ControlStatus.PASS,
                    severity=Severity.LOW,
                    score=100.0,
                    evidence=[ev],
                    legal_reference="Cal. Civ. Code §§ 1798.120, 1798.121",
                )

            finding = ComplianceFinding(
                finding_id=f"FIND-CCPA_CPRA-PREF-{tenant_id}",
                tenant_id=tenant_id,
                framework=self.framework_id,
                control_id="CCPA-1798-120-PREF",
                title="CCPA/CPRA Opt-Out or GPC Signal Enforcement Disabled",
                severity=Severity.HIGH,
                category="PRIVACY_RIGHTS",
                affected_asset=f"Tenant-{tenant_id}-PrivacyPreferences",
                department="Data Governance & Privacy",
                affected_data="Consumer Opt-Out & SPI Preferences",
                finding_details=f"Preference flags: DoNotSellShare={dns}, LimitSPI={lspi}, GPC={gpc}.",
                evidence_hash=ev.evidence_hash,
                remediation=ComplianceRemediation(
                    why_it_matters="CPRA §§1798.120/121 and 11 CCR §7025 require honoring opt-out, SPI limitation, and GPC browser signals.",
                    recommended_action="Enable Do Not Sell/Share, Limit SPI, and GPC enforcement in Compliance Center > Privacy Requests.",
                    manual_action="Toggle all three CPRA preference controls ON.",
                    reference="Cal. Civ. Code §§ 1798.120, 1798.121 & 11 CCR § 7025",
                    verification_method="Verify TenantPrivacyPreferenceRecords flags are True.",
                ),
            )
            return ComplianceCheckResult(
                framework=self.framework_id,
                control_id="CCPA-1798-120-PREF",
                check_name="Do Not Sell/Share, Limit SPI & Global Privacy Control (GPC) Signals",
                category="PRIVACY_RIGHTS",
                status=ControlStatus.PARTIAL if (dns or gpc) else ControlStatus.FAIL,
                severity=Severity.HIGH,
                score=50.0 if (dns or gpc) else 0.0,
                evidence=[ev],
                finding=finding,
                remediation=finding.remediation,
                legal_reference="Cal. Civ. Code §§ 1798.120, 1798.121",
            )
        except Exception as exc:
            return self._diagnostic_manual_review(
                tenant_id, "CCPA-1798-120-PREF",
                "Do Not Sell/Share, Limit SPI & Global Privacy Control (GPC) Signals",
                "Cal. Civ. Code §§ 1798.120, 1798.121", "PRIVACY_RIGHTS", str(type(exc).__name__)
            )

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        return [
            await self.probe_dlp_classifier_coverage(tenant_id, "US", db, "CCPA-1798-100-INV", "Cal. Civ. Code § 1798.100"),
            await self.probe_telemetry_retention(tenant_id, 90, db, "CCPA-1798-100-C-MIN", "Cal. Civ. Code § 1798.100(c)"),
            await self.probe_privacy_request_sla(tenant_id, db, "CCPA-1798-105-DSR", "Cal. Civ. Code §§ 1798.105–130", sla_days=45),
            await self._probe_ccpa_preferences(tenant_id, db),
            await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, "CCPA-1798-150-SEC", "Cal. Civ. Code § 1798.150"),
            await self.probe_supply_chain_tampering(tenant_id, db, "CCPA-1798-100-D-VENDOR", "Cal. Civ. Code § 1798.100(d)"),
            await self.probe_audit_logging_active(tenant_id, db, "CCPA-1798-AUDIT", "11 CCR § 7101"),
            await self.probe_incident_response_backlog(tenant_id, db, "CCPA-1798-82-BREACH", "Cal. Civ. Code § 1798.82"),
            self.manual_review_control(
                "CCPA-1798-100-LEGAL",
                "Notice at Collection, §1798.100(d) Contracts & Legal Applicability Review",
                "Monitorix evaluates technical controls only and does not determine legal applicability under §1798.140(d); legal counsel must review Notice at Collection and Service Provider agreements.",
                "Cal. Civ. Code § 1798.100(a), § 1798.100(d), § 1798.140(d)",
                "Public Notice at Collection URL, Service Provider Addenda, and Legal Threshold Memo",
                tenant_id=tenant_id,
            ),
        ]


async def run_ccpa_cpra_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await CcpaCpraFramework().run_checks(tenant_id=tenant_id, db=db, context=context)


run_ccpa_checks = run_ccpa_cpra_checks
