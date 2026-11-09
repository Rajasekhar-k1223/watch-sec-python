"""
[v4.4.0] USA FISMA 2014 & Reusable NIST SP 800-53 Rev. 5 Control Mapping
Maps all 20 NIST SP 800-53 Rev. 5 control families:
AC, AT, AU, CA, CM, CP, IA, IR, MA, MP, PE, PL, PM, PS, PT, RA, SA, SC, SI, SR
Supports Low, Moderate, and High impact baselines (FIPS 199 / FIPS 200).
NOTE: Evaluates technical Monitorix controls only and NEVER claims federal FISMA ATO certification.
"""
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceControl
from ..core.models import FrameworkCategory, CheckType, Severity, ComplianceCheckResult


NIST_800_53_FAMILIES: List[Dict[str, Any]] = [
    {"family": "AC", "name": "Access Control", "control_id": "NIST-AC-2", "monitorix_control": "IAM RBAC & Tenant Isolation", "baselines": ["LOW", "MODERATE", "HIGH"], "automated": True},
    {"family": "AT", "name": "Awareness and Training", "control_id": "NIST-AT-2", "monitorix_control": "Role-Based Security Training Attestation", "baselines": ["LOW", "MODERATE", "HIGH"], "automated": False},
    {"family": "AU", "name": "Audit and Accountability", "control_id": "NIST-AU-2", "monitorix_control": "Tamper-Evident AuditLog Ledger", "baselines": ["LOW", "MODERATE", "HIGH"], "automated": True},
    {"family": "CA", "name": "Assessment, Authorization, and Monitoring", "control_id": "NIST-CA-7", "monitorix_control": "Continuous Endpoint Fleet Monitoring (CA-7; ATO CA-6 requires Manual Authorizing Official sign-off)", "baselines": ["LOW", "MODERATE", "HIGH"], "automated": True},
    {"family": "CM", "name": "Configuration Management", "control_id": "NIST-CM-3", "monitorix_control": "Signed Software Releases & SBOM Inventory", "baselines": ["LOW", "MODERATE", "HIGH"], "automated": True},
    {"family": "CP", "name": "Contingency Planning", "control_id": "NIST-CP-9", "monitorix_control": "Active-Active Mesh Failover & Zero-RPO Replication", "baselines": ["LOW", "MODERATE", "HIGH"], "automated": True},
    {"family": "IA", "name": "Identification and Authentication", "control_id": "NIST-IA-2", "monitorix_control": "JWT / SSO / mTLS Endpoint & User Authentication", "baselines": ["LOW", "MODERATE", "HIGH"], "automated": True},
    {"family": "IR", "name": "Incident Response", "control_id": "NIST-IR-4", "monitorix_control": "SOC Incident Triage & US-CERT Readiness", "baselines": ["LOW", "MODERATE", "HIGH"], "automated": True},
    {"family": "MA", "name": "Maintenance", "control_id": "NIST-MA-2", "monitorix_control": "Controlled Update History & Maintenance Windows", "baselines": ["LOW", "MODERATE", "HIGH"], "automated": True},
    {"family": "MP", "name": "Media Protection", "control_id": "NIST-MP-4", "monitorix_control": "DSPM Storage Encryption & USB/DLP Controls", "baselines": ["LOW", "MODERATE", "HIGH"], "automated": True},
    {"family": "PE", "name": "Physical and Environmental Protection", "control_id": "NIST-PE-3", "monitorix_control": "Datacenter Physical Access Attestation", "baselines": ["LOW", "MODERATE", "HIGH"], "automated": False},
    {"family": "PL", "name": "Planning", "control_id": "NIST-PL-2", "monitorix_control": "System Security Plan (SSP) Documentation", "baselines": ["LOW", "MODERATE", "HIGH"], "automated": False},
    {"family": "PM", "name": "Program Management", "control_id": "NIST-PM-9", "monitorix_control": "Enterprise Risk Management Strategy & ATO Governance", "baselines": ["MODERATE", "HIGH"], "automated": False},
    {"family": "PS", "name": "Personnel Security", "control_id": "NIST-PS-3", "monitorix_control": "Personnel Screening & Clearance Verification", "baselines": ["LOW", "MODERATE", "HIGH"], "automated": False},
    {"family": "PT", "name": "PII Processing and Transparency", "control_id": "NIST-PT-2", "monitorix_control": "PII Discovery, Retention & DSR Privacy Workflows", "baselines": ["LOW", "MODERATE", "HIGH"], "automated": True},
    {"family": "RA", "name": "Risk Assessment", "control_id": "NIST-RA-5", "monitorix_control": "Continuous Vulnerability Scanning & DSPM Risk Scoring", "baselines": ["LOW", "MODERATE", "HIGH"], "automated": True},
    {"family": "SA", "name": "System and Services Acquisition", "control_id": "NIST-SA-10", "monitorix_control": "Developer Configuration Management & Signed Artifacts", "baselines": ["MODERATE", "HIGH"], "automated": True},
    {"family": "SC", "name": "System and Communications Protection", "control_id": "NIST-SC-8", "monitorix_control": "TLS 1.3 Mutual Auth, AES-256-GCM & Boundary Fencing", "baselines": ["LOW", "MODERATE", "HIGH"], "automated": True},
    {"family": "SI", "name": "System and Information Integrity", "control_id": "NIST-SI-2", "monitorix_control": "Flaw Remediation, Malware Sandbox & EDR Telemetry", "baselines": ["LOW", "MODERATE", "HIGH"], "automated": True},
    {"family": "SR", "name": "Supply Chain Risk Management", "control_id": "NIST-SR-3", "monitorix_control": "SBOM Provenance & Ed25519 Supply Chain Verification", "baselines": ["MODERATE", "HIGH"], "automated": True},
]


class FismaFramework(BaseComplianceFramework):
    framework_id = "FISMA"
    name = "FISMA 2014 / NIST SP 800-53 Rev. 5"
    region = "US"
    jurisdiction = "United States Federal"
    category = FrameworkCategory.GOVERNMENT
    version = "44 U.S.C. § 3551 / NIST SP 800-53 Rev. 5"
    effective_from = "2014-12-18"
    last_reviewed_at = "2026-10-01"
    regulatory_authority = "OMB, CISA & NIST"
    breach_notification_window = "1 Hour to CISA US-CERT for Federal Agency Incidents"
    residency_region = "us-east-1"
    source_reference = "44 U.S.C. § 3551 et seq., FIPS 199/200, NIST SP 800-53 Rev. 5"
    supported_privacy_rights = ["ACCESS", "CORRECT"]

    controls = [
        ComplianceControl(
            control_id=fam["control_id"],
            framework_id="FISMA",
            title=f"NIST 800-53 [{fam['family']}] {fam['name']}",
            requirement=f"Implement NIST SP 800-53 Rev. 5 {fam['family']} family controls ({fam['monitorix_control']}).",
            category="SECURITY" if fam["automated"] else "GOVERNANCE",
            check_type=CheckType.AUTOMATED if fam["automated"] else CheckType.MANUAL_REVIEW,
            severity=Severity.HIGH if fam["automated"] else Severity.LOW,
            legal_reference=f"NIST SP 800-53 Rev. 5 Family {fam['family']} ({'/'.join(fam['baselines'])})",
            recommended_action=f"Verify {fam['monitorix_control']} for {fam['family']} baseline.",
            nist_family=fam["family"],
            nist_baseline="MODERATE" if "LOW" not in fam["baselines"] else "LOW",
        )
        for fam in NIST_800_53_FAMILIES
    ]

    async def evaluate(
        self,
        tenant_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ComplianceCheckResult]:
        baseline = (context or {}).get("nist_baseline", "HIGH").upper()
        if baseline not in ("LOW", "MODERATE", "HIGH"):
            baseline = "HIGH"

        results: List[ComplianceCheckResult] = []
        for fam in NIST_800_53_FAMILIES:
            cid = fam["control_id"]
            code = fam["family"]
            ref = f"NIST SP 800-53 Rev. 5 ({code})"

            if baseline not in fam["baselines"]:
                results.append(
                    self._check_context_override(
                        tenant_id, cid, f"NIST [{code}] {fam['name']}", ref, "SECURITY",
                        {"applicable": False, "not_applicable_reason": f"Control not required in NIST {baseline} baseline"},
                    )  # type: ignore
                )
                continue

            if code in ("AC", "IA"):
                r = await self.probe_access_control_rbac_mfa(tenant_id, db, cid, ref)
            elif code == "AU":
                r = await self.probe_audit_logging_active(tenant_id, db, cid, ref)
            elif code == "CA":
                r = await self.probe_agent_enrollment_health(tenant_id, db, cid, ref)
            elif code in ("CM", "MA", "SA", "SR"):
                r = await self.probe_supply_chain_tampering(tenant_id, db, cid, ref)
            elif code == "CP":
                r = await self.probe_backup_and_dr_readiness(tenant_id, db, cid, ref)
            elif code == "IR":
                r = await self.probe_incident_response_backlog(tenant_id, db, cid, ref)
            elif code == "MP":
                r = await self.probe_dspm_sensitive_exposure(tenant_id, "PII", db, cid, ref)
            elif code == "PT":
                r = await self.probe_telemetry_retention(tenant_id, 90, db, cid, ref)
            elif code in ("RA", "SI"):
                r = await self.probe_vulnerability_backlog(tenant_id, db, cid, ref)
            elif code == "SC":
                r = await self.probe_encryption_and_tls(tenant_id, db, cid, ref)
            else:
                r = self.manual_review_control(
                    cid,
                    f"NIST 800-53 [{code}] {fam['name']} & Federal ATO Review",
                    f"Non-technical organizational/physical/ATO control ({fam['monitorix_control']}). Monitorix never claims federal FISMA ATO certification.",
                    ref,
                    f"Signed System Security Plan (SSP), POA&M, and Authorizing Official Attestation for {code}",
                    tenant_id=tenant_id,
                )
            r.check_name = f"NIST 800-53 [{code}] {fam['name']}"
            results.append(r)

        return results

    @classmethod
    def get_nist_mapping_matrix(
        cls, results: Optional[List[ComplianceCheckResult]] = None, baseline: str = "MODERATE"
    ) -> Dict[str, Any]:
        status_by_id = {r.control_id: r for r in (results or [])}
        families = []
        for fam in NIST_800_53_FAMILIES:
            cid = fam["control_id"]
            code = fam["family"]
            res = status_by_id.get(cid)
            min_base = "LOW" if "LOW" in fam["baselines"] else ("MODERATE" if "MODERATE" in fam["baselines"] else "HIGH")
            families.append({
                "family": code,
                "family_code": code,
                "family_name": fam["name"],
                "control_id": cid,
                "monitorix_control": fam["monitorix_control"],
                "monitorix_telemetry_source": fam["monitorix_control"],
                "representative_nist_controls": [f"{code}-1", f"{code}-2", f"{code}-3"],
                "baselines": fam["baselines"],
                "minimum_baseline": min_base,
                "in_selected_baseline": baseline.upper() in fam["baselines"],
                "status": res.status.value if res else ("MANUAL_REVIEW" if not fam["automated"] else "PENDING"),
                "evidence_hash": res.evidence[0].evidence_hash if (res and res.evidence) else None,
            })
        return {
            "framework_id": "FISMA",
            "standard": "NIST SP 800-53 Rev. 5",
            "total_families": len(families),
            "families": families,
        }


async def run_fisma_checks(
    tenant_id: int = 1,
    db: Optional[AsyncSession] = None,
    context: Optional[Dict[str, Any]] = None,
) -> List[ComplianceCheckResult]:
    return await FismaFramework().run_checks(tenant_id=tenant_id, db=db, context=context)
