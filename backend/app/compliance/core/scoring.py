"""
[v4.4.0] Global Compliance Weighted Scoring Engine
Calculates evidence-based, deterministic compliance scores across controls,
categories, countries, industries, assets, departments, tenants, and organizations.

Rules enforced:
- Zero hardcoded/fake scores. Every score derives strictly from evaluated controls.
- Weighted formula:
    Compliance Score = (weighted passed + 0.5 * weighted partial) / weighted applicable * 100
- Controls in MANUAL_REVIEW or NOT_APPLICABLE are excluded from automated pass/fail
  denominator and never inflate scores with fake points.
- Never uses "COMPLIANT" or "CERTIFIED" legal claims; uses legally-safe technical posture statuses.
"""
from typing import List, Dict, Any, Optional
from collections import defaultdict
from datetime import datetime
from .models import (
    ControlStatus,
    PostureStatus,
    FrameworkScore,
    GlobalCompliancePosture,
    ComplianceCheckResult,
    FrameworkCategory,
    Severity,
)

SEVERITY_WEIGHTS: Dict[Severity, float] = {
    Severity.CRITICAL: 4.0,
    Severity.HIGH: 3.0,
    Severity.MEDIUM: 2.0,
    Severity.LOW: 1.0,
    Severity.INFORMATIONAL: 0.5,
}

CATEGORY_TO_INDUSTRY: Dict[FrameworkCategory, str] = {
    FrameworkCategory.PRIVACY: "CROSS_INDUSTRY_PRIVACY",
    FrameworkCategory.HEALTHCARE: "HEALTHCARE_LIFE_SCIENCES",
    FrameworkCategory.FINANCIAL: "BANKING_FINANCIAL_SERVICES",
    FrameworkCategory.GOVERNMENT: "PUBLIC_SECTOR_DEFENSE",
    FrameworkCategory.CYBERSECURITY: "CRITICAL_INFRASTRUCTURE_CYBER",
    FrameworkCategory.DATA_SECURITY: "ENTERPRISE_DATA_GOVERNANCE",
}


def _weight_for_severity(sev: Severity) -> float:
    return SEVERITY_WEIGHTS.get(sev, 2.0)


def calculate_framework_score(
    framework_id: str,
    name: str,
    region: str,
    jurisdiction: str,
    category: FrameworkCategory,
    version: str,
    source_reference: str,
    results: List[ComplianceCheckResult],
    *,
    effective_from: str = "2018-05-25",
    effective_until: Optional[str] = None,
    last_reviewed_at: str = "2026-10-01",
    regulatory_authority: str = "",
    supported_privacy_rights: Optional[List[str]] = None,
    is_core_32: bool = True,
) -> FrameworkScore:
    """
    Computes weighted evidence-backed technical posture score for a single framework:
    Score = (sum(weight * 1.0 for PASS) + sum(weight * 0.5 for PARTIAL))
            / sum(weight for PASS | PARTIAL | FAIL) * 100
    """
    total = len(results)
    passed = 0
    failed = 0
    partial = 0
    manual_review = 0
    not_applicable = 0
    open_findings = 0

    weighted_earned = 0.0
    weighted_applicable = 0.0

    cat_earned: Dict[str, float] = defaultdict(float)
    cat_total: Dict[str, float] = defaultdict(float)

    for res in results:
        if res.finding and res.finding.status in ("OPEN", "IN_REMEDIATION"):
            open_findings += 1

        w = _weight_for_severity(res.severity)
        ctrl_cat = getattr(res, "category", "SECURITY") or "SECURITY"

        if res.status == ControlStatus.PASS:
            passed += 1
            weighted_applicable += w
            weighted_earned += w * 1.0
            cat_total[ctrl_cat] += w
            cat_earned[ctrl_cat] += w * 1.0
        elif res.status == ControlStatus.PARTIAL:
            partial += 1
            weighted_applicable += w
            weighted_earned += w * 0.5
            cat_total[ctrl_cat] += w
            cat_earned[ctrl_cat] += w * 0.5
        elif res.status == ControlStatus.FAIL:
            failed += 1
            weighted_applicable += w
            cat_total[ctrl_cat] += w
        elif res.status == ControlStatus.MANUAL_REVIEW:
            manual_review += 1
        elif res.status == ControlStatus.NOT_APPLICABLE:
            not_applicable += 1

    applicable_count = passed + partial + failed

    if weighted_applicable > 0.0:
        score = round((weighted_earned / weighted_applicable) * 100.0, 1)
    else:
        score = 0.0

    # Determine legally-safe technical posture status
    if total > 0 and not_applicable == total:
        status = PostureStatus.NOT_APPLICABLE.value
        impl_status = "NOT_APPLICABLE"
    elif applicable_count == 0 and manual_review > 0:
        status = PostureStatus.MANUAL_REVIEW_REQUIRED.value
        impl_status = "MANUAL_REVIEW"
    elif score >= 85.0 and failed == 0:
        status = PostureStatus.EVIDENCE_BACKED_POSTURE.value
        impl_status = "IMPLEMENTED"
    elif score >= 60.0:
        status = PostureStatus.PARTIAL_TECHNICAL_POSTURE.value
        impl_status = "IMPLEMENTED"
    else:
        status = PostureStatus.POTENTIAL_COMPLIANCE_GAP.value
        impl_status = "IMPLEMENTED"

    category_scores = {
        c: round((cat_earned[c] / cat_total[c]) * 100.0, 1)
        for c in cat_total
        if cat_total[c] > 0
    }

    now_iso = datetime.utcnow().isoformat()
    return FrameworkScore(
        id=framework_id,
        framework_id=framework_id,
        name=name,
        region=region,
        country=region,
        jurisdiction=jurisdiction,
        category=category,
        industry=CATEGORY_TO_INDUSTRY.get(category, "CROSS_INDUSTRY"),
        version=version,
        framework_version=version,
        effective_from=effective_from,
        effective_until=effective_until,
        last_reviewed_at=last_reviewed_at,
        source_reference=source_reference,
        regulatory_authority=regulatory_authority,
        implementation_status=impl_status,
        is_core_32=is_core_32,
        score=score,
        status=status,
        total_controls=total,
        applicable_controls=applicable_count,
        passed_controls=passed,
        failed_controls=failed,
        partial_controls=partial,
        manual_review_controls=manual_review,
        not_applicable_controls=not_applicable,
        open_findings_count=open_findings,
        category_scores=category_scores,
        supported_privacy_rights=supported_privacy_rights or [],
        last_assessed_at=now_iso,
        last_checked=now_iso,
    )


def calculate_global_posture(
    tenant_id: int,
    framework_scores: Dict[str, FrameworkScore],
    all_results: Optional[Dict[str, List[ComplianceCheckResult]]] = None,
    supplemental_count: int = 0,
) -> GlobalCompliancePosture:
    """
    Aggregates canonical framework scores into multi-dimensional posture metrics:
    - framework score
    - category score
    - organization score
    - tenant score
    - asset score
    - department score
    - country score
    - industry score
    """
    scores_list = list(framework_scores.values())
    active = [
        s for s in scores_list
        if s.status not in (PostureStatus.NOT_APPLICABLE.value, PostureStatus.MANUAL_REVIEW_REQUIRED.value)
        and s.applicable_controls > 0
    ]

    # Weighted global score across active applicable controls
    total_weighted_num = sum(s.score * max(1, s.applicable_controls) for s in active)
    total_weighted_den = sum(max(1, s.applicable_controls) for s in active)
    overall_score = round(total_weighted_num / total_weighted_den, 1) if total_weighted_den > 0 else 0.0

    verified_count = sum(1 for s in scores_list if s.status == PostureStatus.EVIDENCE_BACKED_POSTURE.value)
    partial_count = sum(1 for s in scores_list if s.status == PostureStatus.PARTIAL_TECHNICAL_POSTURE.value)
    gap_count = sum(1 for s in scores_list if s.status == PostureStatus.POTENTIAL_COMPLIANCE_GAP.value)
    manual_count = sum(1 for s in scores_list if s.status == PostureStatus.MANUAL_REVIEW_REQUIRED.value)
    na_count = sum(1 for s in scores_list if s.status == PostureStatus.NOT_APPLICABLE.value)

    total_controls = sum(s.total_controls for s in scores_list)
    total_passed = sum(s.passed_controls for s in scores_list)
    total_partial = sum(s.partial_controls for s in scores_list)
    total_failed = sum(s.failed_controls for s in scores_list)
    total_manual = sum(s.manual_review_controls for s in scores_list)
    total_findings = sum(s.open_findings_count for s in scores_list)

    # Multi-dimensional aggregations
    cat_buckets: Dict[str, List[float]] = defaultdict(list)
    country_buckets: Dict[str, List[float]] = defaultdict(list)
    industry_buckets: Dict[str, List[float]] = defaultdict(list)

    for s in active:
        cat_buckets[s.category.value].append(s.score)
        for sub_cat, sub_score in s.category_scores.items():
            cat_buckets[sub_cat].append(sub_score)
        country_buckets[s.region].append(s.score)
        industry_buckets[s.industry].append(s.score)

    category_scores = {k: round(sum(v) / len(v), 1) for k, v in cat_buckets.items() if v}
    country_scores = {k: round(sum(v) / len(v), 1) for k, v in country_buckets.items() if v}
    industry_scores = {k: round(sum(v) / len(v), 1) for k, v in industry_buckets.items() if v}

    # Asset & department scores derived from actual check results & findings
    asset_buckets: Dict[str, List[float]] = defaultdict(list)
    dept_buckets: Dict[str, List[float]] = defaultdict(list)
    crit_findings = 0
    high_findings = 0

    if all_results:
        for fid, checks in all_results.items():
            for chk in checks:
                if chk.status in (ControlStatus.MANUAL_REVIEW, ControlStatus.NOT_APPLICABLE):
                    continue
                pts = 100.0 if chk.status == ControlStatus.PASS else (50.0 if chk.status == ControlStatus.PARTIAL else 0.0)
                if chk.finding:
                    if chk.finding.severity == Severity.CRITICAL and chk.finding.status == "OPEN":
                        crit_findings += 1
                    elif chk.finding.severity == Severity.HIGH and chk.finding.status == "OPEN":
                        high_findings += 1
                    asset_key = chk.finding.affected_asset or f"Tenant-{tenant_id}-Core"
                    dept_key = chk.finding.department or "Security Operations"
                else:
                    asset_key = f"Tenant-{tenant_id}-VerifiedAssets"
                    dept_key = (
                        "Data Governance & Privacy"
                        if chk.category in ("DATA_PROTECTION", "PRIVACY_RIGHTS", "DATA_RESIDENCY")
                        else "Security Operations"
                    )
                asset_buckets[asset_key].append(pts)
                dept_buckets[dept_key].append(pts)
    else:
        crit_findings = sum(1 for s in active if s.failed_controls >= 2)
        high_findings = sum(1 for s in active if s.failed_controls == 1)

    asset_scores = {k: round(sum(v) / len(v), 1) for k, v in asset_buckets.items() if v}
    department_scores = {k: round(sum(v) / len(v), 1) for k, v in dept_buckets.items() if v}

    core_32_scores = [s for s in scores_list if s.is_core_32]
    status_breakdown_32 = {
        "Implemented": sum(1 for s in core_32_scores if s.implementation_status == "IMPLEMENTED"),
        "Partially Implemented": sum(1 for s in core_32_scores if s.implementation_status == "PARTIALLY_IMPLEMENTED"),
        "Manual Review": sum(1 for s in core_32_scores if s.manual_review_controls > 0),
        "Not Applicable": sum(1 for s in core_32_scores if s.status == PostureStatus.NOT_APPLICABLE.value),
        "Missing": max(0, 32 - len(core_32_scores)),
    }

    return GlobalCompliancePosture(
        tenant_id=tenant_id,
        overall_score=overall_score,
        organization_score=overall_score,
        tenant_score=overall_score,
        total_frameworks=len(framework_scores),
        core_32_frameworks_count=len(core_32_scores),
        supplemental_frameworks_count=supplemental_count,
        active_frameworks=len(active),
        verified_posture_frameworks=verified_count,
        partial_posture_frameworks=partial_count,
        gap_identified_frameworks=gap_count,
        manual_review_frameworks=manual_count,
        not_applicable_frameworks=na_count,
        total_controls_assessed=total_controls,
        total_controls_monitored=total_controls,
        total_passed_controls=total_passed,
        total_partial_controls=total_partial,
        total_failed_controls=total_failed,
        total_manual_reviews=total_manual,
        total_findings=total_findings,
        open_findings_count=total_findings,
        critical_findings_count=crit_findings,
        high_findings_count=high_findings,
        category_scores=category_scores,
        country_scores=country_scores,
        industry_scores=industry_scores,
        asset_scores=asset_scores,
        department_scores=department_scores,
        status_breakdown_32=status_breakdown_32,
        framework_scores=framework_scores,
        frameworks=scores_list,
        assessed_at=datetime.utcnow().isoformat(),
    )
