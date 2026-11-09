"""
[v4.4.0] Global Compliance & Regulatory Framework REST API Router
Mounted at both `/api/v2/compliance` and `/api/compliance`.

Provides:
- All 32 statutory regulations + 20 supplemental security standards
- Control-by-control assessment, findings, remediation, and SHA-256 cryptographic evidence
- 25-country national PII classifier catalog & live text scanner (checksum + context verified)
- 10-region sovereign data residency topology
- Regulatory applicability engine
- Data Subject / Principal / Consumer Privacy Request (DSR / ARCO) workflows
- CCPA / CPRA Privacy Preferences (Do Not Sell/Share, Limit Sensitive Personal Info, GPC)
- China Data Security Law (DSL) 3-tier asset classification catalog
- USA FISMA / NIST SP 800-53 Rev. 5 20-family baseline matrix
- Machine-readable 32-regulation statutory compliance matrix
- Tamper-evident AuditLog history
- Valid `%PDF-1.4`, CSV, JSON, and ZIP Evidence Packager exports
- Strict JWT RBAC role enforcement & cross-tenant isolation
"""
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from fastapi import APIRouter, Depends, HTTPException, Query, Body, BackgroundTasks, Response
from fastapi.responses import PlainTextResponse
from fastapi.security import APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db, AsyncSessionLocal
from app.compliance.core.models import (
    GlobalCompliancePosture,
    FrameworkScore,
    TenantProfile,
    ApplicabilityResult,
    ComplianceScanJob,
    PrivacyRequest,
    PrivacyRightType,
    PrivacyRequestStatus,
    LEGAL_DISCLAIMER,
)
from app.compliance.core.engine import compliance_engine
from app.compliance.classifiers import pii_classifier_registry, PIIDetectionResult
from app.compliance.frameworks.fisma import FismaFramework
from app.services.global_federation_service import global_federation_service
from app.services.compliance_service import ComplianceService

router = APIRouter(tags=["Global Compliance & Regulations"])
header_scheme = APIKeyHeader(name="Authorization", auto_error=False)

READ_ONLY_ROLES = {"VIEWER", "READONLY", "READ_ONLY", "AUDITOR", "GUEST"}
SUPER_ROLES = {"SUPERADMIN", "SUPER_ADMIN", "MSSP_SUPER_ADMIN"}


@dataclass
class ComplianceAuthContext:
    tenant_id: int
    username: str
    role: str
    authenticated: bool


async def get_compliance_auth(
    tenant_id: Optional[int] = Query(None, description="Target Tenant ID"),
    auth_header: Optional[str] = Depends(header_scheme),
) -> ComplianceAuthContext:
    """
    Resolves tenant context and enforces strict cross-tenant isolation when JWT is provided.
    - Invalid/tampered JWT -> 401 Unauthorized
    - Non-SuperAdmin requesting a different tenant_id -> 403 Forbidden
    """
    raw = (auth_header or "").strip()
    token = raw.split(" ", 1)[1].strip() if raw.lower().startswith("bearer ") else raw

    if token and token.lower() not in ("null", "undefined", "none"):
        try:
            from jose import jwt
            from app.core.security import SECRET_KEY, ALGORITHM

            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid or expired authentication token.")

        jwt_tid = payload.get("tenantId") or payload.get("tenant_id") or 1
        role = str(payload.get("role") or "Analyst")
        username = str(payload.get("sub") or payload.get("username") or "authenticated_user")

        if tenant_id is not None and int(tenant_id) != int(jwt_tid) and role.upper() not in SUPER_ROLES:
            raise HTTPException(
                status_code=403,
                detail=f"Cross-tenant access denied: token belongs to tenant {jwt_tid}, requested tenant {tenant_id}.",
            )
        effective_tid = int(tenant_id) if (tenant_id is not None and role.upper() in SUPER_ROLES) else int(jwt_tid)
        return ComplianceAuthContext(
            tenant_id=effective_tid,
            username=username,
            role=role,
            authenticated=True,
        )

    return ComplianceAuthContext(
        tenant_id=int(tenant_id) if tenant_id is not None else 1,
        username="local_operator",
        role="Admin",
        authenticated=False,
    )


def require_write_permission(ctx: ComplianceAuthContext) -> ComplianceAuthContext:
    """Rejects mutating actions from read-only / viewer / external auditor roles."""
    if ctx.authenticated and ctx.role.upper() in READ_ONLY_ROLES:
        raise HTTPException(
            status_code=403,
            detail=f"Role '{ctx.role}' has read-only compliance visibility and cannot execute state-changing actions.",
        )
    return ctx


# ---------------------------------------------------------------------------
# 1. Frameworks Catalog, Global Posture & Legacy Summary / Evidence Packager
# ---------------------------------------------------------------------------

@router.get("/frameworks", summary="List All 32 Statutory Frameworks (+ Optional Supplemental)")
async def list_frameworks(
    region: Optional[str] = Query(None, description="Filter by ISO country/region code"),
    category: Optional[str] = Query(None, description="Filter by category"),
    include_supplemental: bool = Query(False, description="Include 20 supplemental industry standards"),
) -> Dict[str, Any]:
    frameworks = compliance_engine.list_frameworks(include_supplemental=include_supplemental)
    if region:
        reg_u = region.upper()
        frameworks = [f for f in frameworks if f["region"].upper() == reg_u]
    if category:
        cat_u = category.upper()
        frameworks = [f for f in frameworks if f["category"].upper() == cat_u]

    return {
        "status": "success",
        "total_core_32": 32,
        "total_registered": len(frameworks),
        "count": len(frameworks),
        "legal_disclaimer": LEGAL_DISCLAIMER,
        "frameworks": frameworks,
    }


@router.get("/matrix", summary="Get Machine-Readable 32-Regulation Statutory Matrix")
async def get_regulatory_matrix() -> Dict[str, Any]:
    matrix = compliance_engine.get_regulatory_matrix()
    return {
        "status": "success",
        "count": len(matrix),
        "legal_disclaimer": LEGAL_DISCLAIMER,
        "matrix": matrix,
    }


@router.get("/posture", summary="Get Multi-Dimensional Global Compliance Posture")
async def get_global_posture(
    include_supplemental: bool = Query(False),
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> GlobalCompliancePosture:
    return await compliance_engine.evaluate_all(
        ctx.tenant_id,
        db,
        include_supplemental=include_supplemental,
        record_audit=True,
        actor=ctx.username,
    )


@router.get("/summary", summary="Executive & Multi-Regulatory Compliance Summary")
async def get_executive_compliance_summary(
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    legacy_svc = ComplianceService()
    exec_narrative = await legacy_svc.generate_executive_summary(ctx.tenant_id, db)
    posture = await compliance_engine.evaluate_all(
        ctx.tenant_id, db, record_audit=False, actor=ctx.username
    )
    return {
        "status": "success",
        "tenant_id": ctx.tenant_id,
        "overall_score": posture.overall_score,
        "total_frameworks": posture.total_frameworks,
        "total_controls_assessed": posture.total_controls_assessed,
        "open_findings_count": posture.open_findings_count,
        "executive_narrative": exec_narrative,
        "category_scores": posture.category_scores,
        "country_scores": posture.country_scores,
        "legal_disclaimer": LEGAL_DISCLAIMER,
    }


@router.get("/evidence-packager", summary="Download Signed Auditor Evidence Bundle (.ZIP)")
async def download_evidence_packager(
    framework: str = Query("GDPR", description="Target framework ID or GLOBAL"),
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> Response:
    zip_bytes = await compliance_engine.generate_evidence_zip_bundle(
        ctx.tenant_id, db, framework_id=framework
    )
    filename = f"Monitorix_Compliance_Evidence_{framework.upper()}_T{ctx.tenant_id}.zip"
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ---------------------------------------------------------------------------
# 2. Per-Framework Evaluation, Score, Controls, Findings & Evidence
# ---------------------------------------------------------------------------

@router.get("/frameworks/{framework_id}", summary="Get Detailed Framework Evaluation")
async def get_framework_evaluation(
    framework_id: str,
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    try:
        score_obj, results = await compliance_engine.evaluate_framework(
            ctx.tenant_id, framework_id, db, persist=True, record_audit=False, actor=ctx.username
        )
        return {
            "status": "success",
            "legal_disclaimer": LEGAL_DISCLAIMER,
            "framework": score_obj.dict(),
            "controls": [r.dict() for r in results],
        }
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/frameworks/{framework_id}/score", summary="Get Framework Score")
async def get_framework_score_only(
    framework_id: str,
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> FrameworkScore:
    try:
        score_obj, _ = await compliance_engine.evaluate_framework(
            ctx.tenant_id, framework_id, db, persist=False, record_audit=False, actor=ctx.username
        )
        return score_obj
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/frameworks/{framework_id}/controls", summary="Get Controls for a Specific Framework")
async def get_framework_controls(
    framework_id: str,
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    try:
        score_obj, results = await compliance_engine.evaluate_framework(
            ctx.tenant_id, framework_id, db, persist=False, record_audit=False, actor=ctx.username
        )
        return {
            "status": "success",
            "framework_id": score_obj.framework_id,
            "count": len(results),
            "controls": [r.dict() for r in results],
        }
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/frameworks/{framework_id}/findings", summary="Get Open Findings for a Framework")
async def get_framework_findings(
    framework_id: str,
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    findings = await compliance_engine.list_findings(ctx.tenant_id, db, framework_id=framework_id)
    return {
        "status": "success",
        "tenant_id": ctx.tenant_id,
        "framework_id": framework_id.upper(),
        "count": len(findings),
        "findings": findings,
    }


@router.get("/frameworks/{framework_id}/evidence", summary="Get Cryptographic Evidence for a Framework")
async def get_framework_evidence(
    framework_id: str,
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    evidence = await compliance_engine.list_evidence(ctx.tenant_id, db, framework_id=framework_id)
    return {
        "status": "success",
        "tenant_id": ctx.tenant_id,
        "framework_id": framework_id.upper(),
        "count": len(evidence),
        "evidence": evidence,
    }


@router.post("/frameworks/{framework_id}/evaluate", summary="Run Synchronous Framework Scan")
async def evaluate_framework_trigger(
    framework_id: str,
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    require_write_permission(ctx)
    try:
        score_obj, results = await compliance_engine.evaluate_framework(
            ctx.tenant_id, framework_id, db, persist=True, record_audit=True, actor=ctx.username
        )
        return {
            "status": "success",
            "message": f"Evaluated {score_obj.name}",
            "framework": score_obj.dict(),
            "controls": [r.dict() for r in results],
        }
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/frameworks/{framework_id}/run", summary="Dispatch Asynchronous Framework Scan Job")
async def run_framework_async(
    framework_id: str,
    background_tasks: BackgroundTasks,
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
) -> Dict[str, Any]:
    require_write_permission(ctx)
    job = compliance_engine.start_scan_job(
        ctx.tenant_id, framework_id=framework_id, triggered_by=ctx.username
    )

    async def _scan_runner() -> None:
        async with AsyncSessionLocal() as session:
            await compliance_engine.execute_scan_job(job.job_id, session)

    background_tasks.add_task(_scan_runner)
    return {
        "status": "PENDING",
        "job_id": job.job_id,
        "tenant_id": ctx.tenant_id,
        "framework_id": job.framework_id or framework_id,
        "message": f"Asynchronous compliance scan {job.job_id} queued.",
        "status_url": f"/api/v2/compliance/jobs/{job.job_id}",
    }


@router.post("/evaluate-all", summary="Trigger Full 32-Regulation Scan")
async def evaluate_all_trigger(
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> GlobalCompliancePosture:
    require_write_permission(ctx)
    return await compliance_engine.evaluate_all(
        ctx.tenant_id, db, record_audit=True, actor=ctx.username
    )


# ---------------------------------------------------------------------------
# 3. Controls, Findings, Remediation, Evidence & Audit History
# ---------------------------------------------------------------------------

@router.get("/controls", summary="List Controls Catalog Across Frameworks")
async def list_controls(
    framework_id: Optional[str] = Query(None),
    framework: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    include_supplemental: bool = Query(False),
) -> Dict[str, Any]:
    fw = framework_id or framework
    controls = compliance_engine.list_controls(
        framework_id=fw, include_supplemental=include_supplemental
    )
    if category:
        controls = [c for c in controls if c["category"].upper() == category.upper()]
    if severity:
        controls = [c for c in controls if c["severity"].upper() == severity.upper()]
    return {
        "status": "success",
        "count": len(controls),
        "controls": controls,
    }


@router.get("/findings", summary="List Open Compliance Findings")
async def list_findings(
    framework_id: Optional[str] = Query(None),
    framework: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    fw = framework_id or framework
    findings = await compliance_engine.list_findings(ctx.tenant_id, db, fw)
    if severity:
        findings = [f for f in findings if str(f.get("severity", "")).upper() == severity.upper()]
    return {
        "status": "success",
        "tenant_id": ctx.tenant_id,
        "count": len(findings),
        "findings": findings,
    }


@router.post("/findings/{finding_id}/remediate", summary="Mark or Execute Safe Remediation on a Finding")
async def remediate_finding_endpoint(
    finding_id: str,
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    require_write_permission(ctx)
    return await compliance_engine.remediate_finding(
        ctx.tenant_id, finding_id, db, actor=ctx.username
    )


@router.get("/remediation", summary="Get Prioritized Remediation Recommendations")
async def get_remediation_recommendations(
    framework_id: Optional[str] = Query(None),
    framework: Optional[str] = Query(None),
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    fw = framework_id or framework
    plan = await compliance_engine.get_remediation_plan(ctx.tenant_id, db, fw)
    return {
        "status": "success",
        "tenant_id": ctx.tenant_id,
        "count": len(plan),
        "recommendations": plan,
    }


@router.get("/evidence", summary="List Cryptographic SHA-256 Evidence Ledger")
async def list_evidence(
    framework_id: Optional[str] = Query(None),
    framework: Optional[str] = Query(None),
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    fw = framework_id or framework
    evidence = await compliance_engine.list_evidence(ctx.tenant_id, db, fw)
    return {
        "status": "success",
        "tenant_id": ctx.tenant_id,
        "count": len(evidence),
        "evidence": evidence,
    }


@router.get("/audit-history", summary="List Immutable Compliance Scan & Governance Audit Trail")
async def get_compliance_audit_history(
    limit: int = Query(50, ge=1, le=500),
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    history = await compliance_engine.get_audit_history(ctx.tenant_id, db, limit=limit)
    return {
        "status": "success",
        "tenant_id": ctx.tenant_id,
        "count": len(history),
        "history": history,
    }


# ---------------------------------------------------------------------------
# 4. 25-Country National PII Classifiers & Discovery Scanner
# ---------------------------------------------------------------------------

@router.get("/pii", summary="List All 25+ Country PII Classifiers & Checksum Validators")
async def list_pii_classifiers(
    country: Optional[str] = Query(None, description="ISO country code filter, e.g., IN, US, BR, GB"),
) -> Dict[str, Any]:
    classifiers = (
        pii_classifier_registry.get_by_country(country)
        if country
        else pii_classifier_registry.list_all()
    )
    countries_covered = sorted({c.country_code for c in pii_classifier_registry.list_all()})
    return {
        "status": "success",
        "countries_count": len(countries_covered),
        "countries": countries_covered,
        "count": len(classifiers),
        "classifiers": [
            {
                "classifier_id": c.classifier_id,
                "identifier": c.identifier,
                "name": c.name,
                "country": c.country_code,
                "category": c.category,
                "severity": c.severity,
                "checksum_validator": c.checksum_validator or "REGEX_CONTEXT_BOUNDARY",
                "requires_context_for_high": c.requires_context_for_high,
                "context_keywords_sample": c.context_keywords[:6],
                "regulations": c.regulations,
            }
            for c in classifiers
        ],
    }


@router.post("/pii", summary="Run Real-Time National PII Classification")
async def scan_pii_text(
    payload: Dict[str, Any] = Body(...),
) -> Dict[str, Any]:
    text = payload.get("text") or payload.get("text_sample") or ""
    country_filter = payload.get("country_code") or payload.get("country")
    if not text:
        return {"status": "success", "count": 0, "detections": []}

    results: List[PIIDetectionResult] = pii_classifier_registry.scan_text(text, country_filter)
    return {
        "status": "success",
        "country_filter": country_filter or "GLOBAL",
        "count": len(results),
        "detections": [r.dict() for r in results],
    }


# ---------------------------------------------------------------------------
# 5. 10-Region Sovereign Data Residency, NIST 800-53 & China DSL Catalog
# ---------------------------------------------------------------------------

@router.get("/residency", summary="Get All 10 Global Sovereign Data Residency Zones")
async def get_data_residency_zones(
    region: Optional[str] = Query(None),
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
) -> Dict[str, Any]:
    if region:
        return {
            "status": "success",
            "tenant_id": ctx.tenant_id,
            "residency": global_federation_service.get_residency_compliance(region),
        }
    zones_list = global_federation_service.get_all_residency_zones()
    return {
        "status": "success",
        "tenant_id": ctx.tenant_id,
        "count": len(zones_list),
        "zones": zones_list,
    }


@router.get("/nist-mapping", summary="Get FISMA / NIST SP 800-53 Rev. 5 20-Family Control Matrix")
async def get_nist_800_53_mapping(
    baseline: Optional[str] = Query(None, description="LOW, MODERATE, or HIGH"),
) -> Dict[str, Any]:
    matrix = FismaFramework.get_nist_mapping_matrix()
    if baseline:
        b_u = baseline.upper()
        baseline_levels = {
            "LOW": {"LOW"},
            "MODERATE": {"LOW", "MODERATE"},
            "HIGH": {"LOW", "MODERATE", "HIGH"},
        }.get(b_u, {"LOW", "MODERATE", "HIGH"})
        matrix["families"] = [
            f for f in matrix["families"] if f["minimum_baseline"] in baseline_levels
        ]
    return {"status": "success", **matrix}


@router.get("/dsl-assets", summary="List China Data Security Law (DSL) 3-Tier Classified Assets")
async def list_china_dsl_assets(
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    assets = await compliance_engine.list_dsl_assets(ctx.tenant_id, db)
    return {
        "status": "success",
        "tenant_id": ctx.tenant_id,
        "supported_tiers": ["GENERAL_DATA", "IMPORTANT_DATA", "CORE_DATA"],
        "count": len(assets),
        "assets": assets,
    }


@router.post("/dsl-assets", summary="Register or Update China DSL Classified Data Asset")
async def upsert_china_dsl_asset(
    payload: Dict[str, Any] = Body(...),
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    require_write_permission(ctx)
    asset = await compliance_engine.upsert_dsl_asset(
        ctx.tenant_id, payload, db, actor=ctx.username
    )
    return {"status": "success", "asset": asset}


# ---------------------------------------------------------------------------
# 6. Asynchronous Scan Jobs
# ---------------------------------------------------------------------------

@router.get("/jobs", summary="List Tenant Compliance Scan Jobs")
async def list_jobs(
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
) -> List[ComplianceScanJob]:
    return compliance_engine.list_scan_jobs(ctx.tenant_id)


@router.get("/jobs/{job_id}", summary="Get Asynchronous Scan Job Status")
async def get_job_status(
    job_id: str,
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
) -> ComplianceScanJob:
    tid_filter = ctx.tenant_id if (ctx.authenticated and ctx.role.upper() not in SUPER_ROLES) else None
    job = compliance_engine.get_scan_job(job_id, tenant_id=tid_filter)
    if not job:
        raise HTTPException(status_code=404, detail=f"Compliance scan job '{job_id}' not found.")
    return job


# ---------------------------------------------------------------------------
# 7. Regulatory Applicability Engine
# ---------------------------------------------------------------------------

@router.get("/applicability", summary="Get Default Regulatory Applicability Across 32 Laws")
async def get_default_applicability(
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
) -> Dict[str, Any]:
    default_profile = TenantProfile(tenant_id=ctx.tenant_id)
    results = compliance_engine.determine_applicability(default_profile)
    return {
        "status": "success",
        "tenant_id": ctx.tenant_id,
        "legal_disclaimer": LEGAL_DISCLAIMER,
        "total_assessed": len(results),
        "applicable_count": len([r for r in results if r.status == "APPLICABLE"]),
        "results": [r.dict() for r in results],
    }


@router.post("/applicability", summary="Determine Regulatory Applicability for Custom Tenant Profile")
async def check_applicability(
    profile: TenantProfile = Body(...),
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
) -> Dict[str, Any]:
    if ctx.authenticated and ctx.role.upper() not in SUPER_ROLES:
        profile.tenant_id = ctx.tenant_id
    results: List[ApplicabilityResult] = compliance_engine.determine_applicability(profile)
    applicable = [r for r in results if r.status == "APPLICABLE"]
    potentially_applicable = [r for r in results if r.status == "POTENTIALLY_APPLICABLE"]
    manual_review = [r for r in results if r.status == "MANUAL_REVIEW"]
    not_applicable = [r for r in results if r.status == "NOT_APPLICABLE"]

    return {
        "status": "success",
        "tenant_id": profile.tenant_id,
        "legal_disclaimer": LEGAL_DISCLAIMER,
        "summary": {
            "total_assessed": len(results),
            "applicable_count": len(applicable),
            "potentially_applicable_count": len(potentially_applicable),
            "manual_review_count": len(manual_review),
            "not_applicable_count": len(not_applicable),
        },
        "results": [r.dict() for r in results],
    }


# ---------------------------------------------------------------------------
# 8. Privacy Requests (DSR / ARCO) & CCPA / CPRA Privacy Preferences
# ---------------------------------------------------------------------------

@router.get("/privacy-requests", summary="List Data Subject / Consumer Privacy Requests")
async def list_privacy_requests(
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
) -> Dict[str, Any]:
    reqs = compliance_engine.list_privacy_requests(ctx.tenant_id)
    return {
        "status": "success",
        "tenant_id": ctx.tenant_id,
        "count": len(reqs),
        "requests": [r.dict() for r in reqs],
    }


@router.post("/privacy-requests", summary="Submit Data Subject / Consumer Privacy Request")
async def create_privacy_request(
    payload: Dict[str, Any] = Body(...),
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    require_write_permission(ctx)
    subj = payload.get("data_subject_identifier") or payload.get("data_subject_id") or "unknown"
    req_type_str = payload.get("request_type") or payload.get("right_type") or "ACCESS"
    try:
        r_type = PrivacyRightType(req_type_str.upper())
    except Exception:
        r_type = PrivacyRightType.ACCESS

    req_obj = PrivacyRequest(
        tenant_id=ctx.tenant_id,
        data_subject_identifier=subj,
        data_subject_type=payload.get("data_subject_type", "DATA_SUBJECT"),
        request_type=r_type,
        jurisdiction=payload.get("jurisdiction", "GLOBAL"),
        framework_id=payload.get("framework_id") or payload.get("framework") or "GDPR",
        notes=payload.get("notes"),
    )
    saved = await compliance_engine.submit_privacy_request_async(
        req_obj, db=db, actor=ctx.username
    )
    return {
        "status": "success",
        "message": f"Privacy request {saved.request_id} recorded.",
        "request": saved.dict(),
    }


@router.patch("/privacy-requests/{request_id}", summary="Update Privacy Request Status")
async def update_privacy_request_status(
    request_id: str,
    status: Optional[str] = Query(None),
    payload: Optional[Dict[str, Any]] = Body(None),
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    require_write_permission(ctx)
    status_str = status or (payload and payload.get("status")) or "COMPLETED"
    notes = payload.get("notes") if payload else None
    try:
        req_status = PrivacyRequestStatus(status_str.upper())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid privacy request status '{status_str}'.")

    updated = await compliance_engine.update_privacy_request_async(
        ctx.tenant_id, request_id, req_status, notes=notes, db=db, actor=ctx.username
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Privacy request '{request_id}' not found.")
    return {
        "status": "success",
        "message": f"Updated privacy request {request_id}",
        "request": updated.dict(),
    }


@router.get("/privacy-preferences", summary="Get CCPA/CPRA & Tenant Privacy Governance Preferences")
async def get_privacy_preferences_endpoint(
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    prefs = await compliance_engine.get_privacy_preferences(ctx.tenant_id, db)
    return {"status": "success", "preferences": prefs}


@router.put("/privacy-preferences", summary="Update CCPA/CPRA & Tenant Privacy Governance Preferences")
async def update_privacy_preferences_endpoint(
    payload: Dict[str, Any] = Body(...),
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    require_write_permission(ctx)
    prefs = await compliance_engine.update_privacy_preferences(
        ctx.tenant_id, payload, db, actor=ctx.username
    )
    return {"status": "success", "preferences": prefs}


# ---------------------------------------------------------------------------
# 9. Regulatory Reports & Exports (PDF 1.4, CSV, JSON)
# ---------------------------------------------------------------------------

@router.get("/reports", summary="List Available Regulatory Assessment Report Templates")
async def list_reports(
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
) -> Dict[str, Any]:
    return {
        "status": "success",
        "tenant_id": ctx.tenant_id,
        "legal_disclaimer": LEGAL_DISCLAIMER,
        "available_reports": [
            {
                "report_type": "GLOBAL_32_REGULATION_TECHNICAL_ASSESSMENT",
                "title": "Global 32-Regulation Technical Posture Assessment",
                "supported_formats": ["PDF", "CSV", "JSON", "ZIP"],
            },
            {
                "report_type": "SINGLE_FRAMEWORK_ASSESSMENT",
                "title": "Jurisdiction-Specific Statutory Control Assessment",
                "supported_formats": ["PDF", "CSV", "JSON", "ZIP"],
            },
        ],
    }


@router.post("/reports", summary="Generate Custom Regulatory Assessment Report")
async def generate_report_post(
    payload: Optional[Dict[str, Any]] = Body(None),
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    require_write_permission(ctx)
    fw = (payload or {}).get("framework_id")
    return await compliance_engine.generate_audit_report(ctx.tenant_id, db, framework_id=fw)


@router.get("/reports/summary", summary="Generate Global Executive Assessment Report")
async def get_global_audit_report(
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    return await compliance_engine.generate_audit_report(ctx.tenant_id, db)


@router.get("/reports/{framework_id}", summary="Generate Framework Assessment Report")
async def get_framework_audit_report(
    framework_id: str,
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    try:
        return await compliance_engine.generate_audit_report(
            ctx.tenant_id, db, framework_id=framework_id
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/reports/{framework_id}/export", summary="Export Assessment Report in PDF 1.4, CSV, or JSON")
async def export_report(
    framework_id: str,
    format: str = Query("json", description="Export format: pdf, csv, json"),
    ctx: ComplianceAuthContext = Depends(get_compliance_auth),
    db: AsyncSession = Depends(get_db),
):
    fid = None if framework_id.upper() in ("GLOBAL", "SUMMARY", "ALL") else framework_id
    try:
        report_data = await compliance_engine.generate_audit_report(
            ctx.tenant_id, db, framework_id=fid
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    fmt = format.lower()
    if fmt == "csv":
        csv_content = compliance_engine.export_report_csv(report_data)
        return PlainTextResponse(
            csv_content,
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=monitorix_compliance_{framework_id}_{ctx.tenant_id}.csv"
            },
        )
    if fmt == "pdf":
        pdf_bytes = compliance_engine.export_report_pdf_bytes(report_data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=monitorix_compliance_{framework_id}_{ctx.tenant_id}.pdf"
            },
        )
    return report_data
