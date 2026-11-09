"""
[v4.4.0] Global Compliance Core Models & Enums
Defines standardized, legally-safe data contracts for all 32 statutory regulatory
frameworks, supplemental standards, automated checks, cryptographic evidence,
findings, remediation, multi-dimensional scoring, applicability, and DSR workflows.
"""
from enum import Enum
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
import uuid


class ControlStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class CheckType(str, Enum):
    AUTOMATED = "AUTOMATED"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    HYBRID = "HYBRID"


class FrameworkCategory(str, Enum):
    PRIVACY = "PRIVACY"
    HEALTHCARE = "HEALTHCARE"
    FINANCIAL = "FINANCIAL"
    GOVERNMENT = "GOVERNMENT"
    CYBERSECURITY = "CYBERSECURITY"
    DATA_SECURITY = "DATA_SECURITY"


class ApplicabilityStatus(str, Enum):
    APPLICABLE = "APPLICABLE"
    POTENTIALLY_APPLICABLE = "POTENTIALLY_APPLICABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class PostureStatus(str, Enum):
    """
    Legally-safe technical posture classifications.
    Never claims legal certification ("CERTIFIED" / "LEGALLY COMPLIANT").
    """
    EVIDENCE_BACKED_POSTURE = "EVIDENCE_BACKED_POSTURE"
    PARTIAL_TECHNICAL_POSTURE = "PARTIAL_TECHNICAL_POSTURE"
    POTENTIAL_COMPLIANCE_GAP = "POTENTIAL_COMPLIANCE_GAP"
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ComplianceEvidence(BaseModel):
    """Cryptographically hashed evidence of a verified control."""
    evidence_id: str = Field(default_factory=lambda: f"EVD-{uuid.uuid4().hex[:10].upper()}")
    tenant_id: int = 1
    framework: str
    control_id: str
    source: str
    artifact_type: str = "TECHNICAL_TELEMETRY_ATTESTATION"
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    collected_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    evidence_hash: str
    sha256_hash: str = ""
    collector: str = "Monitorix Automated Sensor"
    source_module: str = "Monitorix Compliance Engine"
    summary: str = ""
    details: Dict[str, Any] = Field(default_factory=dict)
    raw_payload_summary: Dict[str, Any] = Field(default_factory=dict)
    retention_days: int = 2555
    status: str = "VERIFIED"

    def model_post_init(self, __context: Any) -> None:
        if not self.sha256_hash:
            self.sha256_hash = self.evidence_hash
        if not self.collected_at:
            self.collected_at = self.timestamp
        if not self.raw_payload_summary:
            self.raw_payload_summary = dict(self.details)
        if not self.summary:
            self.summary = f"Evidence collected from {self.source} for {self.framework}:{self.control_id}"


class ComplianceRemediation(BaseModel):
    """Actionable remediation guidance for a compliance control finding."""
    why_it_matters: str
    recommended_action: str
    automated_fix_command: Optional[str] = None
    manual_action: str
    reference: str
    verification_method: str
    safe_soar_action: Optional[str] = None
    requires_human_approval: bool = True


class ComplianceFinding(BaseModel):
    """Technical control gap or risk indicator identified during assessment."""
    finding_id: str
    id: str = ""
    tenant_id: int = 1
    framework: str
    control_id: str
    title: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    category: str = "SECURITY"
    affected_asset: str
    department: str = "Security Operations"
    affected_data: str
    finding_details: str
    recommendation: str = ""
    remediation_cmd: Optional[str] = None
    evidence_hash: Optional[str] = None
    remediation: Optional[ComplianceRemediation] = None
    status: str = "OPEN"  # OPEN, IN_REMEDIATION, REMEDIATED, RESOLVED, ACCEPTED_RISK
    detected_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = self.finding_id
        if not self.description:
            self.description = self.finding_details
        if self.remediation:
            if not self.recommendation:
                self.recommendation = self.remediation.recommended_action
            if not self.remediation_cmd and self.remediation.automated_fix_command:
                self.remediation_cmd = self.remediation.automated_fix_command


class ComplianceCheckResult(BaseModel):
    """Standardized output from any framework control evaluation."""
    framework: str
    control_id: str
    check_name: str
    category: str = "SECURITY"
    status: ControlStatus
    severity: Severity = Severity.LOW
    score: float = 100.0  # 0.0 to 100.0 for automated applicable controls; 0.0 for MANUAL_REVIEW/NOT_APPLICABLE
    evidence: List[ComplianceEvidence] = Field(default_factory=list)
    finding: Optional[ComplianceFinding] = None
    remediation: Optional[ComplianceRemediation] = None
    legal_reference: str = ""
    last_checked_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class FrameworkScore(BaseModel):
    """Evidence-derived technical control posture summary for an individual framework."""
    id: str = ""
    framework_id: str
    name: str
    region: str
    country: str = ""
    jurisdiction: str
    category: FrameworkCategory
    industry: str = "CROSS_INDUSTRY"
    version: str
    framework_version: str = ""
    effective_from: str = "2018-05-25"
    effective_until: Optional[str] = None
    last_reviewed_at: str = "2026-10-01"
    source_reference: str
    regulatory_authority: str = ""
    implementation_status: str = "IMPLEMENTED"  # IMPLEMENTED, PARTIALLY_IMPLEMENTED, MANUAL_REVIEW, NOT_APPLICABLE
    is_core_32: bool = True
    score: float  # Weighted passed controls / weighted applicable automated controls * 100
    status: str   # Legally-safe PostureStatus string
    assessment_disclaimer: str = (
        "MONITORIX TECHNICAL CONTROL ASSESSMENT — Evidence-based technical posture only; "
        "does not constitute legal advice or regulatory certification."
    )
    total_controls: int
    applicable_controls: int = 0
    passed_controls: int
    failed_controls: int
    partial_controls: int
    manual_review_controls: int
    not_applicable_controls: int
    open_findings_count: int
    category_scores: Dict[str, float] = Field(default_factory=dict)
    supported_privacy_rights: List[str] = Field(default_factory=list)
    last_assessed_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    last_checked: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = self.framework_id
        if not self.framework_version:
            self.framework_version = self.version
        if not self.country:
            self.country = self.region
        if not self.last_checked:
            self.last_checked = self.last_assessed_at
        if self.applicable_controls == 0:
            self.applicable_controls = (
                self.passed_controls + self.partial_controls + self.failed_controls
            )


class GlobalCompliancePosture(BaseModel):
    """Aggregated global compliance posture across all 32 statutory frameworks."""
    tenant_id: int = 1
    assessment_type: str = "MONITORIX_EVIDENCE_BASED_POSTURE"
    legal_disclaimer: str = (
        "Scores reflect technical security and privacy controls verified by Monitorix telemetry. "
        "Non-technical legal, contractual, and statutory obligations require human legal review."
    )
    overall_score: float
    organization_score: float = 0.0
    tenant_score: float = 0.0
    total_frameworks: int = 32
    core_32_frameworks_count: int = 32
    supplemental_frameworks_count: int = 0
    active_frameworks: int
    verified_posture_frameworks: int = 0
    partial_posture_frameworks: int = 0
    gap_identified_frameworks: int = 0
    manual_review_frameworks: int = 0
    not_applicable_frameworks: int = 0
    total_controls_assessed: int
    total_controls_monitored: int = 0
    total_passed_controls: int = 0
    total_partial_controls: int = 0
    total_failed_controls: int = 0
    total_manual_reviews: int = 0
    total_findings: int = 0
    open_findings_count: int
    critical_findings_count: int
    high_findings_count: int
    category_scores: Dict[str, float] = Field(default_factory=dict)
    country_scores: Dict[str, float] = Field(default_factory=dict)
    industry_scores: Dict[str, float] = Field(default_factory=dict)
    asset_scores: Dict[str, float] = Field(default_factory=dict)
    department_scores: Dict[str, float] = Field(default_factory=dict)
    status_breakdown_32: Dict[str, int] = Field(default_factory=dict)
    framework_scores: Dict[str, FrameworkScore] = Field(default_factory=dict)
    frameworks: List[FrameworkScore] = Field(default_factory=list)
    assessed_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

    def model_post_init(self, __context: Any) -> None:
        if not self.organization_score:
            self.organization_score = self.overall_score
        if not self.tenant_score:
            self.tenant_score = self.overall_score
        if not self.total_controls_monitored:
            self.total_controls_monitored = self.total_controls_assessed
        if not self.total_findings:
            self.total_findings = self.open_findings_count
        if not self.frameworks and self.framework_scores:
            self.frameworks = list(self.framework_scores.values())


class TenantProfile(BaseModel):
    """Organizational attributes used by the applicability engine."""
    tenant_id: int = 1
    primary_country: str = "US"
    operating_countries: List[str] = Field(default_factory=lambda: ["US", "EU", "IN", "GB"])
    industry: str = "TECHNOLOGY"  # TECHNOLOGY, HEALTHCARE, FINANCIAL, GOVERNMENT, RETAIL, CRITICAL_INFRASTRUCTURE
    organization_size: str = "ENTERPRISE"  # STARTUP, SMB, MID_MARKET, ENTERPRISE
    employee_count: int = 500
    annual_revenue_usd: float = 50_000_000.0
    processes_personal_data: bool = True
    processes_children_data: bool = False
    processes_financial_data: bool = False
    processes_health_data: bool = False
    critical_infrastructure: bool = False
    cloud_hosted: bool = True
    cross_border_transfers: bool = False
    target_citizen_data: List[str] = Field(default_factory=lambda: ["US", "EU", "IN", "GB"])


class ApplicabilityResult(BaseModel):
    """Assessment of whether a specific regulation applies to the tenant."""
    framework_id: str
    name: str
    region: str
    jurisdiction: str = ""
    status: ApplicabilityStatus
    reasoning: str
    mandatory_controls_count: int
    legal_disclaimer: str = "Applicability indicator for technical scoping; confirm statutory thresholds with legal counsel."


class PrivacyRightType(str, Enum):
    ACCESS = "ACCESS"
    DELETE = "DELETE"
    RECTIFY = "RECTIFY"
    CORRECT = "CORRECT"
    RESTRICT = "RESTRICT"
    OBJECT = "OBJECT"
    PORTABILITY = "PORTABILITY"
    OPT_OUT = "OPT_OUT"
    DO_NOT_SELL_SHARE = "DO_NOT_SELL_SHARE"
    LIMIT_SENSITIVE_DATA = "LIMIT_SENSITIVE_DATA"


class PrivacyRequestStatus(str, Enum):
    SUBMITTED = "SUBMITTED"
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    IN_VERIFICATION = "IN_VERIFICATION"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"


class PrivacyRequest(BaseModel):
    """Data Subject / Principal / Consumer privacy right request workflow."""
    request_id: str = Field(default_factory=lambda: f"REQ-{uuid.uuid4().hex[:8].upper()}")
    id: str = ""
    tenant_id: int = 1
    data_subject_identifier: str
    data_subject_id: str = ""
    subject_identifier_hash: str = ""
    data_subject_type: str = "CONSUMER"  # CONSUMER, EMPLOYEE, PATIENT, DATA_PRINCIPAL
    request_type: PrivacyRightType = PrivacyRightType.ACCESS
    right_type: str = ""
    jurisdiction: str = "EU"
    framework_id: str = "GDPR"
    framework: str = ""
    status: PrivacyRequestStatus = PrivacyRequestStatus.SUBMITTED
    verification_method: str = "CRYPTOGRAPHIC_TOKEN"
    submitted_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    due_date: str = Field(default_factory=lambda: (datetime.utcnow() + timedelta(days=30)).isoformat())
    completed_at: Optional[str] = None
    notes: Optional[str] = None
    audit_trail: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_hash: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = self.request_id
        if not self.data_subject_id:
            self.data_subject_id = self.data_subject_identifier
        if not self.right_type:
            self.right_type = self.request_type.value
        if not self.framework:
            self.framework = self.framework_id


class ScanJobStatus(str, Enum):
    QUEUED = "QUEUED"
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ComplianceScanJob(BaseModel):
    """Asynchronous background compliance scan execution metadata."""
    job_id: str
    tenant_id: int = 1
    framework_id: Optional[str] = None
    framework_ids: List[str] = Field(default_factory=list)
    status: ScanJobStatus = ScanJobStatus.PENDING
    progress_pct: float = 0.0
    triggered_by: str = "system"
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: Optional[str] = None
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None


LEGAL_DISCLAIMER = (
    "Monitorix Compliance Posture reflects automated technical control checks, configuration "
    "states, and collected cryptographic evidence. It assists compliance, security, privacy, "
    "and audit teams and does not constitute legal advice or formal regulatory certification."
)


class RegulatoryMatrixEntry(BaseModel):
    """Machine-readable 32-framework regulatory matrix row."""
    framework_id: str
    name: str
    region: str = ""
    country_region: str = ""
    jurisdiction: str
    category: str
    version: str = ""
    framework_version: str = ""
    effective_from: str
    effective_until: Optional[str] = None
    last_reviewed_at: str
    regulatory_authority: str
    breach_notification_window: str
    residency_region: str
    runner_function: str = ""
    total_controls: int = 0
    automated_controls: int = 0
    manual_review_controls: int = 0
    automated_controls_count: int = 0
    manual_review_controls_count: int = 0
    total_controls_count: int = 0
    pii_classifiers: List[str] = Field(default_factory=list)
    supported_privacy_rights: List[str] = Field(default_factory=list)
    implementation_status: str = "IMPLEMENTED"

    def __init__(self, **data: Any):
        if "region" in data and not data.get("country_region"):
            data["country_region"] = data["region"]
        if "framework_version" in data and not data.get("version"):
            data["version"] = data["framework_version"]
        if "total_controls" in data and not data.get("total_controls_count"):
            data["total_controls_count"] = data["total_controls"]
        if "automated_controls" in data and not data.get("automated_controls_count"):
            data["automated_controls_count"] = data["automated_controls"]
        if "manual_review_controls" in data and not data.get("manual_review_controls_count"):
            data["manual_review_controls_count"] = data["manual_review_controls"]
        super().__init__(**data)
