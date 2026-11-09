"""
[v4.4.0] PII Classifier Base Data Definition Models
"""
from typing import Any, List, Optional
from pydantic import BaseModel


class PIIClassifierDefinition(BaseModel):
    identifier: str
    country_code: str
    country_name: str
    category: str  # NATIONAL_ID, TAX_ID, FINANCIAL, PASSPORT, HEALTH, CONTACT
    pattern: str
    keywords: List[str]
    checksum_validator: Optional[str] = None  # Name of validator in CHECKSUM_MAP
    severity: str = "HIGH"
    description: str

    @property
    def classifier_id(self) -> str:
        return self.identifier

    @property
    def name(self) -> str:
        return self.description or self.identifier

    @property
    def context_keywords(self) -> List[str]:
        return self.keywords

    @property
    def requires_context_for_high(self) -> bool:
        return True

    @property
    def regulations(self) -> List[str]:
        return [self.country_code]


class PIIDetectionResult(BaseModel):
    identifier: str
    pii_type: str = ""
    country_code: str
    country: str = ""
    category: str
    sample_masked: str
    masked_match: str = ""
    match_snippet: str = ""
    confidence: str  # HIGH, MEDIUM, LOW
    confidence_level: str = ""
    severity: str
    risk_level: str = ""
    matched_keyword: Optional[str] = None
    checksum_passed: bool
    position: int

    def model_post_init(self, __context: Any) -> None:
        if not self.pii_type:
            self.pii_type = self.identifier
        if not self.country:
            self.country = self.country_code
        if not self.match_snippet:
            self.match_snippet = self.sample_masked
        if not self.masked_match:
            self.masked_match = self.sample_masked
        if not self.confidence_level:
            self.confidence_level = self.confidence
        if not self.risk_level:
            self.risk_level = self.severity
