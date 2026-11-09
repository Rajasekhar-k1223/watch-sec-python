"""
[v2.8.0] Türkiye National PII Classifiers (KVKK Compliance)
Supports: TC Kimlik No (11 digits with dual algorithmic check).
"""
from typing import List
from .base_definition import PIIClassifierDefinition


TURKEY_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="TURKEY_TC_KIMLIK",
        country_code="TR",
        country_name="Turkey",
        category="NATIONAL_ID",
        pattern=r"\b\d{11}\b",
        keywords=["tc kimlik", "kimlik no", "tckn", "nüfus cüzdanı", "nvi", "türk kimlik"],
        checksum_validator="turkey_tc_kimlik",
        severity="CRITICAL",
        description="Turkish Republic 11-digit Identity Number (TC Kimlik No) with dual algorithmic check"
    )
]
