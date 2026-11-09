"""
[v2.8.0] UAE National PII Classifiers (Federal Decree-Law No. 45 of 2021 Compliance)
Supports: Emirates ID (15 digits with Modulo 11 / Luhn).
"""
from typing import List
from .base_definition import PIIClassifierDefinition


UAE_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="UAE_EMIRATES_ID",
        country_code="AE",
        country_name="United Arab Emirates",
        category="NATIONAL_ID",
        pattern=r"\b784[ -]?\d{4}[ -]?\d{7}[ -]?\d\b",
        keywords=["emirates id", "eid", "identity authority", "ica", "federal authority for identity", "بطاقة الهوية"],
        checksum_validator="uae_emirates_id",
        severity="CRITICAL",
        description="15-digit UAE Emirates ID (784-YYYY-XXXXXXX-Z) with Luhn checksum validation"
    )
]
