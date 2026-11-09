"""
[v2.8.0] Saudi Arabia National PII Classifiers (PDPL Compliance)
Supports: Saudi National ID (starts with 1, Luhn) and Iqama (starts with 2, Luhn).
"""
from typing import List
from .base_definition import PIIClassifierDefinition


SAUDI_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="SAUDI_NATIONAL_ID",
        country_code="SA",
        country_name="Saudi Arabia",
        category="NATIONAL_ID",
        pattern=r"\b1\d{9}\b",
        keywords=["national id", "saudi id", "hawiyya", "civil affairs", "بطاقة الأحوال", "الهوية الوطنية", "أبشر"],
        checksum_validator="saudi_id",
        severity="CRITICAL",
        description="Saudi 10-digit National ID (starts with 1) validated via Luhn checksum"
    ),
    PIIClassifierDefinition(
        identifier="SAUDI_IQAMA",
        country_code="SA",
        country_name="Saudi Arabia",
        category="NATIONAL_ID",
        pattern=r"\b2\d{9}\b",
        keywords=["iqama", "muqeem", "resident id", "jawazat", "إقامة", "هوية مقيم"],
        checksum_validator="saudi_id",
        severity="CRITICAL",
        description="Saudi 10-digit Resident ID (Iqama, starts with 2) validated via Luhn checksum"
    )
]
