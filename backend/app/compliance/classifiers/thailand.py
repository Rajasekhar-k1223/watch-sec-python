"""
[v2.8.0] Thailand National PII Classifiers (PDPA Compliance)
Supports: Thai National Identification Number (13 digits with Modulo 11).
"""
from typing import List
from .base_definition import PIIClassifierDefinition


THAILAND_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="THAILAND_NATIONAL_ID",
        country_code="TH",
        country_name="Thailand",
        category="NATIONAL_ID",
        pattern=r"\b\d[ -]?\d{4}[ -]?\d{5}[ -]?\d{2}[ -]?\d\b",
        keywords=["บัตรประชาชน", "เลขประจำตัวประชาชน", "thai national id", "id card", "กรมการปกครอง"],
        checksum_validator="thailand_id",
        severity="CRITICAL",
        description="13-digit Thai National Identification Number with statutory Modulo 11 check digit"
    )
]
