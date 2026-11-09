"""
[v2.8.0] South Korea National PII Classifiers (PIPA Compliance)
Supports: Resident Registration Number (RRN Modulo 11) and Mobile.
"""
from typing import List
from .base_definition import PIIClassifierDefinition


KOREA_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="KOREA_RRN",
        country_code="KR",
        country_name="South Korea",
        category="NATIONAL_ID",
        pattern=r"\b\d{6}[ -]?[1-8]\d{6}\b",
        keywords=["주민등록번호", "주민번호", "rrn", "resident registration number", "생년월일"],
        checksum_validator="korea_rrn",
        severity="CRITICAL",
        description="South Korean 13-digit Resident Registration Number (RRN) with gender & Modulo 11 check"
    ),
    PIIClassifierDefinition(
        identifier="KOREA_MOBILE",
        country_code="KR",
        country_name="South Korea",
        category="CONTACT",
        pattern=r"\b(?:010|011|016|017|018|019)[ -]?\d{3,4}[ -]?\d{4}\b",
        keywords=["휴대전화", "핸드폰", "연락처", "mobile", "phone"],
        checksum_validator=None,
        severity="MEDIUM",
        description="South Korean mobile telephone number"
    )
]
