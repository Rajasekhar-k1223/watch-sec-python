"""
[v2.8.0] Japan National PII Classifiers (APPI Compliance)
Supports: Individual Number (My Number Modulo 11), Driver's License, Basic Pension Number.
"""
from typing import List
from .base_definition import PIIClassifierDefinition


JAPAN_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="JAPAN_MY_NUMBER",
        country_code="JP",
        country_name="Japan",
        category="NATIONAL_ID",
        pattern=r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b",
        keywords=["マイナンバー", "個人番号", "my number", "individual number", "通知カード"],
        checksum_validator="japan_my_number",
        severity="CRITICAL",
        description="12-digit Japanese Individual Number (My Number) with statutory Modulo 11 check digit"
    ),
    PIIClassifierDefinition(
        identifier="JAPAN_DRIVERS_LICENSE",
        country_code="JP",
        country_name="Japan",
        category="NATIONAL_ID",
        pattern=r"\b\d{12}\b",
        keywords=["運転免許証", "免許証番号", "drivers license", "公安委員会"],
        checksum_validator=None,
        severity="HIGH",
        description="Japanese 12-digit Driver's License Number"
    ),
    PIIClassifierDefinition(
        identifier="JAPAN_PENSION_NUMBER",
        country_code="JP",
        country_name="Japan",
        category="GOVERNMENT",
        pattern=r"\b\d{4}[ -]?\d{6}\b",
        keywords=["基礎年金番号", "年金手帳", "pension number", "日本年金機構"],
        checksum_validator=None,
        severity="HIGH",
        description="Japanese 10-digit Basic Pension Number"
    )
]
