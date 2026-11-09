"""
[v2.8.0] Singapore National PII Classifiers (PDPA Compliance)
Supports: NRIC / FIN (Modulo 11 check letter) and Mobile.
"""
from typing import List
from .base_definition import PIIClassifierDefinition


SINGAPORE_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="SINGAPORE_NRIC_FIN",
        country_code="SG",
        country_name="Singapore",
        category="NATIONAL_ID",
        pattern=r"\b[STFGMstfgm]\d{7}[A-Za-z]\b",
        keywords=["nric", "fin", "identity card", "singpass", "ica", "work pass"],
        checksum_validator="singapore_nric",
        severity="CRITICAL",
        description="Singapore National Registration Identity Card (NRIC) and Foreign Identification Number (FIN)"
    ),
    PIIClassifierDefinition(
        identifier="SINGAPORE_MOBILE",
        country_code="SG",
        country_name="Singapore",
        category="CONTACT",
        pattern=r"\b(?:\+65\s?)?[89]\d{7}\b",
        keywords=["phone", "mobile", "contact", "hp", "singapore phone"],
        checksum_validator=None,
        severity="MEDIUM",
        description="Singapore 8-digit mobile phone number starting with 8 or 9"
    )
]
