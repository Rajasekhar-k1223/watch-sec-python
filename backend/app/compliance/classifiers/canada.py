"""
[v2.8.0] Canada National PII Classifiers (PIPEDA Compliance)
Supports: Social Insurance Number (SIN Luhn) and Passport.
"""
from typing import List
from .base_definition import PIIClassifierDefinition


CANADA_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="CANADA_SIN",
        country_code="CA",
        country_name="Canada",
        category="NATIONAL_ID",
        pattern=r"\b\d{3}[ -]?\d{3}[ -]?\d{3}\b",
        keywords=["sin", "social insurance number", "nas", "numéro d'assurance sociale", "service canada", "cra"],
        checksum_validator="canada_sin",
        severity="CRITICAL",
        description="Canadian 9-digit Social Insurance Number (SIN) validated via Luhn checksum"
    ),
    PIIClassifierDefinition(
        identifier="CANADA_PASSPORT",
        country_code="CA",
        country_name="Canada",
        category="PASSPORT",
        pattern=r"\b[A-Za-z]{2}\d{6}\b",
        keywords=["passport", "passeport", "canadian passport", "citizenship and immigration"],
        checksum_validator=None,
        severity="CRITICAL",
        description="Canadian Passport Number (2 letters + 6 digits)"
    )
]
