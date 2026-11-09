"""
[v2.8.0] Australia National PII Classifiers (Privacy Act & APPs Compliance)
Supports: Tax File Number (TFN Modulo 11), Medicare Number, and Passport.
"""
from typing import List
from .base_definition import PIIClassifierDefinition


AUSTRALIA_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="AUSTRALIA_TFN",
        country_code="AU",
        country_name="Australia",
        category="TAX_ID",
        pattern=r"\b\d{3}[ -]?\d{3}[ -]?\d{2,3}\b",
        keywords=["tfn", "tax file number", "ato", "australian taxation office", "superannuation"],
        checksum_validator="australia_tfn",
        severity="CRITICAL",
        description="Australian 8 or 9-digit Tax File Number (TFN) validated via ATO Modulo 11"
    ),
    PIIClassifierDefinition(
        identifier="AUSTRALIA_MEDICARE",
        country_code="AU",
        country_name="Australia",
        category="HEALTH",
        pattern=r"\b[2-6]\d{9}[ -]?\d?\b",
        keywords=["medicare", "medicare number", "services australia", "green card", "health insurance"],
        checksum_validator=None,
        severity="HIGH",
        description="Australian 10-digit Medicare card number with optional individual reference number"
    ),
    PIIClassifierDefinition(
        identifier="AUSTRALIA_PASSPORT",
        country_code="AU",
        country_name="Australia",
        category="PASSPORT",
        pattern=r"\b[E-He-hN-Pn-p]\d{7}\b",
        keywords=["passport", "australian passport", "dfat", "pass"],
        checksum_validator=None,
        severity="CRITICAL",
        description="Australian Passport Number with single letter prefix followed by 7 digits"
    )
]
