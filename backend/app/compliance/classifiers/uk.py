"""
[v2.8.0] United Kingdom National PII Classifiers (UK GDPR & DPA 2018 Compliance)
Supports: National Insurance Number (NINO) and NHS Number (Modulo 11).
"""
from typing import List
from .base_definition import PIIClassifierDefinition


UK_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="UK_NINO",
        country_code="GB",
        country_name="United Kingdom",
        category="NATIONAL_ID",
        pattern=r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
        keywords=["nino", "national insurance", "ni number", "hmrc", "dwp", "national insurance number"],
        checksum_validator=None,
        severity="CRITICAL",
        description="UK National Insurance Number (NINO) with statutory prefix exclusions"
    ),
    PIIClassifierDefinition(
        identifier="UK_NHS",
        country_code="GB",
        country_name="United Kingdom",
        category="HEALTH",
        pattern=r"\b\d{3}\s?\d{3}\s?\d{4}\b",
        keywords=["nhs", "nhs number", "national health service", "patient", "medical record", "health authority"],
        checksum_validator="uk_nhs",
        severity="CRITICAL",
        description="UK 10-digit National Health Service (NHS) Number validated via Modulo 11"
    )
]
