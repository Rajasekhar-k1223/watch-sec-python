"""
[v2.8.0] New Zealand National PII Classifiers (Privacy Act 2020 Compliance)
Supports: Inland Revenue Department (IRD Modulo 11) Number and Driver Licence.
"""
from typing import List
from .base_definition import PIIClassifierDefinition


NEW_ZEALAND_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="NZ_IRD",
        country_code="NZ",
        country_name="New Zealand",
        category="TAX_ID",
        pattern=r"\b\d{2,3}[ -]?\d{3}[ -]?\d{3}\b",
        keywords=["ird", "ird number", "inland revenue", "nz tax", "kiwisaver", "tax return"],
        checksum_validator="nz_ird",
        severity="CRITICAL",
        description="New Zealand 8 or 9-digit IRD Tax Number validated via Modulo 11"
    ),
    PIIClassifierDefinition(
        identifier="NZ_DRIVER_LICENCE",
        country_code="NZ",
        country_name="New Zealand",
        category="NATIONAL_ID",
        pattern=r"\b[A-Za-z]{2}\d{6}\b",
        keywords=["driver licence", "driving licence", "nzta", "waka kotahi", "licence card"],
        checksum_validator=None,
        severity="HIGH",
        description="New Zealand Driver Licence Number (2 letters + 6 digits)"
    )
]
