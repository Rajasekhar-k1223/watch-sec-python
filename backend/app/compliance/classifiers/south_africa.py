"""
[v2.8.0] South Africa National PII Classifiers (POPIA Compliance)
Supports: South African National ID (13 digits with Luhn & Date check).
"""
from typing import List
from .base_definition import PIIClassifierDefinition


SOUTH_AFRICA_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="SOUTH_AFRICA_ID",
        country_code="ZA",
        country_name="South Africa",
        category="NATIONAL_ID",
        pattern=r"\b\d{13}\b",
        keywords=["id number", "south african id", "rsa id", "home affairs", "identity document", "smart id"],
        checksum_validator="south_africa_id",
        severity="CRITICAL",
        description="South African 13-digit National ID Number validated via date structure and Luhn checksum"
    )
]
