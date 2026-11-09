"""
[v2.8.0] Switzerland National PII Classifiers (nFADP / FADP Compliance)
Supports: AHV / AVS Social Security Number (13 digits starting with 756).
"""
from typing import List
from .base_definition import PIIClassifierDefinition


SWITZERLAND_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="SWISS_AHV_AVS",
        country_code="CH",
        country_name="Switzerland",
        category="NATIONAL_ID",
        pattern=r"\b756\.\d{4}\.\d{4}\.\d{2}\b",
        keywords=["ahv", "avs", "ahv-nr", "no avs", "oasdi", "social security", "versichertennummer"],
        checksum_validator="swiss_ahv",
        severity="CRITICAL",
        description="Swiss 13-digit AHV / AVS Social Insurance Number validated via EAN-13 checksum"
    )
]
