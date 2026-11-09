"""
[v2.8.0] Nigeria National PII Classifiers (NDPA Compliance)
Supports: National Identification Number (NIN) and Bank Verification Number (BVN).
"""
from typing import List
from .base_definition import PIIClassifierDefinition


NIGERIA_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="NIGERIA_NIN",
        country_code="NG",
        country_name="Nigeria",
        category="NATIONAL_ID",
        pattern=r"\b\d{11}\b",
        keywords=["nin", "national identification number", "nimc", "national identity", "identity slip"],
        checksum_validator=None,
        severity="CRITICAL",
        description="Nigerian 11-digit National Identification Number (NIN) issued by NIMC"
    ),
    PIIClassifierDefinition(
        identifier="NIGERIA_BVN",
        country_code="NG",
        country_name="Nigeria",
        category="FINANCIAL",
        pattern=r"\b\d{11}\b",
        keywords=["bvn", "bank verification number", "cbn", "central bank of nigeria", "bank verification"],
        checksum_validator=None,
        severity="HIGH",
        description="Nigerian 11-digit Bank Verification Number (BVN)"
    )
]
