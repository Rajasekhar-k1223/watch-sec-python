"""
[v2.8.0] Kenya National PII Classifiers (Data Protection Act 2019 Compliance)
Supports: Kenyan National ID and KRA PIN.
"""
from typing import List
from .base_definition import PIIClassifierDefinition


KENYA_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="KENYA_NATIONAL_ID",
        country_code="KE",
        country_name="Kenya",
        category="NATIONAL_ID",
        pattern=r"\b\d{7,8}\b",
        keywords=["national id", "huduma", "kenyan id", "id number", "kitambulisho", "republic of kenya"],
        checksum_validator=None,
        severity="HIGH",
        description="Kenyan 7 or 8-digit National Identity Card Number"
    ),
    PIIClassifierDefinition(
        identifier="KENYA_KRA_PIN",
        country_code="KE",
        country_name="Kenya",
        category="TAX_ID",
        pattern=r"\b[AP]\d{9}[A-Z]\b",
        keywords=["kra pin", "kra", "itax", "kenya revenue authority", "tax pin", "personal identification number"],
        checksum_validator=None,
        severity="HIGH",
        description="Kenya Revenue Authority (KRA) Tax PIN"
    )
]
