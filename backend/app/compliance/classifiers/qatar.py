"""
[v2.8.0] Qatar National PII Classifiers (Personal Data Privacy Protection Law Compliance)
Supports: Qatar ID (QID 11 digits).
"""
from typing import List
from .base_definition import PIIClassifierDefinition


QATAR_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="QATAR_QID",
        country_code="QA",
        country_name="Qatar",
        category="NATIONAL_ID",
        pattern=r"\b\d{11}\b",
        keywords=["qid", "qatar id", "moi qatar", "identity card", "residency permit", "بطاقة شخصية", "الرقم الشخصي"],
        checksum_validator=None,
        severity="CRITICAL",
        description="11-digit Qatari National ID (QID) issued by Ministry of Interior"
    )
]
