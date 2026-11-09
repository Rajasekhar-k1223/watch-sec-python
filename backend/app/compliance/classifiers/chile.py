"""
[v2.8.0] Chile National PII Classifiers (Ley 19.628 / 21.096 / 21.663 Compliance)
Supports: RUT / RUN (Rol Único Tributario) validated via Modulo 11 algorithm.
"""
from typing import List
from .base_definition import PIIClassifierDefinition


CHILE_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="CHILE_RUT_RUN",
        country_code="CL",
        country_name="Chile",
        category="NATIONAL_ID",
        pattern=r"\b\d{1,2}\.?\d{3}\.?\d{3}-?[\dKk]\b",
        keywords=["rut", "run", "cédula", "registro civil", "sii", "identidad", "rol único"],
        checksum_validator="chile_rut",
        severity="CRITICAL",
        description="Chilean National Identity & Tax Number (RUT/RUN) validated via Modulo 11 check digit"
    )
]
