"""
[v2.8.0] Argentina National PII Classifiers (Ley 25.326 PDPA Compliance)
Supports: DNI and CUIT / CUIL (11 digits with Modulo 11 check).
"""
from typing import List
from .base_definition import PIIClassifierDefinition


ARGENTINA_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="ARGENTINA_DNI",
        country_code="AR",
        country_name="Argentina",
        category="NATIONAL_ID",
        pattern=r"\b\d{7,8}\b",
        keywords=["dni", "documento nacional de identidad", "renaper", "documento", "identidad"],
        checksum_validator=None,
        severity="HIGH",
        description="Argentine 7 or 8-digit National Identity Document (DNI)"
    ),
    PIIClassifierDefinition(
        identifier="ARGENTINA_CUIT_CUIL",
        country_code="AR",
        country_name="Argentina",
        category="TAX_ID",
        pattern=r"\b\d{2}-?\d{8}-?\d\b",
        keywords=["cuit", "cuil", "afip", "anses", "constancia", "tributaria", "clave única"],
        checksum_validator="argentina_cuit",
        severity="CRITICAL",
        description="Argentine 11-digit CUIT / CUIL Tax Number with Modulo 11 check digit"
    )
]
