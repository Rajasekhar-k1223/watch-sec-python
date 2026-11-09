"""
[v2.8.0] Colombia National PII Classifiers (Ley 1581 de 2012 Compliance)
Supports: Cédula de Ciudadanía and NIT (Tax ID).
"""
from typing import List
from .base_definition import PIIClassifierDefinition


COLOMBIA_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="COLOMBIA_CEDULA",
        country_code="CO",
        country_name="Colombia",
        category="NATIONAL_ID",
        pattern=r"\b\d{6,10}\b",
        keywords=["cédula", "cedula", "cc", "registraduría", "cédula de ciudadanía", "documento de identidad"],
        checksum_validator=None,
        severity="HIGH",
        description="Colombian Cédula de Ciudadanía (National Identity Document)"
    ),
    PIIClassifierDefinition(
        identifier="COLOMBIA_NIT",
        country_code="CO",
        country_name="Colombia",
        category="TAX_ID",
        pattern=r"\b\d{9}-?\d\b",
        keywords=["nit", "número de identificación tributaria", "dian", "tributario", "rut colombia"],
        checksum_validator=None,
        severity="HIGH",
        description="Colombian Tax Identification Number (NIT) issued by DIAN"
    )
]
