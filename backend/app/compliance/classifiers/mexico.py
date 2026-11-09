"""
[v2.8.0] Mexico National PII Classifiers (LFPDPPP Compliance)
Supports: CURP (18 chars with state/consonant check) and RFC (12 or 13 chars).
"""
from typing import List
from .base_definition import PIIClassifierDefinition


MEXICO_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="MEXICO_CURP",
        country_code="MX",
        country_name="Mexico",
        category="NATIONAL_ID",
        pattern=r"\b[A-Z]{4}\d{6}[HM][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[A-Z0-9]\d\b",
        keywords=["curp", "clave única de registro", "renapo", "población", "identidad"],
        checksum_validator="mexico_curp",
        severity="CRITICAL",
        description="Mexican 18-character CURP (Clave Única de Registro de Población)"
    ),
    PIIClassifierDefinition(
        identifier="MEXICO_RFC",
        country_code="MX",
        country_name="Mexico",
        category="TAX_ID",
        pattern=r"\b[A-Z&Ñ]{3,4}\d{6}[A-Z0-9]{3}\b",
        keywords=["rfc", "registro federal de contribuyentes", "sat", "hacienda", "tributario"],
        checksum_validator="mexico_rfc",
        severity="HIGH",
        description="Mexican 12 or 13-character RFC (Registro Federal de Contribuyentes)"
    )
]
