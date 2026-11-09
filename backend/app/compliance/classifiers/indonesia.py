"""
[v2.8.0] Indonesia National PII Classifiers (PDP Law Compliance)
Supports: NIK (Nomor Induk Kependudukan 16 digits) and NPWP (Tax ID).
"""
from typing import List
from .base_definition import PIIClassifierDefinition


INDONESIA_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="INDONESIA_NIK",
        country_code="ID",
        country_name="Indonesia",
        category="NATIONAL_ID",
        pattern=r"\b\d{16}\b",
        keywords=["nik", "nomor induk kependudukan", "ktp", "kartu tanda penduduk", "dukcapil"],
        checksum_validator=None,
        severity="CRITICAL",
        description="16-digit Indonesian Single Identity Number (NIK) encoded on e-KTP"
    ),
    PIIClassifierDefinition(
        identifier="INDONESIA_NPWP",
        country_code="ID",
        country_name="Indonesia",
        category="TAX_ID",
        pattern=r"\b\d{2}\.?\d{3}\.?\d{3}\.?[0-9]-?\d{3}\.?\d{3}\b",
        keywords=["npwp", "nomor pokok wajib pajak", "pajak", "djp", "wajib pajak"],
        checksum_validator=None,
        severity="HIGH",
        description="Indonesian 15 or 16-digit Tax Identification Number (NPWP)"
    )
]
