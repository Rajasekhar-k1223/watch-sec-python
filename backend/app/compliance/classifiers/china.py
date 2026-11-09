"""
[v2.8.0] China National PII Classifiers (PIPL, CSL, DSL Compliance)
Supports: Resident ID Card (ISO 7064 MOD 11-2), Mobile, Unified Social Credit Code.
"""
from typing import List
from .base_definition import PIIClassifierDefinition


CHINA_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="CHINA_RESIDENT_ID",
        country_code="CN",
        country_name="China",
        category="NATIONAL_ID",
        pattern=r"\b\d{17}[\dXx]\b",
        keywords=["居民身份证", "身份证", "身份证号", "resident identity card", "china id", "公民身份号码"],
        checksum_validator="china_ric",
        severity="CRITICAL",
        description="18-digit Chinese Resident Identity Card validated via ISO 7064 MOD 11-2 check code"
    ),
    PIIClassifierDefinition(
        identifier="CHINA_MOBILE",
        country_code="CN",
        country_name="China",
        category="CONTACT",
        pattern=r"\b(?:\+86\s?)?1[3-9]\d{9}\b",
        keywords=["手机", "手机号", "电话", "mobile", "phone", "联系方式"],
        checksum_validator=None,
        severity="MEDIUM",
        description="Mainland Chinese 11-digit mobile phone number"
    ),
    PIIClassifierDefinition(
        identifier="CHINA_USCC",
        country_code="CN",
        country_name="China",
        category="TAX_ID",
        pattern=r"\b[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}\b",
        keywords=["统一社会信用代码", "营业执照", "uscc", "credit code", "企业信用代码"],
        checksum_validator=None,
        severity="HIGH",
        description="China 18-digit Unified Social Credit Code (USCC) for legal entities"
    )
]
