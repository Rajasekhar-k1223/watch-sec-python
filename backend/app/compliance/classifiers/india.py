"""
[v2.8.0] India National PII Classifiers (DPDP Act 2023 & CERT-In Compliance)
Supports: Aadhaar (Verhoeff), PAN, Voter ID, Passport, Driving Licence,
Mobile, IFSC, Bank Account, and UPI identifiers.
"""
from typing import List
from pydantic import BaseModel
from .base_definition import PIIClassifierDefinition


INDIA_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="INDIA_AADHAAR",
        country_code="IN",
        country_name="India",
        category="NATIONAL_ID",
        pattern=r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b",
        keywords=["aadhaar", "aadhar", "uidai", "uid number", "unique identification"],
        checksum_validator="verhoeff",
        severity="CRITICAL",
        description="12-digit Indian Aadhaar number validated via Verhoeff checksum algorithm"
    ),
    PIIClassifierDefinition(
        identifier="INDIA_PAN",
        country_code="IN",
        country_name="India",
        category="TAX_ID",
        pattern=r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        keywords=["pan", "pan card", "incometax", "it department", "permanent account number"],
        checksum_validator=None,
        severity="HIGH",
        description="Indian Permanent Account Number (PAN) issued by Income Tax Department"
    ),
    PIIClassifierDefinition(
        identifier="INDIA_VOTER_ID",
        country_code="IN",
        country_name="India",
        category="NATIONAL_ID",
        pattern=r"\b[A-Z]{3}[0-9]{7}\b",
        keywords=["voter id", "epic", "election commission", "eci", "voter card"],
        checksum_validator=None,
        severity="HIGH",
        description="Indian Voter Identity Card (EPIC) issued by Election Commission of India"
    ),
    PIIClassifierDefinition(
        identifier="INDIA_PASSPORT",
        country_code="IN",
        country_name="India",
        category="PASSPORT",
        pattern=r"\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b",
        keywords=["passport", "republic of india", "indian passport"],
        checksum_validator=None,
        severity="CRITICAL",
        description="Indian Passport number format with single letter followed by 7 digits"
    ),
    PIIClassifierDefinition(
        identifier="INDIA_DRIVING_LICENCE",
        country_code="IN",
        country_name="India",
        category="NATIONAL_ID",
        pattern=r"\b[A-Z]{2}[0-9]{2}[ -]?[0-9]{11}\b",
        keywords=["driving licence", "driving license", "dl no", "rto", "parivahan"],
        checksum_validator=None,
        severity="HIGH",
        description="Indian Driving Licence issued by State Regional Transport Offices"
    ),
    PIIClassifierDefinition(
        identifier="INDIA_MOBILE",
        country_code="IN",
        country_name="India",
        category="CONTACT",
        pattern=r"\b(?:(?:\+91|91|0)[ -]?)?[6-9]\d{9}\b",
        keywords=["phone", "mobile", "contact", "cell", "call", "whatsapp"],
        checksum_validator=None,
        severity="MEDIUM",
        description="Indian 10-digit mobile number with cellular prefix 6-9"
    ),
    PIIClassifierDefinition(
        identifier="INDIA_IFSC",
        country_code="IN",
        country_name="India",
        category="FINANCIAL",
        pattern=r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
        keywords=["ifsc", "ifsc code", "rtgs", "neft", "bank branch", "imps"],
        checksum_validator=None,
        severity="HIGH",
        description="Indian Financial System Code (IFSC) for electronic funds transfer"
    ),
    PIIClassifierDefinition(
        identifier="INDIA_BANK_ACCOUNT",
        country_code="IN",
        country_name="India",
        category="FINANCIAL",
        pattern=r"\b\d{9,18}\b",
        keywords=["bank account", "account number", "a/c no", "savings account", "current account", "sbi", "hdfc", "icici", "pnb", "axis"],
        checksum_validator=None,
        severity="HIGH",
        description="Indian Commercial Bank Account Number (9 to 18 digits)"
    ),
    PIIClassifierDefinition(
        identifier="INDIA_UPI_ID",
        country_code="IN",
        country_name="India",
        category="FINANCIAL",
        pattern=r"\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b",
        keywords=["upi", "upi id", "vpa", "gpay", "phonepe", "paytm", "bhim", "virtual payment"],
        checksum_validator=None,
        severity="HIGH",
        description="Unified Payments Interface (UPI) Virtual Payment Address (VPA)"
    )
]
