"""
[v4.4.0] USA National PII, Consumer Privacy & GLBA Financial Classifiers
(CCPA/CPRA, GLBA Safeguards Rule, HIPAA, SOX, FISMA)
Supports: SSN, ITIN, EIN Tax ID, Credit/Debit Card (Luhn), Bank Account,
ABA Routing (Modulo-10), Loan Account, Financial Account, NPI Customer Record,
Driver License, and US Passport.
"""
from typing import List
from .base_definition import PIIClassifierDefinition


USA_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="US_SSN",
        country_code="US",
        country_name="United States",
        category="NATIONAL_ID",
        pattern=r"\b(?!000|666|9\d{2})\d{3}[ -]?(?!00)\d{2}[ -]?(?!0000)\d{4}\b",
        keywords=["ssn", "social security", "soc sec", "ssn#", "taxpayer id"],
        checksum_validator=None,
        severity="CRITICAL",
        description="US Social Security Number (SSN) with SSA area/group/serial validation"
    ),
    PIIClassifierDefinition(
        identifier="US_ITIN",
        country_code="US",
        country_name="United States",
        category="TAX_ID",
        pattern=r"\b9\d{2}[ -]?[5-9]\d[ -]?\d{4}\b",
        keywords=["itin", "individual taxpayer", "irs", "tax id", "tax identification"],
        checksum_validator=None,
        severity="HIGH",
        description="US Individual Taxpayer Identification Number (ITIN)"
    ),
    PIIClassifierDefinition(
        identifier="US_EIN_TAX_ID",
        country_code="US",
        country_name="United States",
        category="TAX_ID",
        pattern=r"\b(?:0[1-6]|1[0-6]|2[0-7]|3[0-9]|4[0-8]|5[0-9]|6[0-8]|7[1-7]|8[0-8]|9[0-589])-\d{7}\b",
        keywords=["ein", "fein", "employer identification", "federal tax id", "taxpayer identification"],
        checksum_validator=None,
        severity="HIGH",
        description="US Federal Employer / Tax Identification Number (EIN / FEIN)"
    ),
    PIIClassifierDefinition(
        identifier="US_CREDIT_CARD",
        country_code="US",
        country_name="United States",
        category="FINANCIAL",
        pattern=r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        keywords=["credit card", "visa", "mastercard", "amex", "discover", "card number", "debit card", "cvv"],
        checksum_validator="luhn",
        severity="CRITICAL",
        description="Payment Card Number (Visa, Mastercard, Amex, Discover) validated via Luhn checksum"
    ),
    PIIClassifierDefinition(
        identifier="US_BANK_ACCOUNT",
        country_code="US",
        country_name="United States",
        category="FINANCIAL",
        pattern=r"\b\d{8,17}\b",
        keywords=["bank account", "checking account", "savings account", "account number", "ach", "direct deposit"],
        checksum_validator=None,
        severity="HIGH",
        description="US Commercial / Consumer Bank Account Number (8 to 17 digits)"
    ),
    PIIClassifierDefinition(
        identifier="US_ROUTING_NUMBER",
        country_code="US",
        country_name="United States",
        category="FINANCIAL",
        pattern=r"\b((0[1-9])|([1-2][0-9])|(3[0-2])|(6[1-9])|(7[0-2])|(80))\d{7}\b",
        keywords=["routing number", "aba", "routing transit", "bank routing", "transit number"],
        checksum_validator="aba_routing",
        severity="HIGH",
        description="US American Bankers Association (ABA) 9-digit Transit Routing Number (Modulo 10)"
    ),
    PIIClassifierDefinition(
        identifier="US_LOAN_ACCOUNT",
        country_code="US",
        country_name="United States",
        category="FINANCIAL",
        pattern=r"\b(?:LN|LOAN|MTG|MORT)-[0-9]{6,12}\b|\b\d{10,14}\b",
        keywords=["loan account", "mortgage account", "loan number", "promissory note", "borrower id", "servicing account"],
        checksum_validator=None,
        severity="HIGH",
        description="GLBA Consumer Loan / Mortgage Servicing Account Identifier"
    ),
    PIIClassifierDefinition(
        identifier="US_FINANCIAL_ACCOUNT",
        country_code="US",
        country_name="United States",
        category="FINANCIAL",
        pattern=r"\b(?:FIN|BRK|INV)-[0-9A-Z]{8,14}\b|\b\d{9,16}\b",
        keywords=["brokerage account", "investment account", "wealth account", "custody account", "financial account"],
        checksum_validator=None,
        severity="HIGH",
        description="GLBA Brokerage / Custody / Financial Institution Account Identifier"
    ),
    PIIClassifierDefinition(
        identifier="US_NPI_RECORD",
        country_code="US",
        country_name="United States",
        category="FINANCIAL",
        pattern=r"\b(?:NPI|GLBA|CIF)-[0-9A-Z]{6,14}\b",
        keywords=["nonpublic personal information", "customer information file", "glba npi", "consumer financial profile"],
        checksum_validator=None,
        severity="CRITICAL",
        description="GLBA Non-Public Personal Financial Information (NPI) Customer File Identifier"
    ),
    PIIClassifierDefinition(
        identifier="US_PASSPORT",
        country_code="US",
        country_name="United States",
        category="PASSPORT",
        pattern=r"\b[A-Z0-9]{9}\b",
        keywords=["passport", "us passport", "united states passport", "travel document", "dept of state"],
        checksum_validator=None,
        severity="CRITICAL",
        description="United States 9-character Passport Book Number"
    ),
    PIIClassifierDefinition(
        identifier="US_DRIVER_LICENSE",
        country_code="US",
        country_name="United States",
        category="NATIONAL_ID",
        pattern=r"\b[A-Z]\d{7,12}\b",
        keywords=["driver license", "drivers license", "dl#", "dmv", "state id"],
        checksum_validator=None,
        severity="HIGH",
        description="US State Driver License / Identification Card Number"
    ),
]
