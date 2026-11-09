"""
[v2.8.0] Brazil National PII Classifiers (LGPD Compliance)
Supports: CPF (Modulo 11), CNPJ (Modulo 11), Brazilian Phone, and RG.
"""
from typing import List
from .base_definition import PIIClassifierDefinition


BRAZIL_CLASSIFIERS: List[PIIClassifierDefinition] = [
    PIIClassifierDefinition(
        identifier="BRAZIL_CPF",
        country_code="BR",
        country_name="Brazil",
        category="NATIONAL_ID",
        pattern=r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b",
        keywords=["cpf", "cadastro de pessoas físicas", "receita federal", "contribuinte", "documento"],
        checksum_validator="brazil_cpf",
        severity="CRITICAL",
        description="11-digit Brazilian CPF validated via dual Modulo 11 check digits"
    ),
    PIIClassifierDefinition(
        identifier="BRAZIL_CNPJ",
        country_code="BR",
        country_name="Brazil",
        category="TAX_ID",
        pattern=r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b",
        keywords=["cnpj", "cadastro nacional de pessoa jurídica", "empresa", "razão social", "matriz"],
        checksum_validator="brazil_cnpj",
        severity="HIGH",
        description="14-digit Brazilian CNPJ (Company Registration) validated via Modulo 11"
    ),
    PIIClassifierDefinition(
        identifier="BRAZIL_PHONE",
        country_code="BR",
        country_name="Brazil",
        category="CONTACT",
        pattern=r"\b(?:\+55\s?)?(?:\(?\d{2}\)?\s?)?(?:9\d{4}[ -]?\d{4})\b",
        keywords=["telefone", "celular", "whatsapp", "contato", "fone", "ligar"],
        checksum_validator=None,
        severity="MEDIUM",
        description="Brazilian 11-digit mobile phone number with standard 9-prefix"
    ),
    PIIClassifierDefinition(
        identifier="BRAZIL_RG",
        country_code="BR",
        country_name="Brazil",
        category="NATIONAL_ID",
        pattern=r"\b\d{1,2}\.?\d{3}\.?\d{3}-?[0-9Xx]\b",
        keywords=["rg", "registro geral", "cédula de identidade", "ssp", "identidade"],
        checksum_validator=None,
        severity="HIGH",
        description="Brazilian RG (Registro Geral) National Identity Document"
    )
]
