"""
[v4.4.0] Global National PII Classifier Registry
Covers 25 jurisdictions with multi-layer false-positive controls:
Pattern (Regex) + Country Scope + Contextual Keyword Proximity + Negative Context Suppression
+ Mathematical Checksum Verification + Confidence Scoring (HIGH / MEDIUM / LOW).
"""
import re
from typing import Dict, List, Any, Optional, Callable
from .base_definition import PIIClassifierDefinition, PIIDetectionResult
from .checksums import (
    validate_verhoeff,
    validate_luhn,
    validate_brazil_cpf,
    validate_brazil_cnpj,
    validate_chile_rut,
    validate_singapore_nric,
    validate_china_ric,
    validate_australia_tfn,
    validate_turkey_tc_kimlik,
    validate_uk_nhs,
    validate_nz_ird,
    validate_swiss_ahv,
    validate_argentina_cuit,
    validate_saudi_id,
    validate_japan_my_number,
    validate_korea_rrn,
    validate_thailand_id,
    validate_uae_emirates_id,
    validate_canada_sin,
    validate_south_africa_id,
    validate_mexico_curp,
    validate_mexico_rfc,
    validate_aba_routing,
)

from .india import INDIA_CLASSIFIERS
from .usa import USA_CLASSIFIERS
from .brazil import BRAZIL_CLASSIFIERS
from .china import CHINA_CLASSIFIERS
from .japan import JAPAN_CLASSIFIERS
from .korea import KOREA_CLASSIFIERS
from .singapore import SINGAPORE_CLASSIFIERS
from .thailand import THAILAND_CLASSIFIERS
from .indonesia import INDONESIA_CLASSIFIERS
from .australia import AUSTRALIA_CLASSIFIERS
from .new_zealand import NEW_ZEALAND_CLASSIFIERS
from .canada import CANADA_CLASSIFIERS
from .uk import UK_CLASSIFIERS
from .switzerland import SWITZERLAND_CLASSIFIERS
from .turkey import TURKEY_CLASSIFIERS
from .south_africa import SOUTH_AFRICA_CLASSIFIERS
from .nigeria import NIGERIA_CLASSIFIERS
from .kenya import KENYA_CLASSIFIERS
from .uae import UAE_CLASSIFIERS
from .saudi_arabia import SAUDI_CLASSIFIERS
from .qatar import QATAR_CLASSIFIERS
from .mexico import MEXICO_CLASSIFIERS
from .argentina import ARGENTINA_CLASSIFIERS
from .chile import CHILE_CLASSIFIERS
from .colombia import COLOMBIA_CLASSIFIERS

CHECKSUM_MAP: Dict[str, Callable[[str], bool]] = {
    "verhoeff": validate_verhoeff,
    "luhn": validate_luhn,
    "brazil_cpf": validate_brazil_cpf,
    "brazil_cnpj": validate_brazil_cnpj,
    "chile_rut": validate_chile_rut,
    "singapore_nric": validate_singapore_nric,
    "china_ric": validate_china_ric,
    "australia_tfn": validate_australia_tfn,
    "turkey_tc_kimlik": validate_turkey_tc_kimlik,
    "uk_nhs": validate_uk_nhs,
    "nz_ird": validate_nz_ird,
    "swiss_ahv": validate_swiss_ahv,
    "argentina_cuit": validate_argentina_cuit,
    "saudi_id": validate_saudi_id,
    "japan_my_number": validate_japan_my_number,
    "korea_rrn": validate_korea_rrn,
    "thailand_id": validate_thailand_id,
    "uae_emirates_id": validate_uae_emirates_id,
    "canada_sin": validate_canada_sin,
    "south_africa_id": validate_south_africa_id,
    "mexico_curp": validate_mexico_curp,
    "mexico_rfc": validate_mexico_rfc,
    "aba_routing": validate_aba_routing,
}

# Negative context tokens that commonly accompany random operational numbers
NEGATIVE_CONTEXT_KEYWORDS = (
    "invoice",
    "order",
    "order_id",
    "invoice ref",
    "timestamp",
    "epoch",
    "bytes",
    "packet",
    "port ",
    "sku",
    "txid",
    "build #",
    "commit ",
    "serial#",
    "version ",
    "latency",
)

PII_CLASSIFIERS: Dict[str, List[PIIClassifierDefinition]] = {
    "IN": INDIA_CLASSIFIERS,
    "US": USA_CLASSIFIERS,
    "BR": BRAZIL_CLASSIFIERS,
    "CN": CHINA_CLASSIFIERS,
    "JP": JAPAN_CLASSIFIERS,
    "KR": KOREA_CLASSIFIERS,
    "SG": SINGAPORE_CLASSIFIERS,
    "TH": THAILAND_CLASSIFIERS,
    "ID": INDONESIA_CLASSIFIERS,
    "AU": AUSTRALIA_CLASSIFIERS,
    "NZ": NEW_ZEALAND_CLASSIFIERS,
    "CA": CANADA_CLASSIFIERS,
    "GB": UK_CLASSIFIERS,
    "UK": UK_CLASSIFIERS,
    "CH": SWITZERLAND_CLASSIFIERS,
    "TR": TURKEY_CLASSIFIERS,
    "ZA": SOUTH_AFRICA_CLASSIFIERS,
    "NG": NIGERIA_CLASSIFIERS,
    "KE": KENYA_CLASSIFIERS,
    "AE": UAE_CLASSIFIERS,
    "SA": SAUDI_CLASSIFIERS,
    "QA": QATAR_CLASSIFIERS,
    "MX": MEXICO_CLASSIFIERS,
    "AR": ARGENTINA_CLASSIFIERS,
    "CL": CHILE_CLASSIFIERS,
    "CO": COLOMBIA_CLASSIFIERS,
}

# EU maps to member/European classifiers + universal passport/IBAN/card patterns
COUNTRY_EXPANSION: Dict[str, List[str]] = {
    "EU": ["GB", "CH"],
    "UK": ["GB"],
}

GLOBAL_CLASSIFIERS: List[PIIClassifierDefinition] = []
_seen_identifiers = set()
for c_list in PII_CLASSIFIERS.values():
    for item in c_list:
        if item.identifier not in _seen_identifiers:
            GLOBAL_CLASSIFIERS.append(item)
            _seen_identifiers.add(item.identifier)


class PIIClassifierRegistry:
    """Evaluates text streams with multi-layer false-positive controls."""

    def __init__(self) -> None:
        self._compiled: List[Dict[str, Any]] = []
        for defn in GLOBAL_CLASSIFIERS:
            try:
                regex = re.compile(defn.pattern, re.IGNORECASE)
                self._compiled.append({"def": defn, "regex": regex})
            except Exception:
                pass

    def list_all(self) -> List[PIIClassifierDefinition]:
        return list(GLOBAL_CLASSIFIERS)

    def get_by_country(self, country_code: str) -> List[PIIClassifierDefinition]:
        code = (country_code or "").strip().upper()
        if code in PII_CLASSIFIERS:
            return list(PII_CLASSIFIERS[code])
        if code in COUNTRY_EXPANSION:
            merged: List[PIIClassifierDefinition] = []
            for sub in COUNTRY_EXPANSION[code]:
                merged.extend(PII_CLASSIFIERS.get(sub, []))
            return merged
        return [c for c in GLOBAL_CLASSIFIERS if c.country_code.upper() == code]

    def scan_text(self, text: str, country_filter: Optional[str] = None) -> List[PIIDetectionResult]:
        """
        Scans input string for sensitive national PII identifiers.
        Enforces false-positive protection:
        1. Regex boundary & structure validation
        2. Mathematical checksum validation where applicable (rejects invalid check digits)
        3. Negative operational context suppression (invoices, orders, timestamps, ports, byte counts)
        4. Keyword proximity requirement for non-checksum patterns and bare unformatted digit strings
        """
        if not text:
            return []

        results: List[PIIDetectionResult] = []
        lower_text = text.lower()
        filter_upper = country_filter.strip().upper() if country_filter else None

        for item in self._compiled:
            defn: PIIClassifierDefinition = item["def"]
            if filter_upper:
                allowed_codes = {filter_upper} | set(COUNTRY_EXPANSION.get(filter_upper, []))
                if defn.country_code not in allowed_codes:
                    continue

            for match in item["regex"].finditer(text):
                raw_match = match.group(0)
                start_idx = match.start()
                end_idx = match.end()

                # Boundary guard: avoid matching inside longer alphanumeric tokens
                if start_idx > 0 and text[start_idx - 1].isalnum():
                    continue
                if end_idx < len(text) and text[end_idx].isalnum():
                    continue

                window_start = max(0, start_idx - 100)
                window_end = min(len(text), end_idx + 100)
                surrounding = lower_text[window_start:window_end]

                matched_kw = None
                for kw in defn.keywords:
                    if kw.lower() in surrounding:
                        matched_kw = kw
                        break

                has_negative_ctx = any(neg in surrounding for neg in NEGATIVE_CONTEXT_KEYWORDS)

                # Checksum verification
                has_checksum = bool(defn.checksum_validator and defn.checksum_validator in CHECKSUM_MAP)
                checksum_passed = False
                if has_checksum:
                    validator_func = CHECKSUM_MAP[defn.checksum_validator]  # type: ignore
                    try:
                        checksum_passed = validator_func(raw_match)
                    except Exception:
                        checksum_passed = False
                    if not checksum_passed:
                        continue
                else:
                    checksum_passed = True

                # Non-checksum patterns ALWAYS require positive context keyword proximity
                if not has_checksum and not matched_kw:
                    continue

                # False-positive suppression for operational numbers (e.g., "Invoice ref 130692544")
                is_bare_digits = raw_match.isdigit()
                if has_negative_ctx and not matched_kw:
                    continue

                # Bare unformatted 8-13 digit integers in global unscoped scans require context
                # (prevents random 9-digit numbers from matching Canadian SIN / TFNs without context)
                if not filter_upper and is_bare_digits and len(raw_match) <= 13 and not matched_kw:
                    continue

                # Confidence assignment
                if has_checksum and checksum_passed and matched_kw:
                    confidence = "HIGH"
                elif has_checksum and checksum_passed:
                    confidence = "MEDIUM"
                elif matched_kw:
                    confidence = "HIGH" if (not is_bare_digits or len(raw_match) >= 10) else "MEDIUM"
                else:
                    confidence = "LOW"

                # Mask raw PII so raw values are never persisted or exposed
                if len(raw_match) > 4:
                    masked = raw_match[:2] + ("*" * (len(raw_match) - 4)) + raw_match[-2:]
                else:
                    masked = "****"

                results.append(
                    PIIDetectionResult(
                        identifier=defn.identifier,
                        country_code=defn.country_code,
                        category=defn.category,
                        sample_masked=masked,
                        confidence=confidence,
                        severity=defn.severity,
                        matched_keyword=matched_kw,
                        checksum_passed=checksum_passed,
                        position=start_idx,
                    )
                )

        return results


pii_classifier_registry = PIIClassifierRegistry()

__all__ = [
    "PIIClassifierDefinition",
    "PIIDetectionResult",
    "PII_CLASSIFIERS",
    "GLOBAL_CLASSIFIERS",
    "CHECKSUM_MAP",
    "PIIClassifierRegistry",
    "pii_classifier_registry",
]
