#!/usr/bin/env python3
"""
Comprehensive Unit & Integration Test Suite: 25-Country National PII Classifiers
Tests across all 25 statutory jurisdictions:
1. Valid national IDs (mathematical checksums + context keywords -> HIGH confidence).
2. Invalid checksum / malformed national IDs (rejected or downgraded).
3. False-positive suppression on bare operational numbers (invoice, order_id, timestamp, build #).
4. Token boundary protection (embedded digits inside long hex/numeric hashes do not match).
5. Integration with Monitorix DLPEngine (`dlp_engine.py`) and DSPMService (`dspm_service.py`).
"""
import os
import sys
import unittest

BACKEND_DIR = "/app" if os.path.exists("/app/app/compliance") else "/opt/projects/monitorix/watch-sec-python/backend"
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.compliance.classifiers import pii_classifier_registry
from app.compliance.classifiers.checksums import (
    validate_argentina_cuit,
    validate_australia_tfn,
    validate_brazil_cnpj,
    validate_brazil_cpf,
    validate_canada_sin,
    validate_chile_rut,
    validate_china_ric,
    validate_japan_my_number,
    validate_korea_rrn,
    validate_mexico_curp,
    validate_nz_ird,
    validate_saudi_id,
    validate_singapore_nric,
    validate_south_africa_id,
    validate_swiss_ahv,
    validate_thailand_id,
    validate_turkey_tc_kimlik,
    validate_uae_emirates_id,
    validate_uk_nhs,
    validate_verhoeff,
)
from app.services.dlp_engine import DlpEngine
from app.services.dspm_service import MonitorixDspmService


def _find_valid(prefix: str, total_len: int, fn) -> str:
    """Finds the check digit(s) satisfying a mathematical validator for deterministic test vectors."""
    rem = total_len - len(prefix)
    for n in range(10**rem):
        cand = prefix + str(n).zfill(rem)
        if fn(cand):
            return cand
    raise RuntimeError(f"Could not construct valid vector for {prefix}")


class TestCompliance25CountryClassifiers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.valid_aadhaar = _find_valid("23412341234", 12, validate_verhoeff)
        cls.valid_cpf = _find_valid("529982247", 11, validate_brazil_cpf)
        cls.valid_cnpj = _find_valid("112223330001", 14, validate_brazil_cnpj)
        cls.valid_china_ric = _find_valid("11010519900307123", 18, validate_china_ric)
        cls.valid_jp_mynum = _find_valid("12345678901", 12, validate_japan_my_number)
        cls.valid_kr_rrn = _find_valid("900101123456", 13, validate_korea_rrn)
        cls.valid_th_id = _find_valid("110070012345", 13, validate_thailand_id)
        cls.valid_au_tfn = _find_valid("87654321", 9, validate_australia_tfn)
        cls.valid_nz_ird = _find_valid("4909185", 8, validate_nz_ird)
        cls.valid_ca_sin = _find_valid("46454286", 9, validate_canada_sin)
        cls.valid_uk_nhs = _find_valid("943476591", 10, validate_uk_nhs)
        cls.valid_ch_ahv = _find_valid("756123456789", 13, validate_swiss_ahv)
        cls.valid_tr_tckn = _find_valid("100000001", 11, validate_turkey_tc_kimlik)
        cls.valid_za_id = _find_valid("800101500908", 13, validate_south_africa_id)
        cls.valid_ae_id = _find_valid("78419841234567", 15, validate_uae_emirates_id)
        cls.valid_sa_id = _find_valid("101234567", 10, validate_saudi_id)
        cls.valid_ar_cuit = _find_valid("2012345678", 11, validate_argentina_cuit)
        # Singapore NRIC check letter
        cls.valid_sg_nric = next(
            f"S1234567{ch}" for ch in "JZIHGFEDCBA" if validate_singapore_nric(f"S1234567{ch}")
        )
        # Chile RUT check digit
        cls.valid_cl_rut = next(
            f"12345678-{ch}" for ch in "0123456789K" if validate_chile_rut(f"12345678-{ch}")
        )
        # Mexico CURP check digit
        cls.valid_mx_curp = next(
            f"GODE561231HGRMRN0{d}" for d in "0123456789" if validate_mexico_curp(f"GODE561231HGRMRN0{d}")
        )

    def _flip_last_char(self, val: str) -> str:
        last = val[-1]
        if last.isdigit():
            return val[:-1] + str((int(last) + 1) % 10)
        return val[:-1] + ("A" if last.upper() != "A" else "B")

    def test_01_all_25_countries_registered(self):
        expected_25 = {
            "IN", "US", "BR", "CN", "JP", "KR", "SG", "TH", "ID", "AU",
            "NZ", "CA", "GB", "CH", "TR", "ZA", "NG", "KE", "AE", "SA",
            "QA", "MX", "AR", "CL", "CO",
        }
        registered = {c.country_code for c in pii_classifier_registry.list_all()}
        self.assertTrue(expected_25.issubset(registered), f"Missing countries: {expected_25 - registered}")

    def test_02_valid_and_invalid_across_all_25_countries(self):
        ahv_fmt = f"{self.valid_ch_ahv[:3]}.{self.valid_ch_ahv[3:7]}.{self.valid_ch_ahv[7:11]}.{self.valid_ch_ahv[11:]}"
        ae_fmt = f"784-{self.valid_ae_id[3:7]}-{self.valid_ae_id[7:14]}-{self.valid_ae_id[14]}"
        cuit_fmt = f"{self.valid_ar_cuit[:2]}-{self.valid_ar_cuit[2:10]}-{self.valid_ar_cuit[10]}"

        cases = [
            ("IN", "INDIA_AADHAAR", f"Aadhaar card: {self.valid_aadhaar}", f"Aadhaar card: {self._flip_last_char(self.valid_aadhaar)}", True),
            ("IN", "INDIA_PAN", "Income Tax PAN: ABCDE1234F", "Income Tax PAN: ABCDE12345", False),
            ("US", "US_SSN", "Employee SSN: 123-45-6789", "Employee SSN: 000-00-0000", False),
            ("BR", "BRAZIL_CPF", f"Cadastro CPF: {self.valid_cpf}", f"Cadastro CPF: {self._flip_last_char(self.valid_cpf)}", True),
            ("CN", "CHINA_RESIDENT_ID", f"Resident ID shenfenzheng: {self.valid_china_ric}", f"Resident ID: {self._flip_last_char(self.valid_china_ric)}", True),
            ("JP", "JAPAN_MY_NUMBER", f"My Number kojin bango: {self.valid_jp_mynum}", f"My Number: {self._flip_last_char(self.valid_jp_mynum)}", True),
            ("KR", "KOREA_RRN", f"Resident RRN jumin: {self.valid_kr_rrn[:6]}-{self.valid_kr_rrn[6:]}", f"Resident RRN: {self.valid_kr_rrn[:6]}-{self._flip_last_char(self.valid_kr_rrn[6:])}", True),
            ("SG", "SINGAPORE_NRIC_FIN", f"Citizen NRIC: {self.valid_sg_nric}", f"Citizen NRIC: {self._flip_last_char(self.valid_sg_nric)}", True),
            ("TH", "THAILAND_NATIONAL_ID", f"Thai ID card: {self.valid_th_id}", f"Thai ID card: {self._flip_last_char(self.valid_th_id)}", True),
            ("ID", "INDONESIA_NIK", "KTP NIK: 3171234567890001", "KTP NIK: 317123", False),
            ("AU", "AUSTRALIA_TFN", f"Tax File Number TFN: {self.valid_au_tfn}", f"TFN: {self._flip_last_char(self.valid_au_tfn)}", True),
            ("NZ", "NZ_IRD", f"Inland Revenue IRD: {self.valid_nz_ird}", f"IRD: {self._flip_last_char(self.valid_nz_ird)}", True),
            ("CA", "CANADA_SIN", f"Social Insurance SIN: {self.valid_ca_sin}", f"SIN: {self._flip_last_char(self.valid_ca_sin)}", True),
            ("GB", "UK_NHS", f"Patient NHS number: {self.valid_uk_nhs}", f"Patient NHS: {self._flip_last_char(self.valid_uk_nhs)}", True),
            ("GB", "UK_NINO", "National Insurance NINO: AB123456C", "National Insurance NINO: QQ123456Z", False),
            ("CH", "SWISS_AHV_AVS", f"Swiss AHV AVS: {ahv_fmt}", f"Swiss AHV: {self._flip_last_char(ahv_fmt)}", True),
            ("TR", "TURKEY_TC_KIMLIK", f"TC Kimlik No: {self.valid_tr_tckn}", f"TC Kimlik No: {self._flip_last_char(self.valid_tr_tckn)}", True),
            ("ZA", "SOUTH_AFRICA_ID", f"South Africa ID number: {self.valid_za_id}", f"SA ID: {self._flip_last_char(self.valid_za_id)}", True),
            ("NG", "NIGERIA_NIN", "NIMC NIN: 12345678901", "NIMC NIN: 12345", False),
            ("KE", "KENYA_KRA_PIN", "Kenya KRA PIN: A123456789B", "Kenya KRA PIN: Z1234567899", False),
            ("AE", "UAE_EMIRATES_ID", f"UAE Emirates ID: {ae_fmt}", f"UAE Emirates ID: {self._flip_last_char(ae_fmt)}", True),
            ("SA", "SAUDI_NATIONAL_ID", f"Saudi National ID hawiyah: {self.valid_sa_id}", f"Saudi ID: {self._flip_last_char(self.valid_sa_id)}", True),
            ("QA", "QATAR_QID", "Qatar QID number: 28412345678", "Qatar QID: 12345", False),
            ("MX", "MEXICO_CURP", f"Clave CURP: {self.valid_mx_curp}", "Clave CURP: 123456789012345678", False),
            ("AR", "ARGENTINA_CUIT_CUIL", f"AFIP CUIT: {cuit_fmt}", f"AFIP CUIT: {self._flip_last_char(cuit_fmt)}", True),
            ("CL", "CHILE_RUT_RUN", f"Chile RUT: {self.valid_cl_rut}", f"Chile RUT: {self._flip_last_char(self.valid_cl_rut)}", True),
            ("CO", "COLOMBIA_NIT", "DIAN NIT: 800197268-4", "DIAN NIT: 1234", False),
        ]

        for cc, expected_id, valid_txt, invalid_txt, has_checksum in cases:
            with self.subTest(country=cc, identifier=expected_id):
                pos = pii_classifier_registry.scan_text(valid_txt, country_filter=cc)
                self.assertTrue(
                    any(d.identifier == expected_id for d in pos),
                    f"Expected {expected_id} to match valid sample '{valid_txt}', got {[d.identifier for d in pos]}",
                )
                neg = pii_classifier_registry.scan_text(invalid_txt, country_filter=cc)
                if has_checksum:
                    self.assertFalse(
                        any(d.identifier == expected_id and d.checksum_passed for d in neg),
                        f"Expected invalid checksum sample '{invalid_txt}' to fail {expected_id}",
                    )
                else:
                    self.assertFalse(
                        any(d.identifier == expected_id for d in neg),
                        f"Expected malformed sample '{invalid_txt}' not to match {expected_id}",
                    )

    def test_03_false_positive_suppression_on_operational_numbers(self):
        benign_samples = [
            "Invoice ref 123456789 and order_id 987654321 processed in 45ms",
            "Packet timestamp 1730228400991 bytes 104857600 build # 2026102912",
            "Commit 8392019482910492819203948192039481290394 deployed cleanly",
        ]
        for txt in benign_samples:
            detections = pii_classifier_registry.scan_text(txt)
            high_fp = [d for d in detections if d.confidence_level == "HIGH"]
            self.assertEqual(
                len(high_fp),
                0,
                f"Unexpected HIGH-confidence false positive on benign text '{txt}': {high_fp}",
            )

    def test_04_boundary_protection_embedded_digits_rejected(self):
        embedded = f"SHA_NUMERIC_TOKEN_{self.valid_aadhaar}999888777666_END"
        detections = pii_classifier_registry.scan_text(embedded, country_filter="IN")
        self.assertFalse(any(d.identifier == "INDIA_AADHAAR" for d in detections))

    def test_05_dlp_engine_and_dspm_integration(self):
        sample = f"Confidential HR record — Aadhaar: {self.valid_aadhaar}, PAN: ABCDE1234F"
        dlp_hits = DlpEngine().scan_global_pii(sample, country="IN")
        self.assertGreaterEqual(len(dlp_hits), 2)

        dspm_res = MonitorixDspmService.classify_text_payload(sample)
        self.assertTrue(dspm_res.get("has_sensitive_data"))
        self.assertGreaterEqual(dspm_res.get("detections_count", 0), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
