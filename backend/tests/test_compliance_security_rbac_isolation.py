#!/usr/bin/env python3
"""
Security, RBAC, Multi-Tenant Isolation, Export Integrity & Legal-Safety Suite
Runs against the live FastAPI Compliance API (`http://127.0.0.1:8000` inside container
or `http://127.0.0.1:8010` on host).
"""
import hashlib
import io
import json
import os
import sys
import unittest
import urllib.error
import urllib.request
import zipfile

BACKEND_DIR = "/app" if os.path.exists("/app/app/compliance") else "/opt/projects/monitorix/watch-sec-python/backend"
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from jose import jwt
from app.core.security import SECRET_KEY, ALGORITHM

API_BASE = os.environ.get(
    "COMPLIANCE_API_BASE",
    "http://127.0.0.1:8000/api/v2/compliance" if os.path.exists("/app/app/compliance") else "http://127.0.0.1:8010/api/v2/compliance",
)


def _mint_jwt(username: str, role: str, tenant_id: int) -> str:
    return jwt.encode(
        {"sub": username, "role": role, "tenantId": tenant_id},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def _http_call(method: str, path: str, token: str = None, payload: dict = None):
    url = f"{API_BASE}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


class TestComplianceSecurityRbacIsolation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.viewer_t1 = _mint_jwt("soc_viewer", "Viewer", 1)
        cls.auditor_t1 = _mint_jwt("external_auditor", "Auditor", 1)
        cls.admin_t1 = _mint_jwt("ciso_t1", "Admin", 1)
        cls.admin_t2 = _mint_jwt("ciso_t2", "Admin", 2)
        cls.super_admin = _mint_jwt("mssp_root", "SuperAdmin", 1)

    def test_01_invalid_jwt_rejected_with_401(self):
        status, _ = _http_call("GET", "/posture", token="tampered.invalid.jwt.token")
        self.assertEqual(status, 401)

    def test_02_rbac_readonly_viewer_and_auditor_enforced(self):
        # Viewer & Auditor CAN read posture, PII catalog, NIST mapping, and evidence
        for tok in (self.viewer_t1, self.auditor_t1):
            st_get, _ = _http_call("GET", "/frameworks", token=tok)
            self.assertEqual(st_get, 200)
            st_ev, _ = _http_call("GET", "/evidence", token=tok)
            self.assertEqual(st_ev, 200)

            # Viewer & Auditor CANNOT trigger scans, create DSRs, modify CCPA prefs, or register DSL assets
            st_scan, _ = _http_call("POST", "/frameworks/GDPR/run", token=tok)
            self.assertEqual(st_scan, 403)
            st_dsr, _ = _http_call(
                "POST",
                "/privacy-requests",
                token=tok,
                payload={
                    "data_subject_identifier": "blocked@example.com",
                    "right_type": "ACCESS",
                    "framework_id": "GDPR",
                },
            )
            self.assertEqual(st_dsr, 403)
            st_pref, _ = _http_call(
                "PUT",
                "/privacy-preferences",
                token=tok,
                payload={"do_not_sell_share": False},
            )
            self.assertEqual(st_pref, 403)
            st_dsl, _ = _http_call(
                "POST",
                "/dsl-assets",
                token=tok,
                payload={"asset_name": "Unauthorized", "dsl_tier": "CORE_DATA"},
            )
            self.assertEqual(st_dsl, 403)

    def test_03_cross_tenant_isolation_403_and_superadmin_access(self):
        # Admin of Tenant 1 requesting Tenant 2 posture -> 403 Forbidden
        st_cross, _ = _http_call("GET", "/posture?tenant_id=2", token=self.admin_t1)
        self.assertEqual(st_cross, 403)

        # SuperAdmin requesting Tenant 2 posture -> 200 OK
        st_super, raw_super = _http_call("GET", "/posture?tenant_id=2", token=self.super_admin)
        self.assertEqual(st_super, 200)
        self.assertEqual(json.loads(raw_super)["tenant_id"], 2)

        # Create DSR in Tenant 1 and verify it does NOT appear in Tenant 2 DSR queue
        st_create, raw_create = _http_call(
            "POST",
            "/privacy-requests",
            token=self.admin_t1,
            payload={
                "data_subject_identifier": "tenant1.isolated.user@corp.example",
                "right_type": "DELETE",
                "framework_id": "CCPA_CPRA",
            },
        )
        self.assertEqual(st_create, 200)
        created_req = json.loads(raw_create)["request"]
        t1_req_id = created_req["request_id"]

        # Verify PII masking on stored DSR subject identifier
        self.assertNotEqual(
            created_req["data_subject_identifier"],
            "tenant1.isolated.user@corp.example",
            "Raw subject email must be masked in DSR records!",
        )

        st_t2_list, raw_t2_list = _http_call("GET", "/privacy-requests", token=self.admin_t2)
        self.assertEqual(st_t2_list, 200)
        t2_ids = {r["request_id"] for r in json.loads(raw_t2_list).get("requests", [])}
        self.assertNotIn(t1_req_id, t2_ids, "Tenant 1 DSR leaked into Tenant 2!")

    def test_04_valid_pdf_1_4_and_signed_zip_evidence_bundle(self):
        st_pdf, pdf_bytes = _http_call("GET", "/reports/GDPR/export?format=pdf", token=self.admin_t1)
        self.assertEqual(st_pdf, 200)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"), "Exported PDF missing %PDF-1.4 header")
        self.assertIn(b"xref", pdf_bytes)
        self.assertTrue(pdf_bytes.strip().endswith(b"%%EOF"))

        st_zip, zip_bytes = _http_call("GET", "/evidence-packager?framework=GDPR", token=self.admin_t1)
        self.assertEqual(st_zip, 200)
        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
            names = set(zf.namelist())
            self.assertEqual(
                names,
                {
                    "assessment_report.json",
                    "controls_matrix.csv",
                    "executive_report.pdf",
                    "sha256_manifest.json",
                },
            )
            manifest = json.loads(zf.read("sha256_manifest.json"))
            for fname, expected_sha in manifest["files"].items():
                actual_sha = hashlib.sha256(zf.read(fname)).hexdigest()
                self.assertEqual(actual_sha, expected_sha, f"SHA-256 mismatch in ZIP bundle for {fname}")

    def test_05_10_sovereign_residency_zones_and_25_country_pii_catalog(self):
        st_res, raw_res = _http_call("GET", "/residency", token=self.admin_t1)
        self.assertEqual(st_res, 200)
        res_data = json.loads(raw_res)
        self.assertGreaterEqual(len(res_data.get("zones", [])), 10)

        st_pii, raw_pii = _http_call("GET", "/pii", token=self.admin_t1)
        self.assertEqual(st_pii, 200)
        pii_data = json.loads(raw_pii)
        self.assertGreaterEqual(pii_data.get("countries_count", 0), 25)

    def test_06_legal_safety_no_false_certification_claims(self):
        st_pos, raw_pos = _http_call("GET", "/posture", token=self.admin_t1)
        self.assertEqual(st_pos, 200)
        pos_data = json.loads(raw_pos)
        self.assertIn("legal", pos_data.get("legal_disclaimer", "").lower())
        forbidden_statuses = {"CERTIFIED", "LEGALLY_COMPLIANT", "100%_GUARANTEED_COMPLIANT"}
        for fw in pos_data.get("frameworks", []):
            self.assertNotIn(fw.get("status", "").upper(), forbidden_statuses)


if __name__ == "__main__":
    unittest.main(verbosity=2)

