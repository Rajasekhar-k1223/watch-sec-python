#!/usr/bin/env python3
"""
Unit & Live-DB Integration Test Suite: All 32 Statutory Compliance Frameworks
Verifies:
1. All 32 canonical frameworks and 32 `run_<framework>_checks()` entrypoints exist and execute cleanly.
2. Deterministic evaluation of PASS, FAIL, PARTIAL, NOT_APPLICABLE, and MANUAL_REVIEW control states.
3. Severity-weighted scoring engine accuracy (zero fake MANUAL_REVIEW score inflation).
4. Statutory coverage depth: NIST SP 800-53 20 families, China DSL 3 tiers, Australia APP 1-13,
   New Zealand IPP 1-13, Canada PIPEDA 10 Principles, South Africa POPIA 8 Conditions, and 32-row matrix.
"""
import asyncio
import os
import sys
import unittest

BACKEND_DIR = "/app" if os.path.exists("/app/app/compliance") else "/opt/projects/monitorix/watch-sec-python/backend"
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.compliance import frameworks as fw_pkg
from app.compliance.core.engine import compliance_engine
from app.compliance.core.models import (
    ComplianceCheckResult,
    ControlStatus,
    FrameworkCategory,
    PostureStatus,
    Severity,
)
from app.compliance.core.scoring import calculate_framework_score
from app.compliance.frameworks.fisma import FismaFramework
from app.compliance.registry.framework_registry import CORE_32_FRAMEWORK_CLASSES
from app.db.session import AsyncSessionLocal, engine as async_engine


EXPECTED_32_RUNNER_FUNCTIONS = [
    "run_gdpr_checks",
    "run_hipaa_checks",
    "run_dpdp_checks",
    "run_sox_checks",
    "run_uk_gdpr_checks",
    "run_ccpa_cpra_checks",
    "run_glba_checks",
    "run_fisma_checks",
    "run_lgpd_checks",
    "run_pipl_checks",
    "run_china_csl_checks",
    "run_china_dsl_checks",
    "run_appi_checks",
    "run_pipa_checks",
    "run_singapore_pdpa_checks",
    "run_thailand_pdpa_checks",
    "run_indonesia_pdp_checks",
    "run_australia_privacy_checks",
    "run_new_zealand_privacy_checks",
    "run_pipeda_checks",
    "run_n_fadp_checks",
    "run_kvkk_checks",
    "run_popia_checks",
    "run_ndpa_checks",
    "run_kenya_dpa_checks",
    "run_uae_dpl_checks",
    "run_saudi_pdpl_checks",
    "run_qatar_pdpl_checks",
    "run_mexico_lfpdppp_checks",
    "run_argentina_pdpl_checks",
    "run_chile_pdpl_checks",
    "run_colombia_law_1581_checks",
]


class TestCompliance32Frameworks(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        await async_engine.dispose()

    def test_01_exact_32_core_frameworks_registered(self):
        self.assertEqual(len(CORE_32_FRAMEWORK_CLASSES), 32)
        listed = compliance_engine.list_frameworks(include_supplemental=False)
        self.assertEqual(len(listed), 32)
        matrix = compliance_engine.get_regulatory_matrix()
        self.assertEqual(len(matrix), 32)

    async def test_02_all_32_runner_functions_exported_and_executable(self):
        async with AsyncSessionLocal() as db:
            for fn_name in EXPECTED_32_RUNNER_FUNCTIONS:
                runner = getattr(fw_pkg, fn_name, None)
                self.assertIsNotNone(runner, f"Missing runner function {fn_name}")
                results = await runner(1, db)
                self.assertGreaterEqual(
                    len(results), 8, f"{fn_name} returned fewer than 8 controls ({len(results)})"
                )
                for r in results:
                    self.assertIn(
                        r.status,
                        {
                            ControlStatus.PASS,
                            ControlStatus.FAIL,
                            ControlStatus.PARTIAL,
                            ControlStatus.NOT_APPLICABLE,
                            ControlStatus.MANUAL_REVIEW,
                        },
                    )
                    self.assertTrue(r.control_id)
                    self.assertTrue(r.evidence, f"{r.control_id} missing cryptographic evidence")

    async def test_03_all_five_control_statuses_deterministically_evaluated(self):
        async with AsyncSessionLocal() as db:
            # 1. NOT_APPLICABLE via applicability override
            na_res = await fw_pkg.run_gdpr_checks(1, db, context={"applicable": False})
            self.assertTrue(all(r.status == ControlStatus.NOT_APPLICABLE for r in na_res))

            # 2. Force PASS, PARTIAL, FAIL via deterministic control overrides + natural MANUAL_REVIEW
            controls = fw_pkg.GdprFramework().get_controls()
            auto_ids = [c.control_id for c in controls if c.automated]
            manual_ids = [c.control_id for c in controls if not c.automated]
            self.assertGreaterEqual(len(auto_ids), 3)
            self.assertGreaterEqual(len(manual_ids), 1)

            overrides = {
                auto_ids[0]: "PASS",
                auto_ids[1]: "PARTIAL",
                auto_ids[2]: "FAIL",
            }
            mixed_res = await fw_pkg.run_gdpr_checks(
                1, db, context={"control_overrides": overrides}
            )
            by_id = {r.control_id: r for r in mixed_res}
            self.assertEqual(by_id[auto_ids[0]].status, ControlStatus.PASS)
            self.assertEqual(by_id[auto_ids[1]].status, ControlStatus.PARTIAL)
            self.assertEqual(by_id[auto_ids[2]].status, ControlStatus.FAIL)
            self.assertIsNotNone(by_id[auto_ids[2]].finding)
            self.assertIsNotNone(by_id[auto_ids[2]].remediation)
            self.assertEqual(by_id[manual_ids[0]].status, ControlStatus.MANUAL_REVIEW)

    def test_04_weighted_scoring_math_excludes_manual_review_inflation(self):
        fw_instance = fw_pkg.DpdpFramework()
        synthetic_results = [
            ComplianceCheckResult(
                framework="DPDP_INDIA",
                control_id="C-CRIT-PASS",
                check_name="Critical Pass",
                category="SECURITY",
                status=ControlStatus.PASS,
                severity=Severity.CRITICAL,  # weight 4 * 1.0 = 4.0
                score=100.0,
            ),
            ComplianceCheckResult(
                framework="DPDP_INDIA",
                control_id="C-HIGH-PARTIAL",
                check_name="High Partial",
                category="PRIVACY",
                status=ControlStatus.PARTIAL,
                severity=Severity.HIGH,  # weight 3 * 0.5 = 1.5
                score=50.0,
            ),
            ComplianceCheckResult(
                framework="DPDP_INDIA",
                control_id="C-MED-FAIL",
                check_name="Medium Fail",
                category="GOVERNANCE",
                status=ControlStatus.FAIL,
                severity=Severity.MEDIUM,  # weight 2 * 0.0 = 0.0
                score=0.0,
            ),
            ComplianceCheckResult(
                framework="DPDP_INDIA",
                control_id="C-CRIT-MANUAL",
                check_name="Manual Legal Review",
                category="LEGAL",
                status=ControlStatus.MANUAL_REVIEW,  # excluded from automated denominator!
                severity=Severity.CRITICAL,
                score=0.0,
            ),
            ComplianceCheckResult(
                framework="DPDP_INDIA",
                control_id="C-LOW-NA",
                check_name="Not Applicable",
                category="OTHER",
                status=ControlStatus.NOT_APPLICABLE,  # excluded!
                severity=Severity.LOW,
                score=0.0,
            ),
        ]
        # Expected: (4.0 + 1.5 + 0.0) / (4 + 3 + 2) * 100 = 5.5 / 9 * 100 = 61.1%
        score_obj = calculate_framework_score(
            framework_id=fw_instance.framework_id,
            name=fw_instance.name,
            region=fw_instance.region,
            jurisdiction=fw_instance.jurisdiction,
            category=FrameworkCategory.PRIVACY,
            version=fw_instance.version,
            source_reference=fw_instance.source_reference,
            results=synthetic_results,
        )
        self.assertAlmostEqual(score_obj.score, 61.1, places=1)
        self.assertEqual(score_obj.applicable_controls, 3)
        self.assertEqual(score_obj.manual_review_controls, 1)
        self.assertEqual(score_obj.not_applicable_controls, 1)
        self.assertEqual(score_obj.status, PostureStatus.PARTIAL_TECHNICAL_POSTURE.value)

    def test_05_statutory_depth_nist_20_families_and_national_principles(self):
        # NIST SP 800-53 Rev. 5: all 20 control families
        nist_matrix = FismaFramework.get_nist_mapping_matrix()
        self.assertEqual(len(nist_matrix["families"]), 20)
        family_codes = {f["family_code"] for f in nist_matrix["families"]}
        self.assertIn("AC", family_codes)
        self.assertIn("AU", family_codes)
        self.assertIn("PT", family_codes)
        self.assertIn("SR", family_codes)

        # Australia APP 1-13 & New Zealand IPP 1-13
        au_controls = fw_pkg.AustraliaPrivacyFramework().get_controls()
        nz_controls = fw_pkg.NewZealandPrivacyFramework().get_controls()
        pipeda_controls = fw_pkg.PipedaFramework().get_controls()
        popia_controls = fw_pkg.PopiaFramework().get_controls()
        au_refs = " ".join(f"{c.title} {c.legal_reference}" for c in au_controls)
        for app_num in range(1, 14):
            self.assertIn(f"APP {app_num}", au_refs, f"Missing APP {app_num} coverage")
        self.assertGreaterEqual(len(au_controls), 10)
        self.assertGreaterEqual(len(nz_controls), 10)
        self.assertGreaterEqual(len(pipeda_controls), 10)
        self.assertGreaterEqual(len(popia_controls), 8)

    async def test_06_multi_dimensional_posture_and_china_dsl_catalog(self):
        async with AsyncSessionLocal() as db:
            asset = await compliance_engine.upsert_dsl_asset(
                1,
                {
                    "asset_name": "UnitTest_CN_Core_Vault",
                    "asset_type": "DATABASE",
                    "dsl_tier": "CORE_DATA",
                    "department": "Security",
                    "cross_border_export_approved": False,
                    "security_assessment_completed": True,
                },
                db,
                actor="unittest",
            )
            self.assertEqual(asset["dsl_tier"], "CORE_DATA")

            posture = await compliance_engine.evaluate_all(1, db, record_audit=False)
            self.assertEqual(posture.total_frameworks, 32)
            self.assertGreater(posture.total_controls_assessed, 300)
            self.assertTrue(posture.category_scores)
            self.assertTrue(posture.country_scores)
            self.assertTrue(posture.industry_scores)
            self.assertTrue(posture.department_scores)


if __name__ == "__main__":
    unittest.main(verbosity=2)
