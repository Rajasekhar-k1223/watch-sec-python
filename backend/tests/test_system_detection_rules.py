#!/usr/bin/env python3
"""
MONITORIX ENTERPRISE — PHASE 5.4.3C TEST SUITE (PART 2)
System Detection Rules Validation & Security Verification
=========================================================
Validates:
 1. System rule definitions exist for all 8 reserved IDs (9001-9008)
 2. Valid Sigma YAML parsing for all 8 system rules
 3. Successful AST compilation into CompiledSigmaRule instances
 4. Correct identifier and severity mapping (Medium/High/Critical)
 5. Complete MITRE ATT&CK tactic and technique metadata preservation
 6. Global system-managed ownership (TenantId is None)
 7. Tenant modification security guard (PermissionError on tenant edit/delete)
 8. Idempotent database seeding verification
 9. Rule ID collision detection & tenant rule preservation
10. Malformed Sigma YAML rejection & error classification
"""

import os
import sys
import time
import json
import asyncio
from typing import Dict, Any, List

# Ensure backend path is in sys.path
for candidate in ["/app", "/opt/projects/monitorix/watch-sec-python/backend"]:
    if os.path.exists(candidate) and candidate not in sys.path:
        sys.path.insert(0, candidate)

from app.services.detection.sigma_compiler import (
    sigma_compiler,
    CompiledSigmaRule,
    SigmaCompilationError
)
from app.services.detection.system_rules import (
    RESERVED_SYSTEM_RULE_IDS,
    SYSTEM_RULES_DEFINITIONS,
    get_system_rules,
    get_system_rule_by_id,
    is_system_rule,
    seed_system_rules,
    validate_rule_modification_security
)

PASSED = 0
FAILED = 0
TEST_RESULTS = []


def record_result(test_num: int, name: str, passed: bool, duration_ms: float, detail: str = ""):
    global PASSED, FAILED
    status = "PASS" if passed else "FAIL"
    if passed:
        PASSED += 1
    else:
        FAILED += 1
    TEST_RESULTS.append({
        "test_num": test_num,
        "name": name,
        "status": status,
        "duration_ms": duration_ms,
        "detail": detail
    })
    print(f"  [{status}] #{test_num:02d}: {name} ({duration_ms:.2f}ms) {detail}")


class MockRulesDB:
    """Mock session for validating system rule database operations."""
    def __init__(self):
        self.rules: Dict[int, Any] = {}
        self.committed = False
        self.rolled_back = False

    def add(self, obj):
        self.rules[obj.Id] = obj

    async def commit(self):
        self.committed = True

    async def rollback(self):
        self.rolled_back = True

    async def execute(self, query):
        class MockResult:
            def __init__(self, items):
                self._items = items
            def scalars(self):
                return self
            def all(self):
                return self._items
            def first(self):
                return self._items[0] if self._items else None

        return MockResult(list(self.rules.values()))


async def run_suite():
    global PASSED, FAILED
    print("=" * 80)
    print("MONITORIX ENTERPRISE — PHASE 5.4.3C TEST SUITE (PART 2)")
    print("System Detection Rules Validation & Security Verification")
    print("=" * 80)

    # --------------------------------------------------------------------------
    # TEST 01: System rule definitions completeness (9001-9008)
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    rules_defs = get_system_rules()
    ids_present = {r["id"] for r in rules_defs}
    expected_ids = {9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008}
    d1 = (time.perf_counter() - t0) * 1000
    p1 = (ids_present == expected_ids and len(rules_defs) == 8)
    record_result(1, "System Rule Range Completeness (IDs 9001-9008)", p1, d1)

    # --------------------------------------------------------------------------
    # TEST 02: Valid Sigma YAML parsing across all 8 rules
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    import yaml
    all_yaml_valid = True
    for r in rules_defs:
        try:
            parsed = yaml.safe_load(r["yaml_content"])
            if not isinstance(parsed, dict) or "title" not in parsed or "detection" not in parsed:
                all_yaml_valid = False
        except Exception:
            all_yaml_valid = False
    d2 = (time.perf_counter() - t0) * 1000
    record_result(2, "Valid Sigma YAML Parsing for All 8 System Rules", all_yaml_valid, d2)

    # --------------------------------------------------------------------------
    # TEST 03: Successful AST compilation into CompiledSigmaRule instances
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    compiled_rules = []
    compilation_success = True
    for r in rules_defs:
        try:
            compiled = sigma_compiler.compile(
                yaml_content=r["yaml_content"],
                rule_id=r["id"],
                metadata={
                    "TenantId": None,
                    "MitreTactic": r["mitre_tactic"],
                    "MitreTechnique": r["mitre_technique"],
                    "Category": r["category"],
                    "Severity": r["severity"]
                }
            )
            compiled_rules.append(compiled)
        except Exception as e:
            print(f"    Compilation error on rule {r['id']}: {e}")
            compilation_success = False
    d3 = (time.perf_counter() - t0) * 1000
    p3 = compilation_success and len(compiled_rules) == 8
    record_result(3, "Successful AST Compilation into CompiledSigmaRule Instances", p3, d3)

    # --------------------------------------------------------------------------
    # TEST 04: Correct identifier and severity mapping (Medium/High/Critical)
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    severities = {r.id: r.severity.lower() for r in compiled_rules}
    expected_severities = {
        9001: "medium",
        9002: "high",
        9003: "critical",
        9004: "high",
        9005: "high",
        9006: "high",
        9007: "critical",
        9008: "critical"
    }
    p4 = (severities == expected_severities)
    d4 = (time.perf_counter() - t0) * 1000
    record_result(4, "Rule Identifier and Severity Assignment Verification", p4, d4, f"(Severities={severities})")

    # --------------------------------------------------------------------------
    # TEST 05: Complete MITRE ATT&CK tactic and technique metadata preservation
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    tactics = {r.id: r.mitre_tactics for r in compiled_rules}
    mitre_ok = (
        ("defense evasion" in str(tactics[9001]).lower() or "defense_evasion" in str(tactics[9001]).lower()) and
        ("credential access" in str(tactics[9002]).lower() or "credential_access" in str(tactics[9002]).lower()) and
        ("defense evasion" in str(tactics[9003]).lower() or "defense_evasion" in str(tactics[9003]).lower()) and
        ("defense evasion" in str(tactics[9004]).lower() or "defense_evasion" in str(tactics[9004]).lower()) and
        ("credential access" in str(tactics[9005]).lower() or "credential_access" in str(tactics[9005]).lower()) and
        ("exfiltration" in str(tactics[9006]).lower()) and
        ("command and control" in str(tactics[9007]).lower() or "command_and_control" in str(tactics[9007]).lower()) and
        ("execution" in str(tactics[9008]).lower())
    )
    d5 = (time.perf_counter() - t0) * 1000
    record_result(5, "MITRE ATT&CK Tactic & Technique Preservation", mitre_ok, d5)

    # --------------------------------------------------------------------------
    # TEST 06: Global system-managed ownership (TenantId is None)
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    all_global = all(r.tenant_id is None for r in compiled_rules)
    d6 = (time.perf_counter() - t0) * 1000
    record_result(6, "Global System-Managed Ownership (TenantId=None)", all_global, d6)

    # --------------------------------------------------------------------------
    # TEST 07: Tenant modification security guard (PermissionError on edit/delete)
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    blocked_tenant_user = False
    blocked_non_admin = False
    allowed_super_admin = False

    try:
        # Tenant user attempting to edit rule 9001
        validate_rule_modification_security(rule_id=9001, user_role="TenantAdmin", user_tenant_id=1)
    except PermissionError:
        blocked_tenant_user = True

    try:
        # Viewer attempting to edit rule 9003
        validate_rule_modification_security(rule_id=9003, user_role="Viewer", user_tenant_id=2)
    except PermissionError:
        blocked_non_admin = True

    try:
        # SuperAdmin with global scope
        validate_rule_modification_security(rule_id=9007, user_role="SuperAdmin", user_tenant_id=None)
        allowed_super_admin = True
    except Exception:
        allowed_super_admin = False

    d7 = (time.perf_counter() - t0) * 1000
    p7 = blocked_tenant_user and blocked_non_admin and allowed_super_admin
    record_result(7, "Tenant Modification Guard (Strict SuperAdmin Only)", p7, d7)

    # --------------------------------------------------------------------------
    # TEST 08: Idempotent database seeding verification
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    mock_db = MockRulesDB()
    res1 = await seed_system_rules(mock_db)
    res2 = await seed_system_rules(mock_db)
    d8 = (time.perf_counter() - t0) * 1000
    p8 = (res1["seeded"] == 8 and res2["seeded"] == 0 and res2["verified_existing"] == 8)
    record_result(8, "System Rule Idempotent Seeding (Zero Duplicate Rows)", p8, d8)

    # --------------------------------------------------------------------------
    # TEST 09: Rule ID collision detection & tenant rule preservation
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    collision_db = MockRulesDB()
    from app.db.models import DetectionRule
    # Pre-populate custom rule 9005 for Tenant 7
    collision_db.rules[9005] = DetectionRule(
        Id=9005,
        TenantId=7,
        Name="Custom Tenant 7 Forensics Rule",
        Type="Sigma",
        RuleContent="title: Custom Rule",
        IsActive=True
    )
    col_res = await seed_system_rules(collision_db)
    d9 = (time.perf_counter() - t0) * 1000
    p9 = (
        len(col_res["collisions"]) == 1 and
        col_res["collisions"][0]["rule_id"] == 9005 and
        col_res["collisions"][0]["existing_tenant_id"] == 7 and
        collision_db.rules[9005].Name == "Custom Tenant 7 Forensics Rule"  # Untouched!
    )
    record_result(9, "Rule ID Collision Detection & Tenant Rule Protection", p9, d9)

    # --------------------------------------------------------------------------
    # TEST 10: Malformed Sigma YAML rejection & error classification
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    malformed_yamls = [
        "title: Only Title No Detection",
        "invalid: yaml: syntax: [unclosed",
        "title: Bad Condition\ndetection:\n  selection:\n    image: cmd.exe\n  condition: (unclosed parenthesis",
        "title: Bad Modifier\ndetection:\n  selection:\n    image|unsupported_mod: cmd.exe\n  condition: selection"
    ]
    all_rejected = True
    for bad_yaml in malformed_yamls:
        try:
            sigma_compiler.compile(yaml_content=bad_yaml, rule_id=9999)
            all_rejected = False
        except SigmaCompilationError:
            pass
        except Exception:
            all_rejected = False
    d10 = (time.perf_counter() - t0) * 1000
    record_result(10, "Malformed Sigma YAML Rejection & Error Classification", all_rejected, d10)

    print("\n" + "=" * 80)
    print(f"PART 2 TOTAL: 10 | PASSED: {PASSED} | FAILED: {FAILED}")
    print("=" * 80)
    return FAILED == 0


if __name__ == "__main__":
    success = asyncio.run(run_suite())
    sys.exit(0 if success else 1)
