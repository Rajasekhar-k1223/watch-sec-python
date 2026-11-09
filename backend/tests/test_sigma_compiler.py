#!/usr/bin/env python3
"""
MONITORIX ENTERPRISE — PHASE 5.4.3A
Comprehensive Sigma Compiler & Detection Evaluation Test Suite
==============================================================
Validates:
1. Valid Sigma YAML compilation
2. Invalid YAML syntax rejection
3. Missing mandatory fields rejection
4. Single selection evaluation
5. Multiple selection evaluation
6. AND conditions
7. OR conditions
8. NOT conditions
9. contains modifier
10. endswith modifier
11. startswith modifier
12. equals modifier (and glob wildcard)
13. exists modifier
14. Unsupported condition rejection
15. Malformed event handling
16. Rule cache invalidation
17. Tenant rule isolation
18. MITRE metadata preservation
Plus:
- Performance benchmarks: 10, 100, and 500 compiled rules
- Memory consumption profiling with tracemalloc
"""

import os
import sys
import time
import json
import tracemalloc
from typing import Dict, Any, List

# Ensure backend path is configured
for candidate in ["/app", "/opt/projects/monitorix/watch-sec-python/backend"]:
    if os.path.exists(candidate) and candidate not in sys.path:
        sys.path.insert(0, candidate)

from app.services.detection.sigma_compiler import (
    SigmaCompiler,
    SigmaRuleRegistry,
    SigmaCompilationError,
    CompiledSigmaRule,
    evaluate_event,
    evaluate_all,
)


def log_test(num: int, title: str, status: str, duration_ms: float, error: str = ""):
    stat_str = f"\033[92m[PASS]\033[0m" if status == "PASS" else f"\033[91m[FAIL]\033[0m"
    err_str = f" - Error: {error}" if error else ""
    print(f"  {stat_str} #{num:02d}: {title} ({duration_ms:.2f}ms){err_str}", flush=True)


def main():
    print("=" * 80)
    print("MONITORIX ENTERPRISE — PHASE 5.4.3A TEST SUITE")
    print("Native Sigma YAML Compiler & Detection Evaluation Foundation")
    print("=" * 80)

    compiler = SigmaCompiler()
    registry = SigmaRuleRegistry()
    results = []

    # --------------------------------------------------------------------------
    # Test 1: Valid Sigma YAML
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    try:
        yaml_valid = """
title: Test PowerShell Encoded Command
id: 5f2a8910-1c09-406a-a0f5-5727e1957077
status: experimental
description: Detects encoded PowerShell command lines
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - ' -enc '
      - ' -encodedcommand '
    Image|endswith: '\\powershell.exe'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
"""
        rule = compiler.compile(yaml_valid, rule_id=1)
        assert rule.id == 1
        assert rule.name == "Test PowerShell Encoded Command"
        assert rule.severity == "High"
        assert "selection" in rule.selections
        assert rule.mitre_tactic == "Execution"
        assert rule.mitre_technique == "T1059.001"
        dur = (time.perf_counter() - t0) * 1000
        log_test(1, "Valid Sigma YAML Compilation", "PASS", dur)
        results.append({"id": 1, "title": "Valid Sigma YAML", "status": "PASS", "duration_ms": dur})
    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        log_test(1, "Valid Sigma YAML Compilation", "FAIL", dur, str(e))
        results.append({"id": 1, "title": "Valid Sigma YAML", "status": "FAIL", "duration_ms": dur, "error": str(e)})

    # --------------------------------------------------------------------------
    # Test 2: Invalid YAML
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    try:
        yaml_invalid = """
title: Broken YAML
detection
  selection:
    CommandLine: 'something'
"""
        caught = False
        try:
            compiler.compile(yaml_invalid)
        except SigmaCompilationError as err:
            caught = True
            assert err.error_type == "YAMLParseError"
        assert caught, "Expected SigmaCompilationError on invalid YAML"
        dur = (time.perf_counter() - t0) * 1000
        log_test(2, "Invalid YAML Rejection", "PASS", dur)
        results.append({"id": 2, "title": "Invalid YAML", "status": "PASS", "duration_ms": dur})
    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        log_test(2, "Invalid YAML Rejection", "FAIL", dur, str(e))
        results.append({"id": 2, "title": "Invalid YAML", "status": "FAIL", "duration_ms": dur, "error": str(e)})

    # --------------------------------------------------------------------------
    # Test 3: Missing Mandatory Fields
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    try:
        # Missing title
        yaml_no_title = """
detection:
  selection:
    CommandLine: 'whoami'
  condition: selection
"""
        caught_title = False
        try:
            compiler.compile(yaml_no_title)
        except SigmaCompilationError as err:
            caught_title = True
            assert err.field == "title"

        # Missing condition
        yaml_no_condition = """
title: No Condition Rule
detection:
  selection:
    CommandLine: 'whoami'
"""
        caught_cond = False
        try:
            compiler.compile(yaml_no_condition)
        except SigmaCompilationError as err:
            caught_cond = True
            assert err.field == "condition"

        assert caught_title and caught_cond
        dur = (time.perf_counter() - t0) * 1000
        log_test(3, "Missing Mandatory Fields Rejection", "PASS", dur)
        results.append({"id": 3, "title": "Missing Mandatory Fields", "status": "PASS", "duration_ms": dur})
    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        log_test(3, "Missing Mandatory Fields Rejection", "FAIL", dur, str(e))
        results.append({"id": 3, "title": "Missing Mandatory Fields", "status": "FAIL", "duration_ms": dur, "error": str(e)})

    # --------------------------------------------------------------------------
    # Test 4: Single Selection Matching
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    try:
        yaml_single = """
title: Cmd Execution
detection:
  selection:
    Image|endswith: '\\cmd.exe'
  condition: selection
"""
        r_single = compiler.compile(yaml_single, rule_id=4)
        ev_pos = {"process_name": "C:\\Windows\\System32\\cmd.exe"}
        ev_neg = {"process_name": "C:\\Windows\\System32\\notepad.exe"}

        res_pos = evaluate_event(ev_pos, r_single)
        res_neg = evaluate_event(ev_neg, r_single)

        assert res_pos.matched is True
        assert "selection" in res_pos.matched_selections
        assert res_neg.matched is False

        dur = (time.perf_counter() - t0) * 1000
        log_test(4, "Single Selection Evaluation", "PASS", dur)
        results.append({"id": 4, "title": "Single Selection", "status": "PASS", "duration_ms": dur})
    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        log_test(4, "Single Selection Evaluation", "FAIL", dur, str(e))
        results.append({"id": 4, "title": "Single Selection", "status": "FAIL", "duration_ms": dur, "error": str(e)})

    # --------------------------------------------------------------------------
    # Test 5: Multiple Selections
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    try:
        yaml_multi = """
title: Recon or Tampering
detection:
  sel_recon:
    CommandLine|contains: 'whoami'
  sel_tamper:
    CommandLine|contains: 'netsh advfirewall'
  condition: sel_recon or sel_tamper
"""
        r_multi = compiler.compile(yaml_multi, rule_id=5)
        ev1 = {"cmdline": "whoami /priv"}
        ev2 = {"cmdline": "netsh advfirewall set allprofiles state off"}
        ev3 = {"cmdline": "dir C:\\"}

        assert evaluate_event(ev1, r_multi).matched is True
        assert evaluate_event(ev2, r_multi).matched is True
        assert evaluate_event(ev3, r_multi).matched is False

        dur = (time.perf_counter() - t0) * 1000
        log_test(5, "Multiple Selections Evaluation", "PASS", dur)
        results.append({"id": 5, "title": "Multiple Selections", "status": "PASS", "duration_ms": dur})
    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        log_test(5, "Multiple Selections Evaluation", "FAIL", dur, str(e))
        results.append({"id": 5, "title": "Multiple Selections", "status": "FAIL", "duration_ms": dur, "error": str(e)})

    # --------------------------------------------------------------------------
    # Test 6: AND Conditions
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    try:
        yaml_and = """
title: ProcDump on LSASS
detection:
  sel_proc:
    Image|endswith: 'procdump.exe'
  sel_target:
    CommandLine|contains: 'lsass'
  condition: sel_proc and sel_target
"""
        r_and = compiler.compile(yaml_and, rule_id=6)
        ev_both = {"process_name": "procdump.exe", "cmdline": "procdump.exe -ma lsass.exe out.dmp"}
        ev_proc_only = {"process_name": "procdump.exe", "cmdline": "procdump.exe -ma svchost.exe out.dmp"}
        ev_target_only = {"process_name": "taskmgr.exe", "cmdline": "taskmgr.exe lsass"}

        assert evaluate_event(ev_both, r_and).matched is True
        assert evaluate_event(ev_proc_only, r_and).matched is False
        assert evaluate_event(ev_target_only, r_and).matched is False

        dur = (time.perf_counter() - t0) * 1000
        log_test(6, "AND Conditions Evaluation", "PASS", dur)
        results.append({"id": 6, "title": "AND Conditions", "status": "PASS", "duration_ms": dur})
    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        log_test(6, "AND Conditions Evaluation", "FAIL", dur, str(e))
        results.append({"id": 6, "title": "AND Conditions", "status": "FAIL", "duration_ms": dur, "error": str(e)})

    # --------------------------------------------------------------------------
    # Test 7: OR Conditions
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    try:
        yaml_or = """
title: Remote Execution Utility
detection:
  sel_psexec:
    Image|endswith: 'psexec.exe'
  sel_wmic:
    Image|endswith: 'wmic.exe'
  condition: sel_psexec or sel_wmic
"""
        r_or = compiler.compile(yaml_or, rule_id=7)
        assert evaluate_event({"process_name": "C:\\Tools\\psexec.exe"}, r_or).matched is True
        assert evaluate_event({"process_name": "C:\\Windows\\System32\\wbem\\wmic.exe"}, r_or).matched is True
        assert evaluate_event({"process_name": "C:\\Windows\\System32\\calc.exe"}, r_or).matched is False

        dur = (time.perf_counter() - t0) * 1000
        log_test(7, "OR Conditions Evaluation", "PASS", dur)
        results.append({"id": 7, "title": "OR Conditions", "status": "PASS", "duration_ms": dur})
    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        log_test(7, "OR Conditions Evaluation", "FAIL", dur, str(e))
        results.append({"id": 7, "title": "OR Conditions", "status": "FAIL", "duration_ms": dur, "error": str(e)})

    # --------------------------------------------------------------------------
    # Test 8: NOT Conditions
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    try:
        yaml_not = """
title: Suspicious PowerShell with Filter
detection:
  selection:
    CommandLine|contains: 'powershell.exe'
  filter_admin:
    CommandLine|contains: 'HealthCheckScript.ps1'
  condition: selection and not filter_admin
"""
        r_not = compiler.compile(yaml_not, rule_id=8)
        ev_malicious = {"cmdline": "powershell.exe -w hidden -enc aXNzb2Z0..."}
        ev_benign = {"cmdline": "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\HealthCheckScript.ps1"}

        assert evaluate_event(ev_malicious, r_not).matched is True
        assert evaluate_event(ev_benign, r_not).matched is False

        dur = (time.perf_counter() - t0) * 1000
        log_test(8, "NOT Conditions & Filter Exclusion", "PASS", dur)
        results.append({"id": 8, "title": "NOT Conditions", "status": "PASS", "duration_ms": dur})
    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        log_test(8, "NOT Conditions & Filter Exclusion", "FAIL", dur, str(e))
        results.append({"id": 8, "title": "NOT Conditions", "status": "FAIL", "duration_ms": dur, "error": str(e)})

    # --------------------------------------------------------------------------
    # Test 9: contains Modifier (and contains|all)
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    try:
        yaml_contains = """
title: Contains Check
detection:
  sel_any:
    CommandLine|contains:
      - 'mimikatz'
      - 'sekurlsa'
  sel_all:
    CommandLine|contains|all:
      - 'vssadmin'
      - 'delete'
      - 'shadows'
  condition: sel_any or sel_all
"""
        r_c = compiler.compile(yaml_contains, rule_id=9)
        # Any matches on one keyword
        assert evaluate_event({"cmdline": "C:\\temp\\mimikatz.exe privilege::debug"}, r_c).matched is True
        assert evaluate_event({"cmdline": "invoke-mimikatz -dump"}, r_c).matched is True
        # All requires all three keywords
        assert evaluate_event({"cmdline": "vssadmin.exe delete shadows /all /quiet"}, r_c).matched is True
        assert evaluate_event({"cmdline": "vssadmin.exe list shadows"}, r_c).matched is False

        dur = (time.perf_counter() - t0) * 1000
        log_test(9, "contains & contains|all Modifiers", "PASS", dur)
        results.append({"id": 9, "title": "contains Modifier", "status": "PASS", "duration_ms": dur})
    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        log_test(9, "contains & contains|all Modifiers", "FAIL", dur, str(e))
        results.append({"id": 9, "title": "contains Modifier", "status": "FAIL", "duration_ms": dur, "error": str(e)})

    # --------------------------------------------------------------------------
    # Test 10: endswith Modifier
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    try:
        yaml_ends = """
title: Script Extension Execution
detection:
  selection:
    TargetFilename|endswith:
      - '.vbs'
      - '.js'
      - '.hta'
  condition: selection
"""
        r_ends = compiler.compile(yaml_ends, rule_id=10)
        assert evaluate_event({"file_path": "C:\\Users\\victim\\invoice.vbs"}, r_ends).matched is True
        assert evaluate_event({"file_path": "/var/tmp/payload.HTA"}, r_ends).matched is True  # case-insensitive
        assert evaluate_event({"file_path": "C:\\Windows\\notepad.exe"}, r_ends).matched is False

        dur = (time.perf_counter() - t0) * 1000
        log_test(10, "endswith Modifier", "PASS", dur)
        results.append({"id": 10, "title": "endswith Modifier", "status": "PASS", "duration_ms": dur})
    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        log_test(10, "endswith Modifier", "FAIL", dur, str(e))
        results.append({"id": 10, "title": "endswith Modifier", "status": "FAIL", "duration_ms": dur, "error": str(e)})

    # --------------------------------------------------------------------------
    # Test 11: startswith Modifier
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    try:
        yaml_starts = """
title: Temp Folder Execution
detection:
  selection:
    Image|startswith:
      - 'C:\\Windows\\Temp\\'
      - '/tmp/'
  condition: selection
"""
        r_starts = compiler.compile(yaml_starts, rule_id=11)
        assert evaluate_event({"process_name": "C:\\Windows\\Temp\\malware.exe"}, r_starts).matched is True
        assert evaluate_event({"process_name": "/tmp/dropper.sh"}, r_starts).matched is True
        assert evaluate_event({"process_name": "C:\\Program Files\\app.exe"}, r_starts).matched is False

        dur = (time.perf_counter() - t0) * 1000
        log_test(11, "startswith Modifier", "PASS", dur)
        results.append({"id": 11, "title": "startswith Modifier", "status": "PASS", "duration_ms": dur})
    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        log_test(11, "startswith Modifier", "FAIL", dur, str(e))
        results.append({"id": 11, "title": "startswith Modifier", "status": "FAIL", "duration_ms": dur, "error": str(e)})

    # --------------------------------------------------------------------------
    # Test 12: equals Modifier (and glob wildcard)
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    try:
        yaml_eq = """
title: Direct Process and Glob Match
detection:
  sel_exact:
    User|equals: 'NT AUTHORITY\\SYSTEM'
  sel_glob:
    TargetImage: '*\\lsass.exe'
  condition: sel_exact and sel_glob
"""
        r_eq = compiler.compile(yaml_eq, rule_id=12)
        ev_match = {
            "user": "NT AUTHORITY\\SYSTEM",
            "process_name": "C:\\Windows\\System32\\lsass.exe"
        }
        ev_wrong_user = {
            "user": "DOMAIN\\analyst",
            "process_name": "C:\\Windows\\System32\\lsass.exe"
        }

        assert evaluate_event(ev_match, r_eq).matched is True
        assert evaluate_event(ev_wrong_user, r_eq).matched is False

        dur = (time.perf_counter() - t0) * 1000
        log_test(12, "equals & Glob Wildcard Modifier", "PASS", dur)
        results.append({"id": 12, "title": "equals Modifier", "status": "PASS", "duration_ms": dur})
    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        log_test(12, "equals & Glob Wildcard Modifier", "FAIL", dur, str(e))
        results.append({"id": 12, "title": "equals Modifier", "status": "FAIL", "duration_ms": dur, "error": str(e)})

    # --------------------------------------------------------------------------
    # Test 13: exists Modifier
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    try:
        yaml_exists = """
title: Unparented Process or Missing Hashes
detection:
  sel_parent_missing:
    ParentImage|exists: false
  sel_sha_present:
    sha256|exists: true
  condition: sel_parent_missing and sel_sha_present
"""
        r_ex = compiler.compile(yaml_exists, rule_id=13)
        ev_match = {"sha256": "ed01ebfbc9eb5b...", "process_name": "orphan.exe"}
        ev_has_parent = {"sha256": "ed01ebfbc9eb5b...", "parent_process_name": "explorer.exe"}
        ev_no_sha = {"process_name": "orphan.exe"}

        assert evaluate_event(ev_match, r_ex).matched is True
        assert evaluate_event(ev_has_parent, r_ex).matched is False
        assert evaluate_event(ev_no_sha, r_ex).matched is False

        dur = (time.perf_counter() - t0) * 1000
        log_test(13, "exists Modifier", "PASS", dur)
        results.append({"id": 13, "title": "exists Modifier", "status": "PASS", "duration_ms": dur})
    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        log_test(13, "exists Modifier", "FAIL", dur, str(e))
        results.append({"id": 13, "title": "exists Modifier", "status": "FAIL", "duration_ms": dur, "error": str(e)})

    # --------------------------------------------------------------------------
    # Test 14: Unsupported Condition Rejection
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    try:
        # References non-existent selection
        yaml_bad_ref = """
title: Bad Reference
detection:
  selection_1:
    Image: 'calc.exe'
  condition: selection_1 and not imaginary_filter
"""
        caught_bad_ref = False
        try:
            compiler.compile(yaml_bad_ref)
        except SigmaCompilationError as e_ref:
            caught_bad_ref = True
            assert "imaginary_filter" in e_ref.message

        # Syntax error in condition
        yaml_bad_syntax = """
title: Bad Syntax
detection:
  selection_1:
    Image: 'calc.exe'
  condition: selection_1 and and
"""
        caught_bad_syn = False
        try:
            compiler.compile(yaml_bad_syntax)
        except SigmaCompilationError as e_syn:
            caught_bad_syn = True

        assert caught_bad_ref and caught_bad_syn
        dur = (time.perf_counter() - t0) * 1000
        log_test(14, "Unsupported Condition Rejection", "PASS", dur)
        results.append({"id": 14, "title": "Unsupported Condition Rejection", "status": "PASS", "duration_ms": dur})
    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        log_test(14, "Unsupported Condition Rejection", "FAIL", dur, str(e))
        results.append({"id": 14, "title": "Unsupported Condition Rejection", "status": "FAIL", "duration_ms": dur, "error": str(e)})

    # --------------------------------------------------------------------------
    # Test 15: Malformed Event Handling
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    try:
        rule_test = compiler.compile("""
title: Safe Event Test
detection:
  selection:
    CommandLine|contains: 'test'
  condition: selection
""")
        # Malformed inputs
        res_none = evaluate_event(None, rule_test)
        assert res_none.matched is False and res_none.evaluation_error is not None

        res_str = evaluate_event("not a dict", rule_test)
        assert res_str.matched is False and res_str.evaluation_error is not None

        res_int = evaluate_event(12345, rule_test)
        assert res_int.matched is False and res_int.evaluation_error is not None

        res_empty = evaluate_event({}, rule_test)
        assert res_empty.matched is False and res_empty.evaluation_error is None

        # Event with weird non-string values for string field
        res_weird = evaluate_event({"cmdline": 1234567}, rule_test)
        assert res_weird.matched is False

        dur = (time.perf_counter() - t0) * 1000
        log_test(15, "Malformed Event Safe Handling", "PASS", dur)
        results.append({"id": 15, "title": "Malformed Event Handling", "status": "PASS", "duration_ms": dur})
    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        log_test(15, "Malformed Event Safe Handling", "FAIL", dur, str(e))
        results.append({"id": 15, "title": "Malformed Event Handling", "status": "FAIL", "duration_ms": dur, "error": str(e)})

    # --------------------------------------------------------------------------
    # Test 16: Rule Cache Invalidation
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    try:
        registry.clear()
        yaml_v1 = """
title: Cache Test Rule
detection:
  selection:
    CommandLine|contains: 'v1_token'
  condition: selection
"""
        yaml_v2 = """
title: Cache Test Rule
detection:
  selection:
    CommandLine|contains: 'v2_token'
  condition: selection
"""
        r1 = registry.register_rule(yaml_v1, rule_id=999)
        assert registry.count() == 1
        h1 = r1.content_hash

        # Re-registering identical content must return cached rule
        r1_cached = registry.register_rule(yaml_v1, rule_id=999)
        assert r1_cached is r1, "Expected identical cached rule instance"

        # Registering modified content must recompile
        r2 = registry.register_rule(yaml_v2, rule_id=999)
        assert r2 is not r1, "Expected recompiled rule instance on content change"
        assert r2.content_hash != h1

        # Invalidate rule
        registry.invalidate_rule(999)
        assert registry.get_rule(999) is None
        assert registry.count() == 0

        dur = (time.perf_counter() - t0) * 1000
        log_test(16, "Rule Cache Invalidation & Hash Verification", "PASS", dur)
        results.append({"id": 16, "title": "Rule Cache Invalidation", "status": "PASS", "duration_ms": dur})
    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        log_test(16, "Rule Cache Invalidation & Hash Verification", "FAIL", dur, str(e))
        results.append({"id": 16, "title": "Rule Cache Invalidation", "status": "FAIL", "duration_ms": dur, "error": str(e)})

    # --------------------------------------------------------------------------
    # Test 17: Tenant Rule Isolation
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    try:
        yaml_rule = """
title: Tenant Scoped Rule
detection:
  selection:
    CommandLine|contains: 'secret_trigger'
  condition: selection
"""
        r_t1 = compiler.compile(yaml_rule, rule_id=101, metadata={"TenantId": 1})
        r_t2 = compiler.compile(yaml_rule, rule_id=102, metadata={"TenantId": 2})
        r_global = compiler.compile(yaml_rule, rule_id=103, metadata={"TenantId": None})

        event = {"cmdline": "echo secret_trigger"}

        # Authoritative Tenant 1 evaluation
        assert evaluate_event(event, r_t1, authoritative_tenant_id=1).matched is True
        assert evaluate_event(event, r_t2, authoritative_tenant_id=1).matched is False  # Tenant 2 rule blocked!
        assert evaluate_event(event, r_global, authoritative_tenant_id=1).matched is True  # Global allowed

        # Authoritative Tenant 2 evaluation
        assert evaluate_event(event, r_t1, authoritative_tenant_id=2).matched is False  # Tenant 1 rule blocked!
        assert evaluate_event(event, r_t2, authoritative_tenant_id=2).matched is True
        assert evaluate_event(event, r_global, authoritative_tenant_id=2).matched is True

        dur = (time.perf_counter() - t0) * 1000
        log_test(17, "Tenant Rule Isolation Guard", "PASS", dur)
        results.append({"id": 17, "title": "Tenant Rule Isolation", "status": "PASS", "duration_ms": dur})
    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        log_test(17, "Tenant Rule Isolation Guard", "FAIL", dur, str(e))
        results.append({"id": 17, "title": "Tenant Rule Isolation", "status": "FAIL", "duration_ms": dur, "error": str(e)})

    # --------------------------------------------------------------------------
    # Test 18: MITRE Metadata Preservation
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    try:
        yaml_mitre = """
title: Mimikatz Credential Access
detection:
  selection:
    CommandLine|contains: 'mimikatz'
  condition: selection
tags:
  - attack.credential_access
  - attack.t1003.001
"""
        r_mitre = compiler.compile(yaml_mitre, rule_id=18, metadata={
            "MitreTactic": "TA0006 (Credential Access)",
            "MitreTechnique": "T1003.001"
        })
        res = evaluate_event({"cmdline": "mimikatz.exe"}, r_mitre)
        assert res.matched is True
        assert "TA0006 (Credential Access)" in res.mitre_tactics
        assert "T1003.001" in res.mitre_techniques
        assert res.rule_name == "Mimikatz Credential Access"

        dur = (time.perf_counter() - t0) * 1000
        log_test(18, "MITRE Metadata Preservation in Results", "PASS", dur)
        results.append({"id": 18, "title": "MITRE Metadata Preservation", "status": "PASS", "duration_ms": dur})
    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        log_test(18, "MITRE Metadata Preservation in Results", "FAIL", dur, str(e))
        results.append({"id": 18, "title": "MITRE Metadata Preservation", "status": "FAIL", "duration_ms": dur, "error": str(e)})

    # --------------------------------------------------------------------------
    # PERFORMANCE BENCHMARKS (10, 100, 500 Rules)
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("PERFORMANCE BENCHMARKS & CACHE PROFILING")
    print("=" * 80)

    perf_data = {}
    sample_template = """
title: Synthetic Detection Rule #{idx}
id: syn-rule-{idx}
detection:
  sel_proc:
    Image|endswith:
      - 'proc_{idx}.exe'
      - 'agent_{idx}.bin'
  sel_cmd:
    CommandLine|contains:
      - 'param_{idx}'
      - 'flag_test'
  filter:
    User: 'service_account'
  condition: (sel_proc or sel_cmd) and not filter
level: high
tags:
  - attack.t1059.00{idx_mod}
"""
    test_event = {
        "process_name": "agent_42.bin",
        "cmdline": "agent_42.bin --flag_test --verbose",
        "user": "local_admin"
    }

    rule_counts = [10, 100, 500]
    for count in rule_counts:
        tracemalloc.start()
        t_comp_start = time.perf_counter()
        compiled_batch = []
        for i in range(count):
            rule_text = sample_template.format(idx=i, idx_mod=(i % 9) + 1)
            comp = compiler.compile(rule_text, rule_id=2000 + i)
            compiled_batch.append(comp)
        t_comp_total = (time.perf_counter() - t_comp_start) * 1000
        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        avg_comp_ms = t_comp_total / count

        # Evaluation Benchmark (1,000 evaluations across compiled rule set)
        iterations = 1000
        t_eval_start = time.perf_counter()
        matches_found = 0
        for _ in range(iterations):
            # Evaluate event against all rules in batch
            res_list = evaluate_all(test_event, compiled_batch)
            matches_found += len(res_list)
        t_eval_total = (time.perf_counter() - t_eval_start) * 1000

        # Latency per single rule evaluation (microseconds)
        total_evals = count * iterations
        latency_per_rule_us = (t_eval_total * 1000) / total_evals
        latency_per_event_batch_us = (t_eval_total * 1000) / iterations

        perf_data[f"rules_{count}"] = {
            "rule_count": count,
            "total_compilation_time_ms": round(t_comp_total, 2),
            "avg_compilation_time_per_rule_ms": round(avg_comp_ms, 3),
            "peak_memory_bytes": peak_mem,
            "peak_memory_kb": round(peak_mem / 1024, 2),
            "evaluations_executed": total_evals,
            "total_eval_time_ms": round(t_eval_total, 2),
            "latency_per_event_all_rules_us": round(latency_per_event_batch_us, 2),
            "latency_per_single_rule_eval_us": round(latency_per_rule_us, 3),
            "matches_detected": matches_found
        }

        print(f"  Count: {count:3d} Rules | Compile: {t_comp_total:6.2f}ms ({avg_comp_ms:.3f}ms/rule) | "
              f"Eval/Event: {latency_per_event_batch_us:7.2f}µs | Per-Rule: {latency_per_rule_us:.3f}µs | "
              f"Peak Mem: {peak_mem / 1024:.1f} KB")

    # Write results output file
    output_payload = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_tests": len(results),
        "passed": sum(1 for r in results if r["status"] == "PASS"),
        "failed": sum(1 for r in results if r["status"] == "FAIL"),
        "test_cases": results,
        "performance_benchmarks": perf_data
    }

    results_path = "/tmp/monitorix_phase5_4_3a_results.json"
    with open(results_path, "w") as f:
        json.dump(output_payload, f, indent=2)

    print("\n" + "=" * 80)
    print(f"TOTAL TESTS: {len(results)} | PASSED: {output_payload['passed']} | FAILED: {output_payload['failed']}")
    print(f"Results written to {results_path}")
    print("=" * 80)

    if output_payload["failed"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
