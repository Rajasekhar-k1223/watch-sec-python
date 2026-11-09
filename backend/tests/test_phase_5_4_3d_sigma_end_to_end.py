#!/usr/bin/env python3
"""
MONITORIX ENTERPRISE — PHASE 5.4.3D TEST SUITE (2/6)
End-to-End Sigma Rule Detection & Negative Control Suite
======================================================
Validates all 8 Canonical Security Detection Scenarios:
  #01: Rule 9001 — Unauthorized VPN Interface / Suspicious PowerShell Execution
  #02: Rule 9002 — LSASS Memory Dump / Excessive Process Crash Dumps
  #03: Rule 9003 — Host Firewall Disabled / Shadow Copy Deletion
  #04: Rule 9004 — Critical System File Integrity Violation / Privilege Reconnaissance
  #05: Rule 9005 — Cleartext Network Credentials in PCAP Forensics
  #06: Rule 9006 — Sensitive Data Exfiltration via Webmail Session / Scheduled Task
  #07: Rule 9007 — Malicious C2 Communication / Threat Intelligence IOC Match
  #08: Rule 9008 — Monitorix Endpoint Detonation Sandbox Threat Prevented
  #09: Benign Negative Control Suite (Zero False Positives across all 8 Scenarios)
  #10: Sub-Millisecond AST Evaluation Latency Benchmark (< 0.1ms per rule)
"""

import os
import sys
import time
import json
import asyncio
from datetime import datetime
from typing import Dict, Any, List

# Ensure backend path is in sys.path
for candidate in ["/app", "/opt/projects/monitorix/watch-sec-python/backend"]:
    if os.path.exists(candidate) and candidate not in sys.path:
        sys.path.insert(0, candidate)

from app.services.detection.sigma_compiler import (
    sigma_compiler,
    evaluate_all,
    CompiledSigmaRule,
    DetectionResult
)
from app.services.detection.system_rules import SYSTEM_RULES_DEFINITIONS

PASSED = 0
FAILED = 0
TEST_RESULTS = []
COMPILED_RULES = {}


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


def run_suite():
    global PASSED, FAILED, COMPILED_RULES
    print("=" * 80)
    print("MONITORIX ENTERPRISE — PHASE 5.4.3D TEST SUITE (2/6)")
    print("End-to-End Sigma Rule Detection & Negative Control Validation")
    print("=" * 80)

    # Pre-compile all 8 system rules
    for r_def in SYSTEM_RULES_DEFINITIONS:
        compiled = sigma_compiler.compile(
            yaml_content=r_def["yaml_content"],
            rule_id=r_def["id"],
            metadata={
                "tenant_id": None,
                "category": r_def["category"],
                "mitre_tactic": r_def["mitre_tactic"],
                "mitre_technique": r_def["mitre_technique"]
            }
        )
        COMPILED_RULES[r_def["id"]] = compiled

    # -------------------------------------------------------------------------
    # TEST 1: Rule 9001 — Unauthorized VPN / Proxy Interface
    # -------------------------------------------------------------------------
    t0 = time.time()
    try:
        rule = COMPILED_RULES[9001]
        threat_ev = {
            "AgentId": "AG-01",
            "EventType": "network_interface",
            "vpn_active": True,
            "CommandLine": "openvpn --config corporate_bypass.ovpn"
        }
        matches = evaluate_all(threat_ev, [rule], authoritative_tenant_id=1)
        assert len(matches) == 1, "Rule 9001 failed to match threat event"
        m = matches[0]
        assert m.rule_id == 9001
        assert m.severity.lower() == "medium"
        assert "TA0005" in m.mitre_tactic or "Defense Evasion" in m.mitre_tactic
        dt = (time.time() - t0) * 1000
        record_result(1, "Rule 9001: Unauthorized VPN Interface Detected", True, dt, f"Severity={m.severity}")
    except Exception as e:
        record_result(1, "Rule 9001: Unauthorized VPN Interface Detected", False, (time.time() - t0) * 1000, str(e))

    # -------------------------------------------------------------------------
    # TEST 2: Rule 9002 — LSASS Dump / Excessive Process Crash Dumps
    # -------------------------------------------------------------------------
    t0 = time.time()
    try:
        rule = COMPILED_RULES[9002]
        threat_ev = {
            "AgentId": "AG-02",
            "EventType": "process_crash",
            "crash_dumps_count": 4,
            "target_process": "lsass.exe",
            "CommandLine": "procdump.exe -ma lsass.exe lsass.dmp"
        }
        matches = evaluate_all(threat_ev, [rule], authoritative_tenant_id=2)
        assert len(matches) == 1, "Rule 9002 failed to match threat event"
        m = matches[0]
        assert m.rule_id == 9002
        assert m.severity.lower() == "high"
        assert "TA0006" in m.mitre_tactic or "Credential Access" in m.mitre_tactic
        dt = (time.time() - t0) * 1000
        record_result(2, "Rule 9002: Excessive Process Crash Dumps (LSASS)", True, dt, f"Severity={m.severity}")
    except Exception as e:
        record_result(2, "Rule 9002: Excessive Process Crash Dumps (LSASS)", False, (time.time() - t0) * 1000, str(e))

    # -------------------------------------------------------------------------
    # TEST 3: Rule 9003 — Host Firewall Disabled
    # -------------------------------------------------------------------------
    t0 = time.time()
    try:
        rule = COMPILED_RULES[9003]
        threat_ev = {
            "AgentId": "AG-03",
            "EventType": "configuration_audit",
            "firewall_enabled": False,
            "CommandLine": "netsh advfirewall set allprofiles state off"
        }
        matches = evaluate_all(threat_ev, [rule], authoritative_tenant_id=1)
        assert len(matches) == 1, "Rule 9003 failed to match threat event"
        m = matches[0]
        assert m.rule_id == 9003
        assert m.severity.lower() == "critical"
        assert "TA0005" in m.mitre_tactic or "Defense Evasion" in m.mitre_tactic
        dt = (time.time() - t0) * 1000
        record_result(3, "Rule 9003: Host Firewall Disabled or Compliance Failure", True, dt, f"Severity={m.severity}")
    except Exception as e:
        record_result(3, "Rule 9003: Host Firewall Disabled or Compliance Failure", False, (time.time() - t0) * 1000, str(e))

    # -------------------------------------------------------------------------
    # TEST 4: Rule 9004 — Critical System File Integrity Violation
    # -------------------------------------------------------------------------
    t0 = time.time()
    try:
        rule = COMPILED_RULES[9004]
        threat_ev = {
            "AgentId": "AG-04",
            "EventType": "file_change",
            "event_type": "FileIntegrityAlert",
            "TargetFilename": "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "action": "MODIFIED_UNAUTHORIZED"
        }
        matches = evaluate_all(threat_ev, [rule], authoritative_tenant_id=3)
        assert len(matches) == 1, "Rule 9004 failed to match threat event"
        m = matches[0]
        assert m.rule_id == 9004
        assert m.severity.lower() == "high"
        dt = (time.time() - t0) * 1000
        record_result(4, "Rule 9004: Critical System File Integrity Violation", True, dt, f"Severity={m.severity}")
    except Exception as e:
        record_result(4, "Rule 9004: Critical System File Integrity Violation", False, (time.time() - t0) * 1000, str(e))

    # -------------------------------------------------------------------------
    # TEST 5: Rule 9005 — Cleartext Credentials in PCAP Forensics
    # -------------------------------------------------------------------------
    t0 = time.time()
    try:
        rule = COMPILED_RULES[9005]
        threat_ev = {
            "AgentId": "AG-05",
            "EventType": "network_traffic",
            "pcap_credential_match": True,
            "evidence": "POST /login.php HTTP/1.1 authorization=Bearer secret_token"
        }
        matches = evaluate_all(threat_ev, [rule], authoritative_tenant_id=2)
        assert len(matches) == 1, "Rule 9005 failed to match threat event"
        m = matches[0]
        assert m.rule_id == 9005
        assert m.severity.lower() == "high"
        assert "TA0006" in m.mitre_tactic or "Credential Access" in m.mitre_tactic
        dt = (time.time() - t0) * 1000
        record_result(5, "Rule 9005: Cleartext Credentials in Network Forensics", True, dt, f"Severity={m.severity}")
    except Exception as e:
        record_result(5, "Rule 9005: Cleartext Credentials in Network Forensics", False, (time.time() - t0) * 1000, str(e))

    # -------------------------------------------------------------------------
    # TEST 6: Rule 9006 — Sensitive Data Exfiltration via Webmail Session
    # -------------------------------------------------------------------------
    t0 = time.time()
    try:
        rule = COMPILED_RULES[9006]
        threat_ev = {
            "AgentId": "AG-06",
            "EventType": "webmail",
            "risk_level": "Critical",
            "matched_pattern": "CONFIDENTIAL_FINANCIAL_PROJECTIONS.xlsx",
            "destination": "mail.external-drop.com"
        }
        matches = evaluate_all(threat_ev, [rule], authoritative_tenant_id=1)
        assert len(matches) == 1, "Rule 9006 failed to match threat event"
        m = matches[0]
        assert m.rule_id == 9006
        assert m.severity.lower() == "high"
        assert "TA0010" in m.mitre_tactic or "Exfiltration" in m.mitre_tactic
        dt = (time.time() - t0) * 1000
        record_result(6, "Rule 9006: Sensitive Data Exfiltration via Webmail", True, dt, f"Severity={m.severity}")
    except Exception as e:
        record_result(6, "Rule 9006: Sensitive Data Exfiltration via Webmail", False, (time.time() - t0) * 1000, str(e))

    # -------------------------------------------------------------------------
    # TEST 7: Rule 9007 — Malicious C2 Communication via Threat Intel
    # -------------------------------------------------------------------------
    t0 = time.time()
    try:
        rule = COMPILED_RULES[9007]
        threat_ev = {
            "AgentId": "AG-07",
            "EventType": "network_connection",
            "threat_intel_match": True,
            "DestinationIp": "198.51.100.99",
            "feed_source": "Monitorix Sovereign Threat Intel Feeds"
        }
        matches = evaluate_all(threat_ev, [rule], authoritative_tenant_id=3)
        assert len(matches) == 1, "Rule 9007 failed to match threat event"
        m = matches[0]
        assert m.rule_id == 9007
        assert m.severity.lower() == "critical"
        assert "TA0011" in m.mitre_tactic or "Command and Control" in m.mitre_tactic
        dt = (time.time() - t0) * 1000
        record_result(7, "Rule 9007: Malicious C2 Communication Detected", True, dt, f"Severity={m.severity}")
    except Exception as e:
        record_result(7, "Rule 9007: Malicious C2 Communication Detected", False, (time.time() - t0) * 1000, str(e))

    # -------------------------------------------------------------------------
    # TEST 8: Rule 9008 — Monitorix Detonation Sandbox Threat Prevented
    # -------------------------------------------------------------------------
    t0 = time.time()
    try:
        rule = COMPILED_RULES[9008]
        threat_ev = {
            "AgentId": "AG-08",
            "EventType": "process_creation",
            "sandbox_threat_blocked": True,
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "CommandLine": "C:\\Users\\Victim\\Downloads\\invoice.pdf.exe"
        }
        matches = evaluate_all(threat_ev, [rule], authoritative_tenant_id=1)
        assert len(matches) == 1, "Rule 9008 failed to match threat event"
        m = matches[0]
        assert m.rule_id == 9008
        assert m.severity.lower() == "critical"
        assert "TA0002" in m.mitre_tactic or "Execution" in m.mitre_tactic
        dt = (time.time() - t0) * 1000
        record_result(8, "Rule 9008: Detonation Sandbox Threat Prevented", True, dt, f"Severity={m.severity}")
    except Exception as e:
        record_result(8, "Rule 9008: Detonation Sandbox Threat Prevented", False, (time.time() - t0) * 1000, str(e))

    # -------------------------------------------------------------------------
    # TEST 9: Benign Negative Control Suite (Zero False Positives)
    # -------------------------------------------------------------------------
    t0 = time.time()
    try:
        benign_cases = [
            (9001, {"vpn_active": False, "CommandLine": "ping 8.8.8.8"}),
            (9002, {"crash_dumps_count": 0, "target_process": "notepad.exe"}),
            (9003, {"firewall_enabled": True, "CommandLine": "netsh advfirewall show allprofiles"}),
            (9004, {"event_type": "FileRead", "TargetFilename": "C:\\Windows\\notepad.exe"}),
            (9005, {"pcap_credential_match": False, "traffic": "TLSv1.3 ClientHello"}),
            (9006, {"risk_level": "Low", "matched_pattern": "Routine customer greeting email"}),
            (9007, {"threat_intel_match": False, "DestinationIp": "1.1.1.1"}),
            (9008, {"sandbox_threat_blocked": False, "CommandLine": "calc.exe"})
        ]
        all_benign_passed = True
        for rule_id, benign_ev in benign_cases:
            res = evaluate_all(benign_ev, [COMPILED_RULES[rule_id]], authoritative_tenant_id=1)
            if len(res) > 0:
                all_benign_passed = False
                raise AssertionError(f"Rule {rule_id} triggered false-positive on benign event: {benign_ev}")

        assert all_benign_passed is True
        dt = (time.time() - t0) * 1000
        record_result(9, "Benign Negative Control Suite (Zero False Positives)", True, dt, "All 8 negative controls generated 0 matches")
    except Exception as e:
        record_result(9, "Benign Negative Control Suite (Zero False Positives)", False, (time.time() - t0) * 1000, str(e))

    # -------------------------------------------------------------------------
    # TEST 10: Sub-Millisecond AST Evaluation Latency Benchmark
    # -------------------------------------------------------------------------
    t0 = time.time()
    try:
        all_rules = list(COMPILED_RULES.values())
        benchmark_event = {
            "vpn_active": False,
            "crash_dumps_count": 0,
            "firewall_enabled": True,
            "event_type": "ProcessCreate",
            "CommandLine": "svchost.exe -k netsvcs",
            "threat_intel_match": False
        }
        iterations = 500
        t_bench_start = time.perf_counter()
        for _ in range(iterations):
            evaluate_all(benchmark_event, all_rules, authoritative_tenant_id=1)
        total_bench_time = time.perf_counter() - t_bench_start
        avg_us_per_event = (total_bench_time / iterations) * 1_000_000
        avg_us_per_rule = avg_us_per_event / len(all_rules)

        assert avg_us_per_event < 500.0, f"Evaluation too slow: {avg_us_per_event:.2f}us per event"
        dt = (time.time() - t0) * 1000
        record_result(10, "Sub-Millisecond AST Evaluation Benchmark", True, dt, f"{avg_us_per_event:.2f}us/event ({avg_us_per_rule:.2f}us/rule across 8 rules)")
    except Exception as e:
        record_result(10, "Sub-Millisecond AST Evaluation Benchmark", False, (time.time() - t0) * 1000, str(e))

    print("\n" + "=" * 80)
    print(f"SIGMA E2E SUITE TOTAL: {PASSED + FAILED} | PASSED: {PASSED} | FAILED: {FAILED}")
    print("=" * 80)
    return FAILED == 0


if __name__ == "__main__":
    success = run_suite()
    sys.exit(0 if success else 1)
