#!/usr/bin/env python3
"""
MONITORIX ENTERPRISE — PHASE 5.4.3B CONSOLIDATED TEST RUNNER
Executes All 3 Validation Test Suites (18 Tests Total)
=====================================================
Suite 1: test_kafka_streaming_detection.py (Tests 01-08)
Suite 2: test_detection_alert_persistence.py (Tests 09-15)
Suite 3: test_detection_alert_tenant_migration.py (Tests 16-18)
"""

import sys
import os
import json
import time
import subprocess

for candidate in ["/app", "/opt/projects/monitorix/watch-sec-python/backend"]:
    if os.path.exists(candidate) and candidate not in sys.path:
        sys.path.insert(0, candidate)

SUITES = [
    ("/app/tests/test_kafka_streaming_detection.py", "Kafka Streaming Detection Integration (Tests 01-08)"),
    ("/app/tests/test_detection_alert_persistence.py", "Alert Persistence & System Rules (Tests 09-15)"),
    ("/app/tests/test_detection_alert_tenant_migration.py", "Tenant Migration & SOC Promotion (Tests 16-18)")
]

def main():
    print("=" * 80)
    print("MONITORIX ENTERPRISE — PHASE 5.4.3B COMPLETE TEST VALIDATION RUNNER")
    print("Executing All 18 Mandatory Acceptance Tests Across 3 Test Suites")
    print("=" * 80)

    total_start = time.time()
    all_passed = True
    suite_summaries = []

    for script_path, title in SUITES:
        print(f"\n>>> Running: {title}")
        t0 = time.time()
        res = subprocess.run([sys.executable, script_path], capture_output=True, text=True)
        dur = (time.time() - t0) * 1000
        print(res.stdout)
        if res.stderr:
            print("[STDERR]", res.stderr)

        passed = (res.returncode == 0)
        if not passed:
            all_passed = False

        suite_summaries.append({
            "script": os.path.basename(script_path),
            "title": title,
            "passed": passed,
            "duration_ms": round(dur, 2),
            "returncode": res.returncode
        })

    total_dur = (time.time() - total_start) * 1000

    print("=" * 80)
    print("CONSOLIDATED SUMMARY:")
    for s in suite_summaries:
        status = "PASSED" if s["passed"] else "FAILED"
        print(f"  [{status}] {s['title']} ({s['duration_ms']:.2f}ms)")
    print(f"\nOVERALL RESULT: {'ALL 18 TESTS PASSED (100% SUCCESS)' if all_passed else 'FAILURES DETECTED'}")
    print(f"TOTAL EXECUTION TIME: {total_dur:.2f}ms")
    print("=" * 80)

    out_json = "/tmp/monitorix_phase5_4_3b_test_results.json"
    with open(out_json, "w") as f:
        json.dump({
            "overall_success": all_passed,
            "total_tests": 18,
            "total_passed": 18 if all_passed else "check_logs",
            "total_duration_ms": round(total_dur, 2),
            "suites": suite_summaries
        }, f, indent=2)

    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
