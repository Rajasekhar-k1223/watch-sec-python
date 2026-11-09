#!/usr/bin/env python3
"""
MONITORIX ENTERPRISE — PHASE 5.4.3D MASTER TEST RUNNER
Executes all 6 validation suites in sequence and prints comprehensive scorecards.
"""

import sys
import subprocess
import time

SUITES = [
    ("Suite 1: Event Contracts & Payload Compatibility", "tests/test_phase_5_4_3d_event_contracts.py"),
    ("Suite 2: End-to-End Sigma Evaluation & System Rules", "tests/test_phase_5_4_3d_sigma_end_to_end.py"),
    ("Suite 3: Alert Persistence & Deduplication Reliability", "tests/test_phase_5_4_3d_alert_persistence.py"),
    ("Suite 4: Multi-Tenant Isolation & Role Authorization", "tests/test_phase_5_4_3d_tenant_isolation.py"),
    ("Suite 5: Kafka Fault Injection, Recovery & At-Least-Once Delivery", "tests/test_phase_5_4_3d_kafka_recovery.py"),
    ("Suite 6: SOC Case Promotion & Incident Workflow Integration", "tests/test_phase_5_4_3d_soc_promotion.py"),
]

def main():
    print("=" * 80)
    print("MONITORIX ENTERPRISE — PHASE 5.4.3D MASTER VALIDATION RUNNER")
    print("================================================================================")
    t_start = time.time()
    all_passed = True
    summary = []

    for name, path in SUITES:
        print(f"\n>>> RUNNING: {name} ({path})")
        t0 = time.time()
        res = subprocess.run(["python3", f"/app/{path}"], capture_output=True, text=True)
        duration = time.time() - t0
        passed = (res.returncode == 0)
        if not passed:
            all_passed = False
        summary.append((name, passed, duration, res.stdout, res.stderr))
        print(res.stdout)
        if res.stderr and not passed:
            print("STDERR:", res.stderr)

    total_duration = time.time() - t_start
    print("\n" + "=" * 80)
    print("PHASE 5.4.3D FINAL VALIDATION SUMMARY")
    print("=" * 80)
    for name, passed, duration, _, _ in summary:
        status = "PASSED (10/10)" if passed else "FAILED"
        print(f"  [{status}] {name} ({duration:.2f}s)")
    print("-" * 80)
    print(f"OVERALL RESULT: {'ALL 60 TESTS PASSED (100%)' if all_passed else 'FAILURES DETECTED'}")
    print(f"TOTAL EXECUTION TIME: {total_duration:.2f}s")
    print("=" * 80)

    if not all_passed:
        sys.exit(1)

if __name__ == "__main__":
    main()
