#!/usr/bin/env python3
"""
MONITORIX ENTERPRISE — PHASE 5.4.3B TEST SUITE (PART 1)
Kafka Streaming Detection Integration & Event Evaluation
========================================================
Tests 1 to 8:
 1. ProcessExecution event reception
 2. PROCESS_START event reception
 3. Valid Sigma rule match
 4. Non-matching event
 5. Multiple rule matches
 6. Malformed event handling
 7. Invalid tenant rejection & tenant isolation guard
 8. Authoritative agent-to-tenant mapping & caching
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

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

from app.services.detection.sigma_compiler import (
    sigma_compiler,
    sigma_registry,
    CompiledSigmaRule,
    DetectionResult
)
from app.services.detection.streaming_detector import (
    StreamingDetectionEngine,
    streaming_detection_engine,
    SUPPORTED_EVENT_TYPES
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


class MockAsyncSession:
    """Mock AsyncSession for isolated streaming detection tests without touching production DB."""
    def __init__(self, agents_db: Dict[str, Any] = None, rules_db: List[Any] = None):
        self.agents_db = agents_db or {}
        self.rules_db = rules_db or []
        self.committed = False
        self.rolled_back = False
        self.added = []

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

        # Check query representations
        q_str = str(query)
        if "FROM \"Agents\"" in q_str or "FROM agents" in q_str or "Agents.AgentId" in q_str:
            # Match agent lookup
            items = []
            for agent_id, agent_obj in self.agents_db.items():
                items.append(agent_obj)
            return MockResult(items)

        return MockResult([])

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.committed = True

    async def rollback(self):
        self.rolled_back = True


class MockAgent:
    def __init__(self, agent_id: str, tenant_id: int, hostname: str = "host-01"):
        self.AgentId = agent_id
        self.TenantId = tenant_id
        self.Hostname = hostname


async def run_suite():
    global PASSED, FAILED
    print("=" * 80)
    print("MONITORIX ENTERPRISE — PHASE 5.4.3B TEST SUITE (PART 1)")
    print("Kafka Streaming Detection Integration (Tests 01-08)")
    print("=" * 80)

    # Initialize a clean test registry
    sigma_registry.clear()
    engine = StreamingDetectionEngine()

    # Rule A: Suspicious PowerShell Encoded Command (Global, TenantId=None)
    rule_ps_yaml = """
title: Suspicious Encoded PowerShell Execution
id: 101
status: production
description: Detects encoded PowerShell command execution.
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: 'powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
level: high
"""
    rule_ps = sigma_compiler.compile(
        yaml_content=rule_ps_yaml,
        rule_id=101,
        metadata={
            "tenant_id": None,
            "mitre_tactic": "TA0002 (Execution)",
            "mitre_technique": "T1059.001 (PowerShell)",
            "category": "Execution"
        }
    )
    sigma_registry.register(rule_ps)

    # Rule B: Mimikatz LSASS Dump (Tenant 1 Only)
    rule_mimikatz_yaml = """
title: Mimikatz Credential Dumping Command Line
id: 102
status: production
description: Detects command lines executing mimikatz or sekurlsa.
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'sekurlsa::logonpasswords'
  condition: selection
level: critical
"""
    rule_mimi = sigma_compiler.compile(
        yaml_content=rule_mimikatz_yaml,
        rule_id=102,
        metadata={
            "tenant_id": 1,
            "mitre_tactic": "TA0006 (Credential Access)",
            "mitre_technique": "T1003.001 (OS Credential Dumping)",
            "category": "Credential Dumping"
        }
    )
    sigma_registry.register(rule_mimi)

    # Rule C: Secondary Mimikatz Rule (Also matches sekurlsa)
    rule_mimi2_yaml = """
title: General Credential Dumper Invocation
id: 103
status: production
description: Secondary match for credential dumping tools.
tags:
  - attack.credential_access
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'logonpasswords'
  condition: selection
level: high
"""
    rule_mimi2 = sigma_compiler.compile(
        yaml_content=rule_mimi2_yaml,
        rule_id=103,
        metadata={
            "tenant_id": 1,
            "mitre_tactic": "TA0006 (Credential Access)",
            "mitre_technique": "T1003",
            "category": "Credential Access"
        }
    )
    sigma_registry.register(rule_mimi2)

    # --------------------------------------------------------------------------
    # TEST 01: ProcessExecution event reception
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    event_1 = {
        "EventType": "ProcessExecution",
        "AgentId": "AGENT-001",
        "TenantId": 1,
        "Timestamp": datetime.utcnow().isoformat(),
        "Payload": {
            "process_name": "cmd.exe",
            "cmdline": "cmd.exe /c echo hello",
            "pid": 4321
        }
    }
    mock_db = MockAsyncSession(agents_db={"AGENT-001": MockAgent("AGENT-001", 1)})
    norm_1 = engine.normalize_event(event_1)
    res_1 = await engine.process_kafka_event(mock_db, event_1)
    d1 = (time.perf_counter() - t0) * 1000
    p1 = (
        norm_1.get("Image") == "cmd.exe" and
        norm_1.get("CommandLine") == "cmd.exe /c echo hello" and
        engine.total_events_evaluated >= 1
    )
    record_result(1, "ProcessExecution Event Reception & Normalization", p1, d1)

    # --------------------------------------------------------------------------
    # TEST 02: PROCESS_START event reception
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    event_2 = {
        "EventType": "PROCESS_START",
        "AgentId": "AGENT-001",
        "TenantId": 1,
        "Timestamp": datetime.utcnow().isoformat(),
        "Image": "C:\\Windows\\System32\\svchost.exe",
        "CommandLine": "svchost.exe -k netsvcs",
        "ProcessId": 1234
    }
    norm_2 = engine.normalize_event(event_2)
    res_2 = await engine.process_kafka_event(mock_db, event_2)
    d2 = (time.perf_counter() - t0) * 1000
    p2 = (
        norm_2.get("process_name") == "C:\\Windows\\System32\\svchost.exe" and
        norm_2.get("CommandLine") == "svchost.exe -k netsvcs"
    )
    record_result(2, "PROCESS_START Event Reception & Normalization", p2, d2)

    # --------------------------------------------------------------------------
    # TEST 03: Valid Sigma rule match
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    event_3 = {
        "EventType": "ProcessExecution",
        "AgentId": "AGENT-001",
        "TenantId": 1,
        "Timestamp": datetime.utcnow().isoformat(),
        "Payload": {
            "process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "cmdline": "powershell.exe -NoProfile -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGo...",
            "pid": 5544
        }
    }
    norm_3 = engine.normalize_event(event_3)
    matches_3 = sigma_registry.evaluate_all(norm_3, tenant_id=1)
    d3 = (time.perf_counter() - t0) * 1000
    p3 = (
        len(matches_3) == 1 and
        matches_3[0].rule_id == 101 and
        matches_3[0].rule_title == "Suspicious Encoded PowerShell Execution" and
        "Execution" in matches_3[0].mitre_tactic and
        matches_3[0].severity.lower() == "high"
    )
    record_result(3, "Valid Sigma Rule Match & MITRE Extraction", p3, d3)

    # --------------------------------------------------------------------------
    # TEST 04: Non-matching event
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    event_4 = {
        "EventType": "ProcessExecution",
        "AgentId": "AGENT-001",
        "TenantId": 1,
        "Timestamp": datetime.utcnow().isoformat(),
        "Payload": {
            "process_name": "notepad.exe",
            "cmdline": "notepad.exe C:\\Users\\analyst\\document.txt",
            "pid": 9988
        }
    }
    norm_4 = engine.normalize_event(event_4)
    matches_4 = sigma_registry.evaluate_all(norm_4, tenant_id=1)
    d4 = (time.perf_counter() - t0) * 1000
    p4 = len(matches_4) == 0
    record_result(4, "Non-Matching Benign Event Rejection", p4, d4)

    # --------------------------------------------------------------------------
    # TEST 05: Multiple rule matches
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    event_5 = {
        "EventType": "ProcessExecution",
        "AgentId": "AGENT-001",
        "TenantId": 1,
        "Timestamp": datetime.utcnow().isoformat(),
        "Payload": {
            "process_name": "mimikatz.exe",
            "cmdline": "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
            "pid": 7766
        }
    }
    norm_5 = engine.normalize_event(event_5)
    matches_5 = sigma_registry.evaluate_all(norm_5, tenant_id=1)
    d5 = (time.perf_counter() - t0) * 1000
    matched_ids = {m.rule_id for m in matches_5}
    p5 = len(matches_5) == 2 and 102 in matched_ids and 103 in matched_ids
    record_result(5, "Multiple Independent Rule Matches on Single Event", p5, d5)

    # --------------------------------------------------------------------------
    # TEST 06: Malformed event handling
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    malformed_inputs = [
        "not-a-dict-string",
        None,
        [],
        {"EventType": "ProcessExecution"},  # Missing AgentId
        {"EventType": "ProcessExecution", "AgentId": ""},  # Empty AgentId
        {"EventType": "ProcessExecution", "AgentId": "AGENT-001", "Payload": "invalid{json"},  # Corrupt json payload
        {"EventType": "ProcessExecution", "AgentId": "AGENT-001", "CommandLine": 12345},  # Non-string command line
    ]
    all_malformed_handled = True
    for mal in malformed_inputs:
        try:
            res = await engine.process_kafka_event(mock_db, mal)
            if not isinstance(res, list):
                all_malformed_handled = False
        except Exception as e:
            all_malformed_handled = False
            print(f"    Unexpected exception on malformed input: {e}")
    d6 = (time.perf_counter() - t0) * 1000
    record_result(6, "Malformed Event Safe Handling & Crash Immunity", all_malformed_handled, d6)

    # --------------------------------------------------------------------------
    # TEST 07: Invalid tenant rejection & tenant isolation guard
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    # Event claims TenantId = 2, but Agent-001 is authoritative TenantId = 1
    # Rule 102 belongs strictly to Tenant 1. A query for Tenant 2 should NOT match Rule 102.
    matches_tenant2 = sigma_registry.evaluate_all(norm_5, tenant_id=2)
    tenant_isolation_ok = (len(matches_tenant2) == 0)

    # Also test authoritative tenant override
    mock_db_spoof = MockAsyncSession(agents_db={"AGENT-SPOOF": MockAgent("AGENT-SPOOF", 1)})
    resolved_tenant = await engine.resolve_authoritative_tenant(
        mock_db_spoof,
        agent_id="AGENT-SPOOF",
        declared_tenant_id=999
    )
    # The authoritative DB tenant (1) MUST override declared tenant (999)
    authoritative_override_ok = (resolved_tenant == 1)

    d7 = (time.perf_counter() - t0) * 1000
    p7 = tenant_isolation_ok and authoritative_override_ok
    record_result(7, "Tenant Isolation & Spoofed Tenant Rejection", p7, d7)

    # --------------------------------------------------------------------------
    # TEST 08: Authoritative agent-to-tenant mapping & caching
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    mock_db_cache = MockAsyncSession(agents_db={"AGENT-CACHE": MockAgent("AGENT-CACHE", 42)})
    # First call - queries DB
    tenant_first = await engine.resolve_authoritative_tenant(mock_db_cache, "AGENT-CACHE")
    # Second call - should hit cache
    tenant_cached = await engine.resolve_authoritative_tenant(mock_db_cache, "AGENT-CACHE")
    d8 = (time.perf_counter() - t0) * 1000
    p8 = (tenant_first == 42 and tenant_cached == 42 and "AGENT-CACHE" in engine._agent_tenant_cache)
    record_result(8, "Authoritative Agent-to-Tenant DB Resolution & Caching", p8, d8)

    print("\n" + "=" * 80)
    print(f"PART 1 TOTAL: 8 | PASSED: {PASSED} | FAILED: {FAILED}")
    print("=" * 80)
    return FAILED == 0


if __name__ == "__main__":
    success = asyncio.run(run_suite())
    sys.exit(0 if success else 1)
