#!/usr/bin/env python3
"""
MONITORIX ENTERPRISE — PHASE 5.4.3C TEST SUITE (PART 3)
Detection Multi-Tenant Isolation & Security Validation
======================================================
Validates:
 1. Cross-tenant alert list isolation (GET /api/v2/detection/alerts)
 2. Cross-tenant alert detail retrieval rejection (HTTP 404)
 3. Cross-tenant alert status modification rejection (HTTP 404)
 4. Private tenant rule evaluation isolation (Tenant A rule never evaluates Tenant B events)
 5. Global system rule evaluation across authorized tenants (TenantId IS NULL)
 6. Authoritative agent ownership anti-spoofing override
 7. Cross-tenant SOC case alert promotion rejection (HTTP 404)
 8. SuperAdmin cross-tenant oversight visibility
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

import httpx
from jose import jwt
from sqlalchemy.future import select
from sqlalchemy import text, delete

from app.core.security import SECRET_KEY, ALGORITHM
from app.db.session import AsyncSessionLocal
from app.db.models import User, Tenant, Agent, DetectionRule, DetectionAlert, SocCase
from app.main_dashboard import app
from app.services.detection.sigma_compiler import (
    sigma_compiler,
    sigma_registry,
    evaluate_all
)
from app.services.detection.streaming_detector import streaming_detection_engine

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


def mint_token(username: str, role: str, tenant_id: int = None) -> str:
    """Mints an enterprise JWT for testing."""
    payload = {
        "sub": username,
        "role": role,
        "tenantId": tenant_id,
        "exp": datetime.utcnow() + timedelta(hours=2)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


async def run_suite():
    global PASSED, FAILED
    print("=" * 80)
    print("MONITORIX ENTERPRISE — PHASE 5.4.3C TEST SUITE (PART 3)")
    print("Detection Multi-Tenant Isolation & Security Validation")
    print("=" * 80)

    # Setup isolated test database records
    t_now = int(time.time())
    agent_t1_id = f"TEST-AG-T1-{t_now}"
    agent_t3_id = f"TEST-AG-T3-{t_now}"
    alert_t1_id = None
    alert_t3_id = None

    async with AsyncSessionLocal() as db:
        # Create test agent for Tenant 1
        agent_t1 = Agent(
            AgentId=agent_t1_id,
            TenantId=1,
            Hostname="SRV-TENANT1-DC01",
            Status="Active"
        )
        db.add(agent_t1)

        # Create test agent for Tenant 3
        agent_t3 = Agent(
            AgentId=agent_t3_id,
            TenantId=3,
            Hostname="SRV-TENANT3-APP01",
            Status="Active"
        )
        db.add(agent_t3)

        # Create alert for Tenant 1
        alert_t1 = DetectionAlert(
            AgentId=agent_t1_id,
            RuleId=2,  # Mimikatz rule
            MatchedContent="[T1] Mimikatz command execution",
            Status="New",
            Timestamp=datetime.utcnow()
        )
        db.add(alert_t1)

        # Create alert for Tenant 3
        alert_t3 = DetectionAlert(
            AgentId=agent_t3_id,
            RuleId=3,  # PowerShell rule
            MatchedContent="[T3] Encoded PowerShell command execution",
            Status="New",
            Timestamp=datetime.utcnow()
        )
        db.add(alert_t3)

        await db.commit()
        alert_t1_id = alert_t1.Id
        alert_t3_id = alert_t3.Id

    token_t1 = mint_token("elsea", "TenantAdmin", tenant_id=1)
    token_t3 = mint_token("sentinelx", "TenantAdmin", tenant_id=3)
    token_super = mint_token("superadmin", "SuperAdmin", tenant_id=None)

    h_t1 = {"Authorization": f"Bearer {token_t1}"}
    h_t3 = {"Authorization": f"Bearer {token_t3}"}
    h_super = {"Authorization": f"Bearer {token_super}"}

    async with httpx.AsyncClient(app=app, base_url="http://testserver") as client:
        # ----------------------------------------------------------------------
        # TEST 01: Cross-tenant alert list isolation (GET /api/v2/detection/alerts)
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        res_t1 = await client.get("/api/v2/detection/alerts", headers=h_t1)
        res_t3 = await client.get("/api/v2/detection/alerts", headers=h_t3)
        d1 = (time.perf_counter() - t0) * 1000

        data_t1 = res_t1.json() if res_t1.status_code == 200 else []
        data_t3 = res_t3.json() if res_t3.status_code == 200 else []

        t1_alert_ids = {a["Id"] for a in data_t1}
        t3_alert_ids = {a["Id"] for a in data_t3}

        # Tenant 1 must see alert_t1 and NEVER alert_t3
        # Tenant 3 must see alert_t3 and NEVER alert_t1
        p1 = (
            res_t1.status_code == 200 and
            res_t3.status_code == 200 and
            alert_t1_id in t1_alert_ids and
            alert_t3_id not in t1_alert_ids and
            alert_t3_id in t3_alert_ids and
            alert_t1_id not in t3_alert_ids
        )
        record_result(1, "Cross-Tenant Alert Listing Isolation (GET /alerts)", p1, d1)

        # ----------------------------------------------------------------------
        # TEST 02: Cross-tenant alert detail retrieval rejection (HTTP 404)
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        # Tenant 3 attempts to view detail of Tenant 1's alert
        cross_detail_res = await client.get(f"/api/v2/detection/alerts/{alert_t1_id}", headers=h_t3)
        # Tenant 1 attempts to view their own alert
        own_detail_res = await client.get(f"/api/v2/detection/alerts/{alert_t1_id}", headers=h_t1)
        d2 = (time.perf_counter() - t0) * 1000

        p2 = (
            cross_detail_res.status_code == 404 and
            own_detail_res.status_code == 200 and
            own_detail_res.json().get("Id") == alert_t1_id
        )
        record_result(2, "Cross-Tenant Alert Detail Rejection (Strict HTTP 404)", p2, d2)

        # ----------------------------------------------------------------------
        # TEST 03: Cross-tenant alert status modification rejection (HTTP 404)
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        # Tenant 3 attempts to close Tenant 1's alert
        cross_update_res = await client.patch(
            f"/api/v2/detection/alerts/{alert_t1_id}",
            headers=h_t3,
            json={"status": "Closed"}
        )
        # Verify status did not change
        async with AsyncSessionLocal() as db:
            refreshed = (await db.execute(select(DetectionAlert).where(DetectionAlert.Id == alert_t1_id))).scalars().first()
            status_unmodified = (refreshed.Status == "New")

        d3 = (time.perf_counter() - t0) * 1000
        p3 = (cross_update_res.status_code == 404 and status_unmodified)
        record_result(3, "Cross-Tenant Alert Status Modification Rejection", p3, d3)

        # ----------------------------------------------------------------------
        # TEST 04: Private tenant rule evaluation isolation
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        # Compile private rule for Tenant 1
        private_rule_yaml = """
title: Tenant 1 Proprietary Backdoor Pattern
id: 7001
status: production
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'tenant1_secret_token_trigger'
  condition: selection
level: critical
"""
        priv_rule = sigma_compiler.compile(
            yaml_content=private_rule_yaml,
            rule_id=7001,
            metadata={"tenant_id": 1, "Severity": "Critical"}
        )
        sigma_registry.register(priv_rule)

        # Event from Tenant 3 containing the trigger string
        event_t3 = {
            "EventType": "ProcessExecution",
            "AgentId": agent_t3_id,
            "TenantId": 3,
            "CommandLine": "evil.exe tenant1_secret_token_trigger",
            "Timestamp": datetime.utcnow().isoformat()
        }
        # In-flight evaluation scoped to Tenant 3
        norm_t3 = streaming_detection_engine.normalize_event(event_t3)
        matches_for_t3 = sigma_registry.evaluate_all(norm_t3, tenant_id=3)
        # Private rule for Tenant 1 MUST NOT match Tenant 3
        d4 = (time.perf_counter() - t0) * 1000
        p4 = (len(matches_for_t3) == 0)
        record_result(4, "Private Tenant Rule Evaluation Isolation Guard", p4, d4)

        # ----------------------------------------------------------------------
        # TEST 05: Global system rule evaluation across authorized tenants
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        global_rule_yaml = """
title: Global Suspicious Whoami Invocation
id: 9901
status: production
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: 'whoami.exe'
  condition: selection
level: medium
"""
        global_rule = sigma_compiler.compile(
            yaml_content=global_rule_yaml,
            rule_id=9901,
            metadata={"tenant_id": None, "Severity": "Medium"}
        )
        sigma_registry.register(global_rule)

        whoami_event_t1 = {"EventType": "ProcessExecution", "Image": "whoami.exe", "AgentId": agent_t1_id}
        whoami_event_t3 = {"EventType": "ProcessExecution", "Image": "whoami.exe", "AgentId": agent_t3_id}

        matches_t1 = sigma_registry.evaluate_all(whoami_event_t1, tenant_id=1)
        matches_t3 = sigma_registry.evaluate_all(whoami_event_t3, tenant_id=3)

        d5 = (time.perf_counter() - t0) * 1000
        p5 = (len(matches_t1) >= 1 and len(matches_t3) >= 1)
        record_result(5, "Global System Rule Evaluation Across All Authorized Tenants", p5, d5)

        # ----------------------------------------------------------------------
        # TEST 06: Authoritative agent ownership anti-spoofing override
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        async with AsyncSessionLocal() as db:
            resolved_tenant = await streaming_detection_engine.resolve_authoritative_tenant(
                db=db,
                agent_id=agent_t1_id,
                declared_tenant_id=9999  # Spoofed
            )
        d6 = (time.perf_counter() - t0) * 1000
        # Must resolve to 1 (from DB) and discard 9999
        p6 = (resolved_tenant == 1)
        record_result(6, "Authoritative Agent Ownership (Anti-Spoofing Override)", p6, d6, f"(Declared=9999, Authoritative={resolved_tenant})")

        # ----------------------------------------------------------------------
        # TEST 07: Cross-tenant SOC case alert promotion rejection (HTTP 404)
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        cross_promo_res = await client.post(
            "/api/v2/soc/cases/promote-alert",
            headers=h_t3,
            json={"alert_id": alert_t1_id, "title": "Illegal Promotion"}
        )
        d7 = (time.perf_counter() - t0) * 1000
        p7 = (cross_promo_res.status_code == 404)
        record_result(7, "Cross-Tenant Alert Promotion Rejection (HTTP 404)", p7, d7)

        # ----------------------------------------------------------------------
        # TEST 08: SuperAdmin cross-tenant oversight visibility
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        super_res = await client.get("/api/v2/detection/alerts", headers=h_super)
        d8 = (time.perf_counter() - t0) * 1000
        super_data = super_res.json() if super_res.status_code == 200 else []
        super_alert_ids = {a["Id"] for a in super_data}
        # SuperAdmin can see both Tenant 1 and Tenant 3 alerts
        p8 = (super_res.status_code == 200 and alert_t1_id in super_alert_ids and alert_t3_id in super_alert_ids)
        record_result(8, "SuperAdmin Cross-Tenant Oversight Visibility", p8, d8)

    # Cleanup test records
    async with AsyncSessionLocal() as db:
        await db.execute(delete(DetectionAlert).where(DetectionAlert.Id.in_([alert_t1_id, alert_t3_id])))
        await db.execute(delete(Agent).where(Agent.AgentId.in_([agent_t1_id, agent_t3_id])))
        await db.commit()

    print("\n" + "=" * 80)
    print(f"PART 3 TOTAL: 8 | PASSED: {PASSED} | FAILED: {FAILED}")
    print("=" * 80)
    return FAILED == 0


if __name__ == "__main__":
    success = asyncio.run(run_suite())
    sys.exit(0 if success else 1)
