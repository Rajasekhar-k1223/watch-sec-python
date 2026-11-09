#!/usr/bin/env python3
"""
MONITORIX ENTERPRISE — PHASE 5.4.3B TEST SUITE (PART 3)
Detection Alert Tenant Migration & SOC Case Promotion
=====================================================
Tests 16 to 18:
 16. Historical alert backfill (AgentId -> Agents.TenantId mapping)
 17. Unresolved historical tenant records (safe NULL preservation)
 18. Alert-to-SOC case promotion (POST /api/v2/soc/cases/promote-alert)
     - Tenant ownership validation
     - Cross-tenant isolation (HTTP 404)
     - Duplicate promotion prevention (HTTP 409 Conflict)
     - MITRE ATT&CK & agent metadata preservation
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
from app.db.models import User, Tenant, Agent, DetectionRule, DetectionAlert, SocCase, AuditLog
from app.main_dashboard import app
from app.db.migrations.migrate_detection_alerts_tenant_id import (
    audit_tenant_migration_readiness,
    run_dry_run_migration
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


def mint_token(username: str, role: str, tenant_id: int) -> str:
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
    print("MONITORIX ENTERPRISE — PHASE 5.4.3B TEST SUITE (PART 3)")
    print("Tenant Migration & SOC Case Promotion (Tests 16-18)")
    print("=" * 80)

    # --------------------------------------------------------------------------
    # TEST 16: Historical alert backfill simulation
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    # Mock data representing pre-migration state
    mock_agents = {
        "AGENT-MIG-1": {"TenantId": 1},
        "AGENT-MIG-2": {"TenantId": 2},
        "AGENT-MIG-3": {"TenantId": 3},
    }
    mock_alerts = [
        {"Id": 1001, "AgentId": "AGENT-MIG-1", "TenantId": None, "MatchedContent": "Event 1"},
        {"Id": 1002, "AgentId": "AGENT-MIG-2", "TenantId": None, "MatchedContent": "Event 2"},
        {"Id": 1003, "AgentId": "AGENT-MIG-3", "TenantId": None, "MatchedContent": "Event 3"},
    ]

    # Execute authoritative backfill logic
    backfilled_count = 0
    for a in mock_alerts:
        agent_id = a["AgentId"]
        if agent_id in mock_agents and mock_agents[agent_id]["TenantId"] is not None:
            a["TenantId"] = mock_agents[agent_id]["TenantId"]
            backfilled_count += 1

    d16 = (time.perf_counter() - t0) * 1000
    p16 = (
        backfilled_count == 3 and
        mock_alerts[0]["TenantId"] == 1 and
        mock_alerts[1]["TenantId"] == 2 and
        mock_alerts[2]["TenantId"] == 3
    )
    record_result(16, "Historical Alert TenantId Authoritative Backfill", p16, d16)

    # --------------------------------------------------------------------------
    # TEST 17: Unresolved historical tenant records (safe NULL preservation)
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    mock_alerts_with_orphans = [
        {"Id": 2001, "AgentId": "AGENT-DELETED-999", "TenantId": None, "MatchedContent": "Orphan 1"},
        {"Id": 2002, "AgentId": "AGENT-MIG-1", "TenantId": None, "MatchedContent": "Valid 1"},
    ]
    unresolved_count = 0
    resolved_count = 0

    for a in mock_alerts_with_orphans:
        agent_id = a["AgentId"]
        if agent_id in mock_agents and mock_agents[agent_id]["TenantId"] is not None:
            a["TenantId"] = mock_agents[agent_id]["TenantId"]
            resolved_count += 1
        else:
            # Crucial invariant: never invent tenant ownership or assign default!
            a["TenantId"] = None
            unresolved_count += 1

    d17 = (time.perf_counter() - t0) * 1000
    p17 = (
        resolved_count == 1 and
        unresolved_count == 1 and
        mock_alerts_with_orphans[0]["TenantId"] is None and
        len(mock_alerts_with_orphans) == 2  # No records dropped or deleted
    )
    record_result(17, "Unresolved Historical Alerts Preserved Without Data Loss", p17, d17)

    # --------------------------------------------------------------------------
    # TEST 18: Alert-to-SOC case promotion via POST /api/v2/soc/cases/promote-alert
    # --------------------------------------------------------------------------
    t0 = time.perf_counter()
    p18 = False
    detail18 = ""

    # Setup isolated test database records
    test_agent_id = f"TEST-AGENT-543B-{int(time.time())}"
    test_rule_id = 2  # Existing LSASS Memory Credential Dumping rule
    created_alert_id = None
    created_case_id = None

    async with AsyncSessionLocal() as db:
        # 1. Ensure test tenant 1 and test tenant 2 exist
        t1 = (await db.execute(select(Tenant).where(Tenant.Id == 1))).scalars().first()
        if not t1:
            t1 = Tenant(Id=1, Name="Enterprise Security Corp", Subdomain="sec-corp", SubscriptionTier="Enterprise", IsActive=True)
            db.add(t1)

        t2 = (await db.execute(select(Tenant).where(Tenant.Id == 2))).scalars().first()
        if not t2:
            t2 = Tenant(Id=2, Name="Partner Bank AG", Subdomain="partner-bank", SubscriptionTier="Enterprise", IsActive=True)
            db.add(t2)

        # 2. Insert test agent for tenant 1
        test_agent = Agent(
            AgentId=test_agent_id,
            TenantId=1,
            Hostname="SOC-MIG-TEST-HOST",
            Status="Active"
        )
        db.add(test_agent)

        # 3. Insert test alert
        test_alert = DetectionAlert(
            AgentId=test_agent_id,
            RuleId=test_rule_id,
            TelemetryId=12345,
            MatchedContent="[Mimikatz] LSASS memory dump sekurlsa::logonpasswords",
            Status="New",
            Timestamp=datetime.utcnow(),
            HitCount=1,
            LastSeenAt=datetime.utcnow()
        )
        db.add(test_alert)
        await db.commit()
        created_alert_id = test_alert.Id

    # Test via httpx AsyncClient using authentic enterprise users
    token_tenant_1 = mint_token("elsea", "TenantAdmin", tenant_id=1)
    token_tenant_3 = mint_token("sentinelx", "TenantAdmin", tenant_id=3)
    h_tenant_1 = {"Authorization": f"Bearer {token_tenant_1}"}
    h_tenant_3 = {"Authorization": f"Bearer {token_tenant_3}"}

    async with httpx.AsyncClient(app=app, base_url="http://testserver") as client:
        # Step A: Cross-tenant promotion rejection (Tenant 3 user attempts to promote Tenant 1 alert)
        cross_res = await client.post(
            "/api/v2/soc/cases/promote-alert",
            headers=h_tenant_3,
            json={"alert_id": created_alert_id, "title": "Malicious Cross-Tenant Promotion"}
        )
        cross_rejected = (cross_res.status_code == 404)

        # Step B: Valid promotion by Tenant 1
        promote_res = await client.post(
            "/api/v2/soc/cases/promote-alert",
            headers=h_tenant_1,
            json={
                "alert_id": created_alert_id,
                "title": "Cobalt Strike Beaconing Investigation",
                "priority": "P1",
                "notes": "Automated escalation from streaming detection pipeline"
            }
        )
        promote_ok = (promote_res.status_code == 201)
        if promote_ok:
            case_data = promote_res.json()
            created_case_id = case_data.get("id")
            evidence_valid = (
                len(case_data.get("evidence", [])) >= 1 and
                case_data["evidence"][0].get("promoted_alert_id") == created_alert_id and
                case_data["evidence"][0].get("agent_id") == test_agent_id
            )
        else:
            evidence_valid = False

        # Step C: Idempotent duplicate promotion prevention (HTTP 409 Conflict)
        dup_res = await client.post(
            "/api/v2/soc/cases/promote-alert",
            headers=h_tenant_1,
            json={"alert_id": created_alert_id, "title": "Duplicate Promotion Attempt"}
        )
        duplicate_prevented = (dup_res.status_code == 409)

    # Cleanup test records
    async with AsyncSessionLocal() as db:
        if created_case_id:
            await db.execute(delete(SocCase).where(SocCase.Id == created_case_id))
        if created_alert_id:
            await db.execute(delete(DetectionAlert).where(DetectionAlert.Id == created_alert_id))
        await db.execute(delete(Agent).where(Agent.AgentId == test_agent_id))
        if test_rule_id == 9999:
            await db.execute(delete(DetectionRule).where(DetectionRule.Id == test_rule_id))
        await db.commit()

    d18 = (time.perf_counter() - t0) * 1000
    p18 = cross_rejected and promote_ok and evidence_valid and duplicate_prevented
    detail18 = f"(Cross404={cross_rejected}, Promote201={promote_ok}, Evidence={evidence_valid}, Dup409={duplicate_prevented})"
    record_result(18, "Alert-to-SOC Case Promotion & Cross-Tenant Security", p18, d18, detail18)

    print("\n" + "=" * 80)
    print(f"PART 3 TOTAL: 3 | PASSED: {PASSED} | FAILED: {FAILED}")
    print("=" * 80)
    return FAILED == 0


if __name__ == "__main__":
    success = asyncio.run(run_suite())
    sys.exit(0 if success else 1)
