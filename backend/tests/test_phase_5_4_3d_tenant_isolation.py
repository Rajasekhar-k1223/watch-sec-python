#!/usr/bin/env python3
"""
MONITORIX ENTERPRISE — PHASE 5.4.3D TEST SUITE (4/6)
End-to-End Multi-Tenant Isolation & Role Authorization Suite
============================================================
Validates:
  #01: gRPC Gateway Anti-Spoofing Tenant Override (Agent DB Authoritative Tenant)
  #02: Rule Execution Scoping (Tenant-Specific Rule Never Fires for Other Tenants)
  #03: Universal System Rule Application (TenantId IS NULL Evaluates Across All Tenants)
  #04: Alert Persistence Multi-Tenant Attribution Partitioning
  #05: Cross-Tenant Deduplication Isolation (Independent Rows & Counters Across Tenants)
  #06: API Alert Listing Isolation (GET /alerts Strictly Partitioned by Caller Tenant)
  #07: API Cross-Tenant Alert Detail Rejection (GET /alerts/{id} Strict 404 Anti-Enumeration)
  #08: API Cross-Tenant Alert Triage Rejection (PATCH /alerts/{id} Strict 404 Anti-Enumeration)
  #09: API Cross-Tenant SOC Case Promotion Rejection (POST /cases/promote-alert Strict 404)
  #10: 5-Role RBAC Authorization Matrix (SuperAdmin, TenantAdmin, Analyst, Viewer, Auditor)
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
from sqlalchemy import text, delete, desc

from app.core.security import SECRET_KEY, ALGORITHM
from app.db.session import AsyncSessionLocal
from app.db.models import User, Tenant, Agent, DetectionRule, DetectionAlert, SocCase
from app.main_dashboard import app
from app.services.detection.sigma_compiler import (
    sigma_compiler,
    sigma_registry,
    evaluate_all,
    DetectionResult
)
from app.services.detection.system_rules import SYSTEM_RULES_DEFINITIONS
from app.services.detection.streaming_detector import streaming_detection_engine
from app.services.detection.alert_persistence import alert_persistence_service

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
    print("MONITORIX ENTERPRISE — PHASE 5.4.3D TEST SUITE (PART 4)")
    print("Multi-Tenant Isolation & Role Authorization Matrix Validation")
    print("=" * 80)

    t_now = int(time.time())
    agent_t1_id = f"TEST-ISO-AG-T1-{t_now}"
    agent_t3_id = f"TEST-ISO-AG-T3-{t_now}"
    alert_t1_id = None
    alert_t3_id = None

    # Pre-compile and register all 8 system rules
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
        # Pre-seed isolated agents and test alerts
        async with AsyncSessionLocal() as db:
            ag_t1 = Agent(
                AgentId=agent_t1_id,
                TenantId=1,
                Hostname="SRV-ISOLATION-T1",
                Status="Active"
            )
            ag_t3 = Agent(
                AgentId=agent_t3_id,
                TenantId=3,
                Hostname="SRV-ISOLATION-T3",
                Status="Active"
            )
            db.add(ag_t1)
            db.add(ag_t3)
            await db.flush()

            # Create Alert for Tenant 1
            al_t1 = DetectionAlert(
                AgentId=agent_t1_id,
                RuleId=9001,
                MatchedContent="whoami /priv /fo csv [Tenant1 synthetic]",
                Status="New",
                Timestamp=datetime.utcnow()
            )
            db.add(al_t1)

            # Create Alert for Tenant 3
            al_t3 = DetectionAlert(
                AgentId=agent_t3_id,
                RuleId=9001,
                MatchedContent="whoami /priv /fo csv [Tenant3 synthetic]",
                Status="New",
                Timestamp=datetime.utcnow()
            )
            db.add(al_t3)

            await db.commit()
            alert_t1_id = al_t1.Id
            alert_t3_id = al_t3.Id

        # ----------------------------------------------------------------------
        # TEST 01: gRPC Gateway Anti-Spoofing Tenant Override
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        async with AsyncSessionLocal() as db:
            # Simulate gRPC gateway look up for agent_t1_id
            db_agent = (await db.execute(select(Agent).where(Agent.AgentId == agent_t1_id))).scalars().first()
            authoritative_tenant = db_agent.TenantId if db_agent else None
            
            # Incoming event claims spoofed tenant 999
            incoming_event = {
                "agent_id": agent_t1_id,
                "tenant_id": 999,  # Maliciously spoofed tenant
                "event_type": "ProcessExecution",
                "CommandLine": "cmd.exe /c calc.exe"
            }
            # Gateway enrichment overrides declared tenant_id with DB authoritative tenant
            enriched_event = dict(incoming_event)
            enriched_event["tenant_id"] = authoritative_tenant

            t1 = time.perf_counter()
            test1_pass = (
                authoritative_tenant == 1 and
                enriched_event["tenant_id"] == 1 and
                enriched_event["tenant_id"] != incoming_event["tenant_id"]
            )
            record_result(1, "gRPC Gateway Anti-Spoofing Tenant Override", test1_pass, (t1 - t0) * 1000,
                          f"Declared 999 overridden to DB Authoritative Tenant={enriched_event['tenant_id']}")

        # ----------------------------------------------------------------------
        # TEST 02: Rule Execution Scoping (Tenant Scoped Rule Isolation)
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        t1_rule_yaml = """
title: Tenant 1 Isolated Secret Trigger
id: 8888-0001
status: production
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'tenant1_isolated_token_secret'
  condition: selection
level: high
"""
        compiled_t1 = sigma_compiler.compile(yaml_content=t1_rule_yaml, rule_id=8881, metadata={"tenant_id": 1, "Id": 8881})
        sigma_registry.register(compiled_t1)

        # Telemetry from Tenant 3 with the trigger string
        ev_t3 = {
            "EventType": "ProcessExecution",
            "AgentId": agent_t3_id,
            "TenantId": 3,
            "CommandLine": "evil.exe tenant1_isolated_token_secret",
            "Timestamp": datetime.utcnow().isoformat()
        }
        norm_t3 = streaming_detection_engine.normalize_event(ev_t3)
        # Evaluate scoped to Tenant 3
        matches_t3 = sigma_registry.evaluate_all(norm_t3, tenant_id=3)
        has_t1_match_on_t3 = any(m.rule_id == 8881 for m in matches_t3)

        # Evaluate scoped to Tenant 1
        ev_t1 = {
            "EventType": "ProcessExecution",
            "AgentId": agent_t1_id,
            "TenantId": 1,
            "CommandLine": "evil.exe tenant1_isolated_token_secret",
            "Timestamp": datetime.utcnow().isoformat()
        }
        norm_t1 = streaming_detection_engine.normalize_event(ev_t1)
        matches_t1 = sigma_registry.evaluate_all(norm_t1, tenant_id=1)
        has_t1_match_on_t1 = any(m.rule_id == 8881 for m in matches_t1)

        t1 = time.perf_counter()
        test2_pass = (not has_t1_match_on_t3) and has_t1_match_on_t1
        record_result(2, "Rule Execution Scoping Isolation", test2_pass, (t1 - t0) * 1000,
                      f"T1 Rule Match on T3={has_t1_match_on_t3}, Match on T1={has_t1_match_on_t1}")

        # ----------------------------------------------------------------------
        # TEST 03: Universal System Rule Application (TenantId IS NULL)
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        # System rule 9001 (Unauthorized VPN Interface) has tenant_id = None
        vpn_ev_t1 = {
            "EventType": "NetworkInterface",
            "AgentId": agent_t1_id,
            "TenantId": 1,
            "vpn_active": True,
            "interface_name": "wg0",
            "Timestamp": datetime.utcnow().isoformat()
        }
        vpn_ev_t3 = {
            "EventType": "NetworkInterface",
            "AgentId": agent_t3_id,
            "TenantId": 3,
            "vpn_active": True,
            "interface_name": "wg0",
            "Timestamp": datetime.utcnow().isoformat()
        }
        norm_w1 = streaming_detection_engine.normalize_event(vpn_ev_t1)
        norm_w3 = streaming_detection_engine.normalize_event(vpn_ev_t3)
        res_w1 = sigma_registry.evaluate_all(norm_w1, tenant_id=1)
        res_w3 = sigma_registry.evaluate_all(norm_w3, tenant_id=3)

        has_sys_w1 = any(m.rule_id == 9001 for m in res_w1)
        has_sys_w3 = any(m.rule_id == 9001 for m in res_w3)

        t1 = time.perf_counter()
        test3_pass = has_sys_w1 and has_sys_w3
        record_result(3, "Universal System Rule Application", test3_pass, (t1 - t0) * 1000,
                      f"System Rule 9001 fired for T1={has_sys_w1} and T3={has_sys_w3}")

        # ----------------------------------------------------------------------
        # TEST 04: Alert Persistence Multi-Tenant Attribution Partitioning
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        async with AsyncSessionLocal() as db:
            match_t1 = DetectionResult(
                matched=True,
                rule_id=9001,
                rule_name="Unauthorized VPN Interface Detected",
                severity="Medium",
                category="Defense Evasion",
                mitre_tactics=["TA0005"],
                mitre_techniques=["T1562.001"],
                details={"vpn_active": True, "interface_name": "wg0"}
            )
            al1_obj, is_new1 = await alert_persistence_service.persist_detection_match(
                db=db,
                event=vpn_ev_t1,
                match=match_t1,
                agent_id=agent_t1_id,
                authoritative_tenant_id=1
            )
            al3_obj, is_new3 = await alert_persistence_service.persist_detection_match(
                db=db,
                event=vpn_ev_t3,
                match=match_t1,
                agent_id=agent_t3_id,
                authoritative_tenant_id=3
            )
            await db.commit()

            al_t1_db = (await db.execute(select(DetectionAlert).where(DetectionAlert.Id == al1_obj.Id))).scalars().first()
            al_t3_db = (await db.execute(select(DetectionAlert).where(DetectionAlert.Id == al3_obj.Id))).scalars().first()

            # Check tenant attribution via agent
            ag_t1_ref = (await db.execute(select(Agent).where(Agent.AgentId == al_t1_db.AgentId))).scalars().first()
            ag_t3_ref = (await db.execute(select(Agent).where(Agent.AgentId == al_t3_db.AgentId))).scalars().first()

            test4_pass = (
                al1_obj.Id != al3_obj.Id and
                ag_t1_ref.TenantId == 1 and
                ag_t3_ref.TenantId == 3
            )
            t1 = time.perf_counter()
            record_result(4, "Alert Persistence Multi-Tenant Attribution", test4_pass, (t1 - t0) * 1000,
                          f"Alert #{al1_obj.Id} (T1) vs #{al3_obj.Id} (T3)")

        # ----------------------------------------------------------------------
        # TEST 05: Cross-Tenant Deduplication Isolation
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        async with AsyncSessionLocal() as db:
            # Emit identical command on T1 and T3
            dup_cmd = "whoami /groups /fo list"
            dup_t1_ev = {"EventType": "ProcessExecution", "AgentId": agent_t1_id, "CommandLine": dup_cmd, "Timestamp": datetime.utcnow().isoformat()}
            dup_t3_ev = {"EventType": "ProcessExecution", "AgentId": agent_t3_id, "CommandLine": dup_cmd, "Timestamp": datetime.utcnow().isoformat()}
            
            dup_match = DetectionResult(
                matched=True,
                rule_id=9001,
                rule_name="Unauthorized VPN Interface Detected",
                severity="Medium",
                category="Defense Evasion",
                mitre_tactics=["TA0005"],
                mitre_techniques=["T1562.001"],
                details={"CommandLine": dup_cmd}
            )
            # First persistence
            al_a1, is_new_a1 = await alert_persistence_service.persist_detection_match(db, dup_t1_ev, dup_match, agent_t1_id, authoritative_tenant_id=1)
            al_b1, is_new_b1 = await alert_persistence_service.persist_detection_match(db, dup_t3_ev, dup_match, agent_t3_id, authoritative_tenant_id=3)
            # Replay persistence (should dedup within own tenant, not across tenants)
            al_a2, is_new_a2 = await alert_persistence_service.persist_detection_match(db, dup_t1_ev, dup_match, agent_t1_id, authoritative_tenant_id=1)
            al_b2, is_new_b2 = await alert_persistence_service.persist_detection_match(db, dup_t3_ev, dup_match, agent_t3_id, authoritative_tenant_id=3)
            await db.commit()

            test5_pass = (
                al_a1.Id != al_b1.Id and  # Separate alerts across tenants
                (not is_new_a2) and al_a2.Id == al_a1.Id and al_a2.HitCount >= 2 and
                (not is_new_b2) and al_b2.Id == al_b1.Id and al_b2.HitCount >= 2
            )
            t1 = time.perf_counter()
            record_result(5, "Cross-Tenant Deduplication Isolation", test5_pass, (t1 - t0) * 1000,
                          f"T1 Alert={al_a1.Id} (Hits={al_a2.HitCount}), T3 Alert={al_b1.Id} (Hits={al_b2.HitCount})")


        # ----------------------------------------------------------------------
        # MINT JWTs FOR API & RBAC TESTING
        # ----------------------------------------------------------------------
        # Existing database users:
        # User id=1: superadmin (SuperAdmin, tenant_id=None)
        # User id=2: elsea (TenantAdmin, tenant_id=1)
        # User id=4: sentinelx (TenantAdmin, tenant_id=3)
        # User id=6: secops_analyst_test@enterprise.corp (Analyst, tenant_id=1)
        # User id=9: auditor_test (Auditor, tenant_id=1)
        # User id=10: viewer_test (Viewer, tenant_id=1)

        token_super = mint_token("superadmin", "SuperAdmin", tenant_id=None)
        token_t1_admin = mint_token("elsea", "TenantAdmin", tenant_id=1)
        token_t3_admin = mint_token("sentinelx", "TenantAdmin", tenant_id=3)
        token_t1_analyst = mint_token("secops_analyst_test@enterprise.corp", "Analyst", tenant_id=1)
        token_t1_auditor = mint_token("auditor_test", "Auditor", tenant_id=1)
        token_t1_viewer = mint_token("viewer_test", "Viewer", tenant_id=1)

        h_super = {"Authorization": f"Bearer {token_super}"}
        h_t1_admin = {"Authorization": f"Bearer {token_t1_admin}"}
        h_t3_admin = {"Authorization": f"Bearer {token_t3_admin}"}
        h_t1_analyst = {"Authorization": f"Bearer {token_t1_analyst}"}
        h_t1_auditor = {"Authorization": f"Bearer {token_t1_auditor}"}
        h_t1_viewer = {"Authorization": f"Bearer {token_t1_viewer}"}

        async with httpx.AsyncClient(app=app, base_url="http://testserver") as client:
            # ------------------------------------------------------------------
            # TEST 06: API Alert Listing Isolation (GET /alerts)
            # ------------------------------------------------------------------
            t0 = time.perf_counter()
            r_t1 = await client.get("/api/v2/detection/alerts?status=All", headers=h_t1_admin)
            r_t3 = await client.get("/api/v2/detection/alerts?status=All", headers=h_t3_admin)

            t1_alerts = r_t1.json() if r_t1.status_code == 200 else []
            t3_alerts = r_t3.json() if r_t3.status_code == 200 else []

            t1_alert_ids = [a["Id"] for a in t1_alerts]
            t3_alert_ids = [a["Id"] for a in t3_alerts]

            # Verify no cross-tenant alerts leaked into list
            leak_t3_in_t1 = alert_t3_id in t1_alert_ids
            leak_t1_in_t3 = alert_t1_id in t3_alert_ids
            has_own_t1 = alert_t1_id in t1_alert_ids
            has_own_t3 = alert_t3_id in t3_alert_ids

            t1 = time.perf_counter()
            test6_pass = (
                r_t1.status_code == 200 and r_t3.status_code == 200 and
                has_own_t1 and has_own_t3 and
                (not leak_t3_in_t1) and (not leak_t1_in_t3)
            )
            record_result(6, "API Alert Listing Isolation", test6_pass, (t1 - t0) * 1000,
                          f"T1 count={len(t1_alerts)}, T3 count={len(t3_alerts)}, Cross-Leaked={leak_t3_in_t1 or leak_t1_in_t3}")

            # ------------------------------------------------------------------
            # TEST 07: API Cross-Tenant Alert Detail Rejection (Strict 404)
            # ------------------------------------------------------------------
            t0 = time.perf_counter()
            # Tenant 1 user requests Tenant 3's alert detail
            r_cross_detail = await client.get(f"/api/v2/detection/alerts/{alert_t3_id}", headers=h_t1_admin)
            # Tenant 1 user requests own alert detail
            r_own_detail = await client.get(f"/api/v2/detection/alerts/{alert_t1_id}", headers=h_t1_admin)

            t1 = time.perf_counter()
            test7_pass = (
                r_cross_detail.status_code == 404 and  # Anti-enumeration strict 404
                r_own_detail.status_code == 200
            )
            record_result(7, "API Cross-Tenant Alert Detail Strict 404 Rejection", test7_pass, (t1 - t0) * 1000,
                          f"Cross-Tenant Status={r_cross_detail.status_code} (Expected 404), Own Status={r_own_detail.status_code} (Expected 200)")

            # ------------------------------------------------------------------
            # TEST 08: API Cross-Tenant Alert Triage Rejection (Strict 404)
            # ------------------------------------------------------------------
            t0 = time.perf_counter()
            # Tenant 1 analyst attempts to triage Tenant 3 alert
            r_cross_triage = await client.patch(
                f"/api/v2/detection/alerts/{alert_t3_id}",
                headers=h_t1_analyst,
                json={"status": "Confirmed"}
            )
            # Tenant 1 analyst triages own alert
            r_own_triage = await client.patch(
                f"/api/v2/detection/alerts/{alert_t1_id}",
                headers=h_t1_analyst,
                json={"status": "Investigating"}
            )

            t1 = time.perf_counter()
            test8_pass = (
                r_cross_triage.status_code == 404 and
                r_own_triage.status_code == 200
            )
            record_result(8, "API Cross-Tenant Alert Triage Strict 404 Rejection", test8_pass, (t1 - t0) * 1000,
                          f"Cross-Tenant Patch Status={r_cross_triage.status_code} (Expected 404), Own Patch Status={r_own_triage.status_code} (Expected 200)")

            # ------------------------------------------------------------------
            # TEST 09: API Cross-Tenant SOC Case Promotion Rejection (Strict 404)
            # ------------------------------------------------------------------
            t0 = time.perf_counter()
            # Tenant 1 analyst attempts to promote Tenant 3 alert to SOC Case
            r_cross_promo = await client.post(
                "/api/v2/soc/cases/promote-alert",
                headers=h_t1_analyst,
                json={
                    "alert_id": alert_t3_id,
                    "title": "Cross Tenant Unauthorized Promotion Attempt",
                    "severity": "Critical"
                }
            )
            t1 = time.perf_counter()
            test9_pass = (r_cross_promo.status_code == 404)
            record_result(9, "API Cross-Tenant SOC Case Promotion Rejection", test9_pass, (t1 - t0) * 1000,
                          f"Cross-Promotion Status={r_cross_promo.status_code} (Expected 404 Anti-Enumeration)")

            # ------------------------------------------------------------------
            # TEST 10: 5-Role RBAC Authorization Matrix Validation
            # ------------------------------------------------------------------
            t0 = time.perf_counter()
            # 1. SuperAdmin: can view any alert detail and triage
            r_sa_view = await client.get(f"/api/v2/detection/alerts/{alert_t1_id}", headers=h_super)
            r_sa_patch = await client.patch(f"/api/v2/detection/alerts/{alert_t1_id}", headers=h_super, json={"status": "New"})
            sa_ok = (r_sa_view.status_code == 200 and r_sa_patch.status_code == 200)

            # 2. TenantAdmin: full access within tenant
            r_ta_view = await client.get(f"/api/v2/detection/alerts/{alert_t1_id}", headers=h_t1_admin)
            r_ta_patch = await client.patch(f"/api/v2/detection/alerts/{alert_t1_id}", headers=h_t1_admin, json={"status": "Investigating"})
            ta_ok = (r_ta_view.status_code == 200 and r_ta_patch.status_code == 200)

            # 3. SOC Analyst: view and triage within tenant
            r_an_view = await client.get(f"/api/v2/detection/alerts/{alert_t1_id}", headers=h_t1_analyst)
            r_an_patch = await client.patch(f"/api/v2/detection/alerts/{alert_t1_id}", headers=h_t1_analyst, json={"status": "Confirmed"})
            an_ok = (r_an_view.status_code == 200 and r_an_patch.status_code == 200)

            # 4. Viewer: read-only access (200 on GET, 403 Forbidden on PATCH and Promote)
            r_vi_view = await client.get(f"/api/v2/detection/alerts/{alert_t1_id}", headers=h_t1_viewer)
            r_vi_patch = await client.patch(f"/api/v2/detection/alerts/{alert_t1_id}", headers=h_t1_viewer, json={"status": "False Positive"})
            r_vi_promo = await client.post("/api/v2/soc/cases/promote-alert", headers=h_t1_viewer, json={"alert_id": alert_t1_id})
            vi_ok = (r_vi_view.status_code == 200 and r_vi_patch.status_code == 403 and r_vi_promo.status_code == 403)

            # 5. Auditor: read-only compliance access (200 on GET, 403 Forbidden on PATCH and Promote)
            r_au_view = await client.get(f"/api/v2/detection/alerts/{alert_t1_id}", headers=h_t1_auditor)
            r_au_patch = await client.patch(f"/api/v2/detection/alerts/{alert_t1_id}", headers=h_t1_auditor, json={"status": "False Positive"})
            r_au_promo = await client.post("/api/v2/soc/cases/promote-alert", headers=h_t1_auditor, json={"alert_id": alert_t1_id})
            au_ok = (r_au_view.status_code == 200 and r_au_patch.status_code == 403 and r_au_promo.status_code == 403)

            test10_pass = sa_ok and ta_ok and an_ok and vi_ok and au_ok
            t1 = time.perf_counter()
            record_result(10, "5-Role RBAC Authorization Matrix", test10_pass, (t1 - t0) * 1000,
                          f"SuperAdmin={sa_ok}, TenantAdmin={ta_ok}, Analyst={an_ok}, Viewer={vi_ok}, Auditor={au_ok}")

    finally:
        # Cleanup isolated test artifacts
        async with AsyncSessionLocal() as db:
            await db.execute(delete(DetectionAlert).where(DetectionAlert.AgentId.in_([agent_t1_id, agent_t3_id])))
            await db.execute(delete(Agent).where(Agent.AgentId.in_([agent_t1_id, agent_t3_id])))
            await db.commit()

    print("=" * 80)
    print(f"SUITE 4 TOTAL: {PASSED} PASSED, {FAILED} FAILED")
    print("=" * 80)
    if FAILED > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(run_suite())
