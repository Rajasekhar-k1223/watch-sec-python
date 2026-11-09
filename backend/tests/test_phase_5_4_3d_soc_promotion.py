#!/usr/bin/env python3
"""
MONITORIX ENTERPRISE — PHASE 5.4.3D TEST SUITE (6/6)
SOC Case Promotion & Incident Workflow Integration Suite
========================================================
Validates:
  #01: SOC Alert Listing API Enrichment & Field Mapping (GET /detection/alerts)
  #02: Single Alert Promotion to SOC Case (POST /cases/promote-alert -> 201)
  #03: DetectionAlert Status Transition on Promotion ('New' -> 'Investigating')
  #04: Idempotency & Duplicate Promotion Prevention (Strict 409 Conflict)
  #05: Cross-Tenant Promotion Rejection (Strict 404 Anti-Enumeration)
  #06: RBAC Authorization Matrix on Promotion (SuperAdmin, TenantAdmin, Analyst vs Viewer/Auditor)
  #07: MITRE ATT&CK & Forensic Evidence Preservation in Case Payload
  #08: Case Detail Retrieval via SOC API (GET /cases/{id} -> 200)
  #09: SOC Case Lifecycle State Machine Transitions (NEW -> TRIAGED -> CONTAINED)
  #10: Promotion Execution Latency Benchmark (< 100ms SLA)
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
from app.db.models import User, Tenant, Agent, DetectionRule, DetectionAlert, SocCase, SocCaseComment, AuditLog
from app.main_dashboard import app

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
    print("MONITORIX ENTERPRISE — PHASE 5.4.3D TEST SUITE (PART 6)")
    print("SOC Case Promotion & Incident Workflow Integration Validation")
    print("=" * 80)

    t_now = int(time.time())
    agent_t1_id = f"TEST-SOC-AG-T1-{t_now}"
    agent_t3_id = f"TEST-SOC-AG-T3-{t_now}"

    # Tokens for testing
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

    test_alerts_created = []
    test_cases_created = []

    try:
        # Pre-seed isolated agents and test alerts
        async with AsyncSessionLocal() as db:
            ag_t1 = Agent(
                AgentId=agent_t1_id,
                TenantId=1,
                Hostname="SRV-SOC-T1-HOST",
                Status="Active"
            )
            ag_t3 = Agent(
                AgentId=agent_t3_id,
                TenantId=3,
                Hostname="SRV-SOC-T3-HOST",
                Status="Active"
            )
            db.add_all([ag_t1, ag_t3])
            await db.flush()

            # Create test alerts for Tenant 1
            # Alert A: Rule 9008 (Sandbox threat blocked)
            al_a = DetectionAlert(
                AgentId=agent_t1_id,
                RuleId=9008,
                MatchedContent="cmd.exe /c malware_detonation_payload.exe",
                Status="New",
                HitCount=1,
                Timestamp=datetime.utcnow()
            )
            # Alert B: Rule 9001 (Unauthorized VPN)
            al_b = DetectionAlert(
                AgentId=agent_t1_id,
                RuleId=9001,
                MatchedContent="openvpn --config office_bypass.ovpn",
                Status="New",
                HitCount=3,
                Timestamp=datetime.utcnow()
            )
            # Alert C: Tenant 3 alert for cross-tenant testing
            al_c = DetectionAlert(
                AgentId=agent_t3_id,
                RuleId=9002,
                MatchedContent="procdump.exe -ma lsass.exe lsass.dmp",
                Status="New",
                HitCount=1,
                Timestamp=datetime.utcnow()
            )
            db.add_all([al_a, al_b, al_c])
            await db.commit()

            test_alerts_created.extend([al_a.Id, al_b.Id, al_c.Id])
            alert_a_id = al_a.Id
            alert_b_id = al_b.Id
            alert_c_id = al_c.Id

        async with httpx.AsyncClient(app=app, base_url="http://testserver") as client:
            # ------------------------------------------------------------------
            # TEST 01: SOC Alert Listing API Enrichment & Field Mapping
            # ------------------------------------------------------------------
            t0 = time.perf_counter()
            r_list = await client.get("/api/v2/detection/alerts?status=All", headers=h_t1_analyst)
            t1 = time.perf_counter()

            test1_pass = False
            found_alert_a = None
            if r_list.status_code == 200:
                alerts_data = r_list.json()
                for a in alerts_data:
                    if a.get("Id") == alert_a_id:
                        found_alert_a = a
                        break

            if found_alert_a:
                required_fields = ["Id", "AgentId", "RuleId", "RuleName", "Severity", "MitreTactic", "MitreTechnique", "Status", "HitCount", "LastSeenAt"]
                has_all_fields = all(f in found_alert_a for f in required_fields)
                test1_pass = has_all_fields and found_alert_a["AgentId"] == agent_t1_id

            record_result(1, "SOC Alert Listing API Enrichment", test1_pass, (t1 - t0) * 1000,
                          f"Alert #{alert_a_id} found in list with all canonical fields={test1_pass}")

            # ------------------------------------------------------------------
            # TEST 02: Single Alert Promotion to SOC Case (201 Created)
            # ------------------------------------------------------------------
            t0 = time.perf_counter()
            promo_payload = {
                "alert_id": alert_a_id,
                "title": "Malware Execution Blocked by Sandbox on Host",
                "priority": "P1",
                "notes": "Automated synthetic promotion test for Phase 5.4.3D validation"
            }
            r_promo = await client.post("/api/v2/soc/cases/promote-alert", headers=h_t1_analyst, json=promo_payload)
            t1 = time.perf_counter()

            case_a_id = None
            case_a_num = None
            test2_pass = False
            if r_promo.status_code == 201:
                case_data = r_promo.json()
                case_a_id = case_data.get("id") or case_data.get("Id")
                case_a_num = case_data.get("case_number") or case_data.get("CaseNumber")
                if case_a_id:
                    test_cases_created.append(case_a_id)
                test2_pass = (
                    case_a_id is not None and
                    case_a_num is not None and
                    case_a_num.startswith("CASE-") and
                    case_data.get("title") == promo_payload["title"]
                )

            record_result(2, "Single Alert Promotion to SOC Case", test2_pass, (t1 - t0) * 1000,
                          f"Status={r_promo.status_code} (Expected 201), Case #{case_a_id} ({case_a_num})")

            # ------------------------------------------------------------------
            # TEST 03: DetectionAlert Status Transition on Promotion
            # ------------------------------------------------------------------
            t0 = time.perf_counter()
            r_al_check = await client.get(f"/api/v2/detection/alerts/{alert_a_id}", headers=h_t1_analyst)
            t1 = time.perf_counter()

            test3_pass = False
            if r_al_check.status_code == 200:
                al_data = r_al_check.json()
                # Status must have automatically updated to 'Investigating'
                test3_pass = (al_data.get("Status") == "Investigating")

            record_result(3, "Alert Status Transition on Promotion", test3_pass, (t1 - t0) * 1000,
                          f"Alert #{alert_a_id} Status={al_data.get('Status') if r_al_check.status_code == 200 else 'ERR'} (Expected 'Investigating')")

            # ------------------------------------------------------------------
            # TEST 04: Idempotency & Duplicate Promotion Prevention (409 Conflict)
            # ------------------------------------------------------------------
            t0 = time.perf_counter()
            r_dup_promo = await client.post("/api/v2/soc/cases/promote-alert", headers=h_t1_analyst, json=promo_payload)
            t1 = time.perf_counter()

            test4_pass = (r_dup_promo.status_code == 409)
            err_msg = r_dup_promo.json().get("detail", "") if r_dup_promo.status_code == 409 else ""
            record_result(4, "Duplicate Promotion Prevention (409 Conflict)", test4_pass, (t1 - t0) * 1000,
                          f"Status={r_dup_promo.status_code} (Expected 409), Detail: {err_msg[:60]}")

            # ------------------------------------------------------------------
            # TEST 05: Cross-Tenant Promotion Rejection (Strict 404)
            # ------------------------------------------------------------------
            t0 = time.perf_counter()
            # Tenant 1 analyst attempts to promote Tenant 3 alert (alert_c_id)
            cross_payload = {
                "alert_id": alert_c_id,
                "title": "Cross Tenant Malicious Promotion"
            }
            r_cross = await client.post("/api/v2/soc/cases/promote-alert", headers=h_t1_analyst, json=cross_payload)
            t1 = time.perf_counter()

            test5_pass = (r_cross.status_code == 404)
            record_result(5, "Cross-Tenant Promotion Strict 404 Rejection", test5_pass, (t1 - t0) * 1000,
                          f"Cross Tenant Status={r_cross.status_code} (Expected 404 Anti-Enumeration)")

            # ------------------------------------------------------------------
            # TEST 06: RBAC Authorization Matrix on Alert Promotion
            # ------------------------------------------------------------------
            t0 = time.perf_counter()
            # We will use alert_b_id for RBAC checks
            # 1. Viewer attempt -> 403 Forbidden
            r_vi = await client.post("/api/v2/soc/cases/promote-alert", headers=h_t1_viewer, json={"alert_id": alert_b_id})
            # 2. Auditor attempt -> 403 Forbidden
            r_au = await client.post("/api/v2/soc/cases/promote-alert", headers=h_t1_auditor, json={"alert_id": alert_b_id})
            # 3. Tenant Admin attempt -> 201 Created
            r_ta = await client.post("/api/v2/soc/cases/promote-alert", headers=h_t1_admin, json={"alert_id": alert_b_id, "title": "Promoted by Tenant Admin"})
            if r_ta.status_code == 201:
                test_cases_created.append(r_ta.json().get("id"))

            test6_pass = (
                r_vi.status_code == 403 and
                r_au.status_code == 403 and
                r_ta.status_code == 201
            )
            t1 = time.perf_counter()
            record_result(6, "RBAC Authorization Matrix on Promotion", test6_pass, (t1 - t0) * 1000,
                          f"Viewer={r_vi.status_code} (403), Auditor={r_au.status_code} (403), TenantAdmin={r_ta.status_code} (201)")

            # ------------------------------------------------------------------
            # TEST 07: MITRE ATT&CK & Forensic Evidence Preservation
            # ------------------------------------------------------------------
            t0 = time.perf_counter()
            async with AsyncSessionLocal() as db:
                case_row = (await db.execute(select(SocCase).where(SocCase.Id == case_a_id))).scalars().first()
                ev_data = json.loads(case_row.EvidenceJson) if case_row and case_row.EvidenceJson else []
                mitre_data = json.loads(case_row.MitreMapJson) if case_row and case_row.MitreMapJson else []

                has_alert_ref = any(e.get("promoted_alert_id") == alert_a_id for e in ev_data)
                has_agent_ref = any(e.get("agent_id") == agent_t1_id for e in ev_data)
                has_promoter = any(e.get("promoted_by") == "secops_analyst_test@enterprise.corp" for e in ev_data)
                has_mitre_tactic = any(m.get("tactic") is not None for m in mitre_data)

                test7_pass = (has_alert_ref and has_agent_ref and has_promoter and has_mitre_tactic)

            t1 = time.perf_counter()
            record_result(7, "MITRE ATT&CK & Forensic Evidence Preservation", test7_pass, (t1 - t0) * 1000,
                          f"AlertRef={has_alert_ref}, AgentRef={has_agent_ref}, Promoter={has_promoter}, Mitre={has_mitre_tactic}")

            # ------------------------------------------------------------------
            # TEST 08: Case Detail Retrieval via SOC API
            # ------------------------------------------------------------------
            t0 = time.perf_counter()
            r_get_case = await client.get(f"/api/v2/soc/cases/{case_a_id}", headers=h_t1_analyst)
            t1 = time.perf_counter()

            test8_pass = False
            if r_get_case.status_code == 200:
                c_detail = r_get_case.json()
                test8_pass = (
                    c_detail.get("id") == case_a_id and
                    c_detail.get("case_number") == case_a_num and
                    c_detail.get("status") == "NEW"
                )

            record_result(8, "Case Detail Retrieval via SOC API", test8_pass, (t1 - t0) * 1000,
                          f"Status={r_get_case.status_code} (Expected 200), Case Number={case_a_num}")

            # ------------------------------------------------------------------
            # TEST 09: SOC Case Lifecycle State Machine Transitions
            # ------------------------------------------------------------------
            t0 = time.perf_counter()
            # 1. NEW -> TRIAGED (Valid)
            r_st1 = await client.patch(
                f"/api/v2/soc/cases/{case_a_id}/status",
                headers=h_t1_analyst,
                json={"status": "TRIAGED", "notes": "Initial triage complete; confirmed true positive sandbox block."}
            )
            # 2. TRIAGED -> CONTAINED (Valid)
            r_st2 = await client.patch(
                f"/api/v2/soc/cases/{case_a_id}/status",
                headers=h_t1_analyst,
                json={"status": "CONTAINED", "notes": "Host isolated and malicious binary quarantined."}
            )
            # 3. CONTAINED -> NEW (Invalid transition, should return 400 Bad Request)
            r_st_inv = await client.patch(
                f"/api/v2/soc/cases/{case_a_id}/status",
                headers=h_t1_analyst,
                json={"status": "NEW", "notes": "Illegal backwards transition attempt"}
            )

            test9_pass = (
                r_st1.status_code == 200 and
                r_st2.status_code == 200 and
                r_st_inv.status_code == 400
            )
            t1 = time.perf_counter()
            record_result(9, "SOC Case Lifecycle State Machine Transitions", test9_pass, (t1 - t0) * 1000,
                          f"NEW->TRIAGED={r_st1.status_code}, TRIAGED->CONTAINED={r_st2.status_code}, Invalid Transition={r_st_inv.status_code} (400)")

            # ------------------------------------------------------------------
            # TEST 10: Promotion Execution Latency Benchmark
            # ------------------------------------------------------------------
            # Seed another alert for latency measurement
            async with AsyncSessionLocal() as db:
                bench_alert = DetectionAlert(
                    AgentId=agent_t1_id,
                    RuleId=9003,
                    MatchedContent="iptables -F [Benchmark Alert]",
                    Status="New",
                    Timestamp=datetime.utcnow()
                )
                db.add(bench_alert)
                await db.commit()
                test_alerts_created.append(bench_alert.Id)
                bench_alert_id = bench_alert.Id

            t0 = time.perf_counter()
            r_bench = await client.post(
                "/api/v2/soc/cases/promote-alert",
                headers=h_t1_analyst,
                json={"alert_id": bench_alert_id, "title": "Latency Benchmark Promotion"}
            )
            t1 = time.perf_counter()
            latency_ms = (t1 - t0) * 1000

            if r_bench.status_code == 201:
                test_cases_created.append(r_bench.json().get("id"))

            test10_pass = (r_bench.status_code == 201 and latency_ms < 100.0)
            record_result(10, "Promotion Execution Latency Benchmark", test10_pass, latency_ms,
                          f"Execution Latency={latency_ms:.2f}ms (Status={r_bench.status_code}, SLA < 100ms)")

    finally:
        # Cleanup isolated test cases, alerts, and agents
        async with AsyncSessionLocal() as db:
            if test_cases_created:
                await db.execute(delete(SocCaseComment).where(SocCaseComment.CaseId.in_(test_cases_created)))
                await db.execute(delete(SocCase).where(SocCase.Id.in_(test_cases_created)))
            if test_alerts_created:
                await db.execute(delete(DetectionAlert).where(DetectionAlert.Id.in_(test_alerts_created)))
            await db.execute(delete(Agent).where(Agent.AgentId.in_([agent_t1_id, agent_t3_id])))
            await db.commit()

    print("=" * 80)
    print(f"SUITE 6 TOTAL: {PASSED} PASSED, {FAILED} FAILED")
    print("=" * 80)
    if FAILED > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(run_suite())
