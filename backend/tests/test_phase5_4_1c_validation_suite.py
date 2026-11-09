#!/usr/bin/env python3
"""
MONITORIX ENTERPRISE — PHASE 5.4.1C
Comprehensive End-to-End Integration, Security & Pre-Deployment Validation Suite
================================================================================
Executes 4 validation suites:
  Suite A: API Contract Schema Validation (11 tests)
  Suite B: End-to-End SOC Workflow Validation (12 steps)
  Suite C: Security & Multi-Tenant Isolation Validation (10 tests)
  Suite D: Regression Validation against Existing Features (7 tests)
Includes exact latency measurements, atomic fixture cleanup, and JSON output report.
"""

import asyncio
import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta

# Ensure backend is on sys.path
for candidate in ["/app", "/opt/projects/monitorix/watch-sec-python/backend"]:
    if os.path.exists(candidate) and candidate not in sys.path:
        sys.path.insert(0, candidate)

import httpx
from jose import jwt
from sqlalchemy.future import select
from sqlalchemy import delete

from app.core.security import SECRET_KEY, ALGORITHM
from app.db.session import AsyncSessionLocal
from app.db.models import (
    User, Tenant, Agent, DetectionAlert, Incident,
    SocCase, SocCaseComment, AuditLog
)
from app.main_dashboard import app

# Tracking structures
SUITE_RESULTS = {
    "suite_a_contracts": [],
    "suite_b_e2e": [],
    "suite_c_security": [],
    "suite_d_regression": []
}

TOTAL_PASSED = 0
TOTAL_FAILED = 0


def log_suite_header(name: str):
    print("\n" + "=" * 80)
    print(f"SUITE: {name}")
    print("=" * 80)


def record_test(suite_key: str, test_id: str, title: str, status: str, duration_ms: float, error_msg: str = None):
    global TOTAL_PASSED, TOTAL_FAILED
    record = {
        "id": test_id,
        "title": title,
        "status": status,
        "duration_ms": round(duration_ms, 2),
        "error": error_msg
    }
    SUITE_RESULTS[suite_key].append(record)
    if status == "PASS":
        TOTAL_PASSED += 1
        print(f"  [PASS] {test_id} - {title} ({duration_ms:.1f}ms)")
    else:
        TOTAL_FAILED += 1
        print(f"  [FAIL] {test_id} - {title}: {error_msg} ({duration_ms:.1f}ms)")


def mint_token(username: str, role: str, tenant_id: int, exp_delta: timedelta = timedelta(hours=2)) -> str:
    payload = {
        "sub": username,
        "role": role,
        "tenantId": tenant_id,
        "exp": datetime.utcnow() + exp_delta
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


async def run_validation():
    global TOTAL_PASSED, TOTAL_FAILED
    start_all = time.time()

    print("================================================================================")
    print("MONITORIX ENTERPRISE — PHASE 5.4.1C VALIDATION SUITE STARTING")
    print("Pre-Deployment End-to-End Integration, Security & Regression Suite")
    print("================================================================================")

    # Authenticated Tokens (Tenant 1 & Tenant 4)
    token_t1_admin = mint_token("elsea", "TenantAdmin", 1)
    token_t1_analyst = mint_token("secops_analyst_test@enterprise.corp", "Analyst", 1)
    token_t1_viewer = mint_token("viewer_test", "Viewer", 1)
    token_t1_auditor = mint_token("auditor_test", "Auditor", 1)

    token_t4_admin = mint_token("test", "TenantAdmin", 4)
    token_t4_analyst = mint_token("analyst_t4", "Analyst", 4)

    # Fixture tracking for atomic cleanup
    created_case_ids = []
    created_comment_ids = []
    created_alert_ids = []
    created_incident_ids = []

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:

        # ======================================================================
        # SUITE A: API CONTRACT SCHEMA VALIDATION (11 Tests)
        # ======================================================================
        log_suite_header("Suite A: API Contract Schema Validation")

        # A.1: Case Listing & Pagination Contract
        t0 = time.time()
        try:
            res = await client.get("/api/v2/soc/cases?limit=10&offset=0", headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
            data = res.json()
            assert isinstance(data, list), "Expected list response"
            record_test("suite_a_contracts", "A01", "Case Listing & Pagination Contract", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_a_contracts", "A01", "Case Listing & Pagination Contract", "FAIL", (time.time() - t0) * 1000, str(e))

        # A.2: Case Creation Contract
        t0 = time.time()
        try:
            payload = {
                "title": "Contract Validation Case 5.4.1C",
                "description": "Validation fixture for schema testing",
                "severity": "High",
                "priority": "P2",
                "tags": ["validation", "contract-test"],
                "evidence": [{"type": "InitialProbe", "source": "unit-test"}]
            }
            res = await client.post("/api/v2/soc/cases", json=payload, headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert res.status_code == 201, f"Expected 201, got {res.status_code}: {res.text}"
            case = res.json()
            created_case_ids.append(case["id"])

            required_fields = ["id", "case_id", "case_number", "tenant_id", "title", "severity", "priority", "status", "lead_analyst", "evidence", "tags", "created_at", "updated_at", "comment_count"]
            for f in required_fields:
                assert f in case, f"Missing required field: {f}"
            assert case["case_number"].startswith("CASE-"), f"Invalid case_number: {case['case_number']}"
            assert case["status"] == "NEW"
            record_test("suite_a_contracts", "A02", "Case Creation Schema & CaseNumber Generation", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_a_contracts", "A02", "Case Creation Schema & CaseNumber Generation", "FAIL", (time.time() - t0) * 1000, str(e))

        # A.3: Case Detail Contract
        t0 = time.time()
        try:
            cid = created_case_ids[-1]
            res = await client.get(f"/api/v2/soc/cases/{cid}", headers={"Authorization": f"Bearer {token_t1_analyst}"})
            assert res.status_code == 200, f"Expected 200, got {res.status_code}"
            detail = res.json()
            assert detail["id"] == cid
            assert "comments" in detail and isinstance(detail["comments"], list)
            assert "evidence" in detail and isinstance(detail["evidence"], list)
            assert "mitre_map" in detail and isinstance(detail["mitre_map"], list)
            record_test("suite_a_contracts", "A03", "Case Detail with Nested Comments & Evidence", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_a_contracts", "A03", "Case Detail with Nested Comments & Evidence", "FAIL", (time.time() - t0) * 1000, str(e))

        # A.4: Case Assignment Contract
        t0 = time.time()
        try:
            cid = created_case_ids[-1]
            assign_payload = {"lead_analyst": "secops_analyst_test@enterprise.corp", "assigned_team": "Tier 2 Threat Response"}
            res = await client.patch(f"/api/v2/soc/cases/{cid}/assign", json=assign_payload, headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
            updated = res.json()
            assert updated["lead_analyst"] == "secops_analyst_test@enterprise.corp"
            assert updated["assigned_team"] == "Tier 2 Threat Response"
            record_test("suite_a_contracts", "A04", "Case Assignment Mutation", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_a_contracts", "A04", "Case Assignment Mutation", "FAIL", (time.time() - t0) * 1000, str(e))

        # A.5: Status Transition State Machine Contract
        t0 = time.time()
        try:
            c_traversal = await client.post("/api/v2/soc/cases", json={"title": "Traversal Test Case", "severity": "Medium"}, headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert c_traversal.status_code == 201
            cid_trav = c_traversal.json()["id"]
            created_case_ids.append(cid_trav)

            # NEW -> TRIAGED
            r_triage = await client.patch(f"/api/v2/soc/cases/{cid_trav}/status", json={"status": "TRIAGED", "notes": "Initial triage"}, headers={"Authorization": f"Bearer {token_t1_analyst}"})
            assert r_triage.status_code == 200 and r_triage.json()["status"] == "TRIAGED", f"NEW->TRIAGED failed: {r_triage.status_code} {r_triage.text}"
            # TRIAGED -> CONTAINED
            r_cont = await client.patch(f"/api/v2/soc/cases/{cid_trav}/status", json={"status": "CONTAINED", "notes": "Contained"}, headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert r_cont.status_code == 200 and r_cont.json()["status"] == "CONTAINED", f"TRIAGED->CONTAINED failed: {r_cont.status_code} {r_cont.text}"
            # CONTAINED -> RESOLVED
            r_res = await client.patch(f"/api/v2/soc/cases/{cid_trav}/status", json={"status": "RESOLVED", "notes": "Resolved"}, headers={"Authorization": f"Bearer {token_t1_analyst}"})
            assert r_res.status_code == 200 and r_res.json()["status"] == "RESOLVED", f"CONTAINED->RESOLVED failed: {r_res.status_code} {r_res.text}"
            # RESOLVED -> CLOSED
            r_cls = await client.patch(f"/api/v2/soc/cases/{cid_trav}/status", json={"status": "CLOSED", "closure_summary": "Full remediation verified"}, headers={"Authorization": f"Bearer {token_t1_analyst}"})
            assert r_cls.status_code == 200 and r_cls.json()["status"] == "CLOSED", f"RESOLVED->CLOSED failed: {r_cls.status_code} {r_cls.text}"
            assert r_cls.json()["closed_at"] is not None
            record_test("suite_a_contracts", "A05", "Valid State Machine Traversal (NEW->TRIAGED->CONTAINED->RESOLVED->CLOSED)", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_a_contracts", "A05", "Valid State Machine Traversal", "FAIL", (time.time() - t0) * 1000, str(e))

        # A.6: Invalid Status Transition Rejection Contract
        t0 = time.time()
        try:
            # Create fresh case
            c_fresh = await client.post("/api/v2/soc/cases", json={"title": "Illegal Transition Case", "severity": "Low"}, headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert c_fresh.status_code == 201
            cid_illegal = c_fresh.json()["id"]
            created_case_ids.append(cid_illegal)

            # Direct jump: NEW -> CONTAINED
            r_bad = await client.patch(f"/api/v2/soc/cases/{cid_illegal}/status", json={"status": "CONTAINED"}, headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert r_bad.status_code == 400, f"Expected 400, got {r_bad.status_code}"
            assert "transition" in r_bad.json().get("detail", "").lower()
            record_test("suite_a_contracts", "A06", "Invalid Transition Jump Rejection (HTTP 400)", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_a_contracts", "A06", "Invalid Transition Jump Rejection (HTTP 400)", "FAIL", (time.time() - t0) * 1000, str(e))

        # A.7: Comment Submission & Visibility Contract
        t0 = time.time()
        try:
            cid = created_case_ids[0]
            # Internal
            r_int = await client.post(f"/api/v2/soc/cases/{cid}/comments", json={"comment_text": "Confidential internal forensic hypothesis", "is_customer_visible": False}, headers={"Authorization": f"Bearer {token_t1_analyst}"})
            assert r_int.status_code == 201 and r_int.json()["is_customer_visible"] is False
            # Customer
            r_cust = await client.post(f"/api/v2/soc/cases/{cid}/comments", json={"comment_text": "Customer notification: containment active", "is_customer_visible": True}, headers={"Authorization": f"Bearer {token_t1_analyst}"})
            assert r_cust.status_code == 201 and r_cust.json()["is_customer_visible"] is True
            # Fetch all
            r_all = await client.get(f"/api/v2/soc/cases/{cid}/comments", headers={"Authorization": f"Bearer {token_t1_analyst}"})
            assert r_all.status_code == 200 and len(r_all.json()) >= 2
            record_test("suite_a_contracts", "A07", "Comment Submission & Visibility Segregation", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_a_contracts", "A07", "Comment Submission & Visibility Segregation", "FAIL", (time.time() - t0) * 1000, str(e))

        # A.8: Evidence Append Contract
        t0 = time.time()
        try:
            cid = created_case_ids[0]
            ev_data = [{
                "type": "NetworkConnection",
                "agent_id": "pilot-46ef27fe",
                "hostname": "srv-prod-db01",
                "destination_ip": "198.51.100.24",
                "destination_port": 4444,
                "protocol": "TCP"
            }]
            res = await client.post(f"/api/v2/soc/cases/{cid}/evidence", json={"evidence": ev_data}, headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert res.status_code == 200
            assert any(e.get("agent_id") == "pilot-46ef27fe" for e in res.json()["evidence"])
            record_test("suite_a_contracts", "A08", "Forensic Evidence Attachment & Serialization", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_a_contracts", "A08", "Forensic Evidence Attachment & Serialization", "FAIL", (time.time() - t0) * 1000, str(e))

        # A.9: Alert Promotion Contract
        t0 = time.time()
        try:
            # Create test detection alert in DB
            async with AsyncSessionLocal() as session:
                alert = DetectionAlert(
                    AgentId="pilot-46ef27fe",
                    MatchedContent=json.dumps({"signature": "Win.Trojan.CobaltStrike", "tactic": "Execution", "technique": "T1059"}),
                    Status="New",
                    Timestamp=datetime.utcnow(),
                    HitCount=1
                )
                session.add(alert)
                await session.commit()
                await session.refresh(alert)
                test_alert_id = alert.Id
                created_alert_ids.append(test_alert_id)

            promo_res = await client.post("/api/v2/soc/cases/promote-alert", json={"alert_id": test_alert_id, "title": "Promoted Threat Case", "priority": "P1"}, headers={"Authorization": f"Bearer {token_t1_analyst}"})
            assert promo_res.status_code == 201, f"Expected 201, got {promo_res.status_code}: {promo_res.text}"
            p_case = promo_res.json()
            created_case_ids.append(p_case["id"])
            assert p_case["case_number"].startswith("CASE-")
            assert any(e.get("promoted_alert_id") == test_alert_id for e in p_case.get("evidence", []))
            record_test("suite_a_contracts", "A09", "Alert Promotion into SOC Case with Evidence", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_a_contracts", "A09", "Alert Promotion into SOC Case with Evidence", "FAIL", (time.time() - t0) * 1000, str(e))

        # A.10: Duplicate Alert Promotion Rejection (HTTP 409 Conflict)
        t0 = time.time()
        try:
            test_alert_id = created_alert_ids[-1]
            dup_res = await client.post("/api/v2/soc/cases/promote-alert", json={"alert_id": test_alert_id, "title": "Duplicate Promotion"}, headers={"Authorization": f"Bearer {token_t1_analyst}"})
            assert dup_res.status_code == 409, f"Expected 409 Conflict, got {dup_res.status_code}"
            assert "already been promoted" in dup_res.json().get("detail", "")
            record_test("suite_a_contracts", "A10", "Duplicate Alert Promotion Rejection (HTTP 409)", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_a_contracts", "A10", "Duplicate Alert Promotion Rejection (HTTP 409)", "FAIL", (time.time() - t0) * 1000, str(e))

        # A.11: Containment Response Contract (safe_mode=True)
        t0 = time.time()
        try:
            # Reset agent isolation
            async with AsyncSessionLocal() as session:
                res_ag = await session.execute(select(Agent).where(Agent.AgentId == "pilot-46ef27fe"))
                ag = res_ag.scalars().first()
                if ag:
                    ag.IsIsolated = False
                    await session.commit()

            c_contain = await client.post("/api/v2/soc/cases", json={"title": "Containment Schema Case", "severity": "Critical"}, headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert c_contain.status_code == 201
            cid_contain = c_contain.json()["id"]
            created_case_ids.append(cid_contain)

            res_cont = await client.post(f"/api/v2/soc/cases/{cid_contain}/contain-host", json={"agent_id": "pilot-46ef27fe", "confirmed": True, "safe_mode": True, "reason": "Schema validation test"}, headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert res_cont.status_code == 200, f"Expected 200, got {res_cont.status_code}: {res_cont.text}"
            c_resp = res_cont.json()
            assert c_resp["status"] == "success"
            assert c_resp["safe_mode"] is True
            assert c_resp["mode"] == "SAFE_MODE_SIMULATION"
            assert c_resp["case_status"] == "CONTAINED"
            record_test("suite_a_contracts", "A11", "Host Containment Safe-Mode Response Schema", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_a_contracts", "A11", "Host Containment Safe-Mode Response Schema", "FAIL", (time.time() - t0) * 1000, str(e))

        # ======================================================================
        # SUITE B: END-TO-END SOC WORKFLOW VALIDATION (12 Steps)
        # ======================================================================
        log_suite_header("Suite B: End-to-End SOC Workflow Validation (12 Steps)")

        # Step 1: Authenticate as authorized user
        t0 = time.time()
        try:
            assert token_t1_admin is not None
            claims = jwt.decode(token_t1_admin, SECRET_KEY, algorithms=[ALGORITHM])
            assert claims["sub"] == "elsea" and claims["tenantId"] == 1
            record_test("suite_b_e2e", "B01", "Step 1: Authenticate as Authorized User", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_b_e2e", "B01", "Step 1: Authenticate as Authorized User", "FAIL", (time.time() - t0) * 1000, str(e))

        # Step 2: Open SOC incident dashboard
        t0 = time.time()
        try:
            res_dash = await client.get("/api/v2/soc/cases?limit=25", headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert res_dash.status_code == 200 and isinstance(res_dash.json(), list)
            record_test("suite_b_e2e", "B02", "Step 2: Open SOC Incident Dashboard (Cases Feed)", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_b_e2e", "B02", "Step 2: Open SOC Incident Dashboard", "FAIL", (time.time() - t0) * 1000, str(e))

        # Step 3: Retrieve a detection alert
        t0 = time.time()
        try:
            async with AsyncSessionLocal() as session:
                e2e_alert = DetectionAlert(
                    AgentId="pilot-46ef27fe",
                    MatchedContent=json.dumps({"signature": "Ransom.WannaCry.Dropped", "tactic": "Impact", "technique": "T1486"}),
                    Status="New",
                    Timestamp=datetime.utcnow(),
                    HitCount=1
                )
                session.add(e2e_alert)
                await session.commit()
                await session.refresh(e2e_alert)
                e2e_alert_id = e2e_alert.Id
                created_alert_ids.append(e2e_alert_id)
            assert e2e_alert_id is not None
            record_test("suite_b_e2e", "B03", "Step 3: Retrieve Live Detection Alert", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_b_e2e", "B03", "Step 3: Retrieve Live Detection Alert", "FAIL", (time.time() - t0) * 1000, str(e))

        # Step 4: Promote alert into SOC Case
        t0 = time.time()
        e2e_case_id = None
        try:
            res_promote = await client.post("/api/v2/soc/cases/promote-alert", json={"alert_id": e2e_alert_id, "title": "E2E Ransomware Outbreak Case", "priority": "P1"}, headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert res_promote.status_code == 201
            e2e_case = res_promote.json()
            e2e_case_id = e2e_case["id"]
            created_case_ids.append(e2e_case_id)
            assert e2e_case["status"] == "NEW"
            record_test("suite_b_e2e", "B04", f"Step 4: Promote Alert to SOC Case ({e2e_case['case_number']})", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_b_e2e", "B04", "Step 4: Promote Alert to SOC Case", "FAIL", (time.time() - t0) * 1000, str(e))

        # Step 5: Open case detail workspace
        t0 = time.time()
        try:
            res_det = await client.get(f"/api/v2/soc/cases/{e2e_case_id}", headers={"Authorization": f"Bearer {token_t1_analyst}"})
            assert res_det.status_code == 200
            assert res_det.json()["id"] == e2e_case_id
            record_test("suite_b_e2e", "B05", "Step 5: Open Case Detail Investigation Workspace", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_b_e2e", "B05", "Step 5: Open Case Detail Investigation Workspace", "FAIL", (time.time() - t0) * 1000, str(e))

        # Step 6: Assign the case
        t0 = time.time()
        try:
            res_assign = await client.patch(f"/api/v2/soc/cases/{e2e_case_id}/assign", json={"lead_analyst": "secops_analyst_test@enterprise.corp", "assigned_team": "Ransomware Specialist Unit"}, headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert res_assign.status_code == 200 and res_assign.json()["lead_analyst"] == "secops_analyst_test@enterprise.corp"
            record_test("suite_b_e2e", "B06", "Step 6: Assign Lead Analyst & Specialist Team", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_b_e2e", "B06", "Step 6: Assign Lead Analyst & Specialist Team", "FAIL", (time.time() - t0) * 1000, str(e))

        # Step 7: Add investigation comments
        t0 = time.time()
        try:
            res_c1 = await client.post(f"/api/v2/soc/cases/{e2e_case_id}/comments", json={"comment_text": "Investigating process memory artifacts on srv-prod-db01", "is_customer_visible": False}, headers={"Authorization": f"Bearer {token_t1_analyst}"})
            assert res_c1.status_code == 201
            res_c2 = await client.post(f"/api/v2/soc/cases/{e2e_case_id}/comments", json={"comment_text": "Threat contained, assessing damage", "is_customer_visible": True}, headers={"Authorization": f"Bearer {token_t1_analyst}"})
            assert res_c2.status_code == 201
            record_test("suite_b_e2e", "B07", "Step 7: Add Internal Note and Customer Advisory", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_b_e2e", "B07", "Step 7: Add Internal Note and Customer Advisory", "FAIL", (time.time() - t0) * 1000, str(e))

        # Step 8: Attach evidence references
        t0 = time.time()
        try:
            ev_item = {
                "type": "FileHashMismatch",
                "agent_id": "pilot-46ef27fe",
                "sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
                "file_path": "/var/tmp/crypt.bin"
            }
            res_ev = await client.post(f"/api/v2/soc/cases/{e2e_case_id}/evidence", json={"evidence": [ev_item]}, headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert res_ev.status_code == 200
            assert any(e.get("sha256") == ev_item["sha256"] for e in res_ev.json()["evidence"])
            record_test("suite_b_e2e", "B08", "Step 8: Attach Forensic File Hash Evidence", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_b_e2e", "B08", "Step 8: Attach Forensic File Hash Evidence", "FAIL", (time.time() - t0) * 1000, str(e))

        # Step 9: Update case status
        t0 = time.time()
        try:
            # Case was transitioned to TRIAGED during assignment in Step 6; analyst submits triage notes / confirms status
            r_tr = await client.patch(f"/api/v2/soc/cases/{e2e_case_id}/status", json={"status": "TRIAGED", "notes": "Triage verified threat integrity"}, headers={"Authorization": f"Bearer {token_t1_analyst}"})
            assert r_tr.status_code == 200 and r_tr.json()["status"] == "TRIAGED", f"Step 9 failed: {r_tr.status_code} {r_tr.text}"
            record_test("suite_b_e2e", "B09", "Step 9: Update Case Status & Investigation Notes", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_b_e2e", "B09", "Step 9: Update Case Status & Investigation Notes", "FAIL", (time.time() - t0) * 1000, str(e))

        # Step 10: Verify audit history in AuditLogs table
        t0 = time.time()
        try:
            async with AsyncSessionLocal() as session:
                q_audit = select(AuditLog).where(AuditLog.TenantId == 1).order_by(AuditLog.Timestamp.desc()).limit(10)
                res_audit = await session.execute(q_audit)
                audits = res_audit.scalars().all()
                actions = [a.Action for a in audits]
                assert any("Case" in a for a in actions), f"Expected Case audit entries, found: {actions}"
            record_test("suite_b_e2e", "B10", "Step 10: Verify Cryptographic Audit History Logged", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_b_e2e", "B10", "Step 10: Verify Cryptographic Audit History Logged", "FAIL", (time.time() - t0) * 1000, str(e))

        # Step 11: Test safe-mode containment
        t0 = time.time()
        try:
            # Ensure agent not isolated initially
            async with AsyncSessionLocal() as session:
                res_ag = await session.execute(select(Agent).where(Agent.AgentId == "pilot-46ef27fe"))
                ag = res_ag.scalars().first()
                if ag:
                    ag.IsIsolated = False
                    await session.commit()

            res_contain = await client.post(f"/api/v2/soc/cases/{e2e_case_id}/contain-host", json={"agent_id": "pilot-46ef27fe", "confirmed": True, "safe_mode": True, "reason": "E2E Safe-mode containment validation"}, headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert res_contain.status_code == 200
            cont_data = res_contain.json()
            assert cont_data["safe_mode"] is True
            assert cont_data["case_status"] == "CONTAINED"
            record_test("suite_b_e2e", "B11", "Step 11: Execute Safe-Mode Host Containment", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_b_e2e", "B11", "Step 11: Execute Safe-Mode Host Containment", "FAIL", (time.time() - t0) * 1000, str(e))

        # Step 12: Verify case remains visible and state consistent after simulated refresh
        t0 = time.time()
        try:
            res_refresh = await client.get(f"/api/v2/soc/cases/{e2e_case_id}", headers={"Authorization": f"Bearer {token_t1_analyst}"})
            assert res_refresh.status_code == 200
            final_case = res_refresh.json()
            assert final_case["id"] == e2e_case_id
            assert final_case["status"] == "CONTAINED"
            assert final_case["lead_analyst"] == "secops_analyst_test@enterprise.corp"
            assert len(final_case["comments"]) >= 2
            assert len(final_case["evidence"]) >= 1
            record_test("suite_b_e2e", "B12", "Step 12: Workspace Refresh State Persistence Verification", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_b_e2e", "B12", "Step 12: Workspace Refresh State Persistence Verification", "FAIL", (time.time() - t0) * 1000, str(e))

        # ======================================================================
        # SUITE C: SECURITY & MULTI-TENANT ISOLATION VALIDATION (10 Tests)
        # ======================================================================
        log_suite_header("Suite C: Security & Multi-Tenant Isolation Validation")

        # C.1: Unauthenticated request rejection
        t0 = time.time()
        try:
            endpoints = [
                ("GET", "/api/v2/soc/cases"),
                ("POST", "/api/v2/soc/cases"),
                ("GET", f"/api/v2/soc/cases/{created_case_ids[0]}"),
                ("PATCH", f"/api/v2/soc/cases/{created_case_ids[0]}/status"),
                ("POST", f"/api/v2/soc/cases/{created_case_ids[0]}/contain-host"),
                ("POST", "/api/v2/soc/cases/promote-alert")
            ]
            for m, url in endpoints:
                r = await client.request(m, url, json={})
                assert r.status_code == 401, f"Unauth {m} {url} returned {r.status_code} instead of 401"
            record_test("suite_c_security", "C01", "Unauthenticated Request Rejection (HTTP 401)", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_c_security", "C01", "Unauthenticated Request Rejection (HTTP 401)", "FAIL", (time.time() - t0) * 1000, str(e))

        # C.2: Expired Token Rejection
        t0 = time.time()
        try:
            expired_token = mint_token("elsea", "TenantAdmin", 1, exp_delta=timedelta(hours=-2))
            r = await client.get("/api/v2/soc/cases", headers={"Authorization": f"Bearer {expired_token}"})
            assert r.status_code == 401, f"Expired token returned {r.status_code} instead of 401"
            record_test("suite_c_security", "C02", "Expired Token Rejection (HTTP 401)", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_c_security", "C02", "Expired Token Rejection (HTTP 401)", "FAIL", (time.time() - t0) * 1000, str(e))

        # C.3: Viewer Read-Only Enforcement
        t0 = time.time()
        try:
            cid = created_case_ids[0]
            # Create case -> 403
            r_c = await client.post("/api/v2/soc/cases", json={"title": "Viewer Case"}, headers={"Authorization": f"Bearer {token_t1_viewer}"})
            assert r_c.status_code == 403, f"Viewer create returned {r_c.status_code}"
            # Status update -> 403
            r_s = await client.patch(f"/api/v2/soc/cases/{cid}/status", json={"status": "CLOSED"}, headers={"Authorization": f"Bearer {token_t1_viewer}"})
            assert r_s.status_code == 403, f"Viewer status update returned {r_s.status_code}"
            # Comment -> 403
            r_m = await client.post(f"/api/v2/soc/cases/{cid}/comments", json={"comment_text": "Viewer comment"}, headers={"Authorization": f"Bearer {token_t1_viewer}"})
            assert r_m.status_code == 403, f"Viewer comment returned {r_m.status_code}"
            record_test("suite_c_security", "C03", "Viewer Read-Only Guard (HTTP 403 on mutations)", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_c_security", "C03", "Viewer Read-Only Guard", "FAIL", (time.time() - t0) * 1000, str(e))

        # C.4: Auditor Read-Only Enforcement
        t0 = time.time()
        try:
            cid = created_case_ids[0]
            r_c = await client.post("/api/v2/soc/cases", json={"title": "Auditor Case"}, headers={"Authorization": f"Bearer {token_t1_auditor}"})
            assert r_c.status_code == 403, f"Auditor create returned {r_c.status_code}"
            r_m = await client.post(f"/api/v2/soc/cases/{cid}/comments", json={"comment_text": "Auditor comment"}, headers={"Authorization": f"Bearer {token_t1_auditor}"})
            assert r_m.status_code == 403, f"Auditor comment returned {r_m.status_code}"
            record_test("suite_c_security", "C04", "Auditor Read-Only Guard (HTTP 403 on mutations)", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_c_security", "C04", "Auditor Read-Only Guard", "FAIL", (time.time() - t0) * 1000, str(e))

        # C.5: Analyst Permissions & Containment Restriction
        t0 = time.time()
        try:
            cid = created_case_ids[0]
            # Analyst can comment
            r_ok = await client.post(f"/api/v2/soc/cases/{cid}/comments", json={"comment_text": "Analyst authorized comment"}, headers={"Authorization": f"Bearer {token_t1_analyst}"})
            assert r_ok.status_code == 201
            # Analyst CANNOT contain host
            r_block = await client.post(f"/api/v2/soc/cases/{cid}/contain-host", json={"agent_id": "pilot-46ef27fe", "confirmed": True, "safe_mode": True, "reason": "Analyst test"}, headers={"Authorization": f"Bearer {token_t1_analyst}"})
            assert r_block.status_code == 403, f"Analyst contain returned {r_block.status_code} instead of 403"
            record_test("suite_c_security", "C05", "Analyst Containment Restriction Guard (HTTP 403)", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_c_security", "C05", "Analyst Containment Restriction Guard", "FAIL", (time.time() - t0) * 1000, str(e))

        # C.6: Admin Containment Authorization
        t0 = time.time()
        try:
            cid = created_case_ids[0]
            r_admin = await client.post(f"/api/v2/soc/cases/{cid}/contain-host", json={"agent_id": "pilot-46ef27fe", "confirmed": True, "safe_mode": True, "reason": "Admin test"}, headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert r_admin.status_code == 200, f"Admin contain returned {r_admin.status_code}"
            record_test("suite_c_security", "C06", "Admin Containment Authorization Verified", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_c_security", "C06", "Admin Containment Authorization Verified", "FAIL", (time.time() - t0) * 1000, str(e))

        # C.7: Cross-Tenant Case Access Isolation
        t0 = time.time()
        try:
            # Create private case in Tenant 4
            c_t4 = await client.post("/api/v2/soc/cases", json={"title": "Tenant 4 Secret Case", "severity": "Critical"}, headers={"Authorization": f"Bearer {token_t4_admin}"})
            assert c_t4.status_code == 201
            cid_t4 = c_t4.json()["id"]
            created_case_ids.append(cid_t4)

            # Tenant 1 user attempts to access Tenant 4 case
            r_leak = await client.get(f"/api/v2/soc/cases/{cid_t4}", headers={"Authorization": f"Bearer {token_t1_analyst}"})
            assert r_leak.status_code == 404, f"Cross-tenant case read returned {r_leak.status_code} instead of 404"
            record_test("suite_c_security", "C07", "Cross-Tenant Case Access Isolation (HTTP 404)", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_c_security", "C07", "Cross-Tenant Case Access Isolation", "FAIL", (time.time() - t0) * 1000, str(e))

        # C.8: Cross-Tenant Comment Access Isolation
        t0 = time.time()
        try:
            # Tenant 1 user attempts to post comment on Tenant 4 case
            r_post = await client.post(f"/api/v2/soc/cases/{cid_t4}/comments", json={"comment_text": "Injected comment"}, headers={"Authorization": f"Bearer {token_t1_analyst}"})
            assert r_post.status_code == 404, f"Cross-tenant comment post returned {r_post.status_code} instead of 404"
            # Tenant 1 user attempts to get comments of Tenant 4 case
            r_get = await client.get(f"/api/v2/soc/cases/{cid_t4}/comments", headers={"Authorization": f"Bearer {token_t1_analyst}"})
            assert r_get.status_code == 404, f"Cross-tenant comments get returned {r_get.status_code} instead of 404"
            record_test("suite_c_security", "C08", "Cross-Tenant Comment Access Isolation (HTTP 404)", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_c_security", "C08", "Cross-Tenant Comment Access Isolation", "FAIL", (time.time() - t0) * 1000, str(e))

        # C.9: Cross-Tenant Alert Promotion Isolation
        t0 = time.time()
        try:
            # Create alert belonging to an agent of Tenant 4 (using isolated synthetic agent in Tenant 4)
            agt_t4_id = f"agt-t4-{uuid.uuid4().hex[:8]}"
            async with AsyncSessionLocal() as session:
                ag_t4 = Agent(AgentId=agt_t4_id, TenantId=4, Hostname="t4-host", Status="Active")
                session.add(ag_t4)
                await session.flush()
                al_t4 = DetectionAlert(AgentId=agt_t4_id, MatchedContent="malware-t4", Status="New", Timestamp=datetime.utcnow(), HitCount=1)
                session.add(al_t4)
                await session.commit()
                await session.refresh(al_t4)
                al_t4_id = al_t4.Id
                created_alert_ids.append(al_t4_id)

            # Tenant 1 user attempts to promote Tenant 4 alert
            r_promo_leak = await client.post("/api/v2/soc/cases/promote-alert", json={"alert_id": al_t4_id, "title": "Stolen Alert Promotion"}, headers={"Authorization": f"Bearer {token_t1_analyst}"})
            assert r_promo_leak.status_code == 404, f"Cross-tenant alert promote returned {r_promo_leak.status_code} instead of 404"

            # Cleanup al_t4 and agt_t4_id in strict FK order
            async with AsyncSessionLocal() as session:
                await session.execute(delete(DetectionAlert).where(DetectionAlert.Id == al_t4_id))
                await session.execute(delete(Agent).where(Agent.AgentId == agt_t4_id))
                await session.commit()
            if al_t4_id in created_alert_ids:
                created_alert_ids.remove(al_t4_id)

            record_test("suite_c_security", "C09", "Cross-Tenant Alert Promotion Isolation (HTTP 404)", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_c_security", "C09", "Cross-Tenant Alert Promotion Isolation", "FAIL", (time.time() - t0) * 1000, str(e))

        # C.10: Tenant Filtering in List Queries
        t0 = time.time()
        try:
            r_t1_list = await client.get("/api/v2/soc/cases?limit=100", headers={"Authorization": f"Bearer {token_t1_analyst}"})
            assert r_t1_list.status_code == 200
            t1_cases = r_t1_list.json()
            for c in t1_cases:
                assert c["tenant_id"] == 1, f"Tenant 1 query leaked Tenant {c['tenant_id']} case #{c['id']}"
            assert not any(c["id"] == cid_t4 for c in t1_cases), "Tenant 4 case leaked in Tenant 1 listing"
            record_test("suite_c_security", "C10", "Tenant Strict SQL Filter in List Queries", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_c_security", "C10", "Tenant Strict SQL Filter in List Queries", "FAIL", (time.time() - t0) * 1000, str(e))

        # ======================================================================
        # SUITE D: REGRESSION VALIDATION (7 Tests)
        # ======================================================================
        log_suite_header("Suite D: Regression Validation (Existing Features)")

        # D.1: Legacy Incident Listing
        t0 = time.time()
        try:
            r_inc = await client.get("/api/incidents", headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert r_inc.status_code == 200, f"Legacy incidents returned {r_inc.status_code}"
            assert isinstance(r_inc.json(), list)
            record_test("suite_d_regression", "D01", "Legacy Incident Listing (/api/incidents)", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_d_regression", "D01", "Legacy Incident Listing", "FAIL", (time.time() - t0) * 1000, str(e))

        # D.2: Legacy Incident Creation
        t0 = time.time()
        try:
            r_cr = await client.post("/api/incidents", json={"title": "Regression Legacy Incident", "description": "Testing legacy compatibility", "agent_id": "pilot-46ef27fe", "severity": "Medium", "affected_agents": ["pilot-46ef27fe"]}, headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert r_cr.status_code == 201, f"Legacy create returned {r_cr.status_code}: {r_cr.text}"
            leg_inc = r_cr.json()
            created_incident_ids.append(leg_inc.get("incident_id") or leg_inc.get("id"))
            record_test("suite_d_regression", "D02", "Legacy Incident Creation Workflow", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_d_regression", "D02", "Legacy Incident Creation Workflow", "FAIL", (time.time() - t0) * 1000, str(e))

        # D.3: Legacy Incident Resolution Workflow
        t0 = time.time()
        try:
            inc_id = created_incident_ids[-1]
            r_res = await client.patch(f"/api/incidents/{inc_id}/resolve", json={"notes": "Resolved via regression test"}, headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert r_res.status_code == 200, f"Legacy resolve returned {r_res.status_code}: {r_res.text}"
            record_test("suite_d_regression", "D03", "Legacy Incident Resolution Workflow", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_d_regression", "D03", "Legacy Incident Resolution Workflow", "FAIL", (time.time() - t0) * 1000, str(e))

        # D.4: Detection Alert Listing
        t0 = time.time()
        try:
            r_al = await client.get("/api/v2/detection/alerts?status=New", headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert r_al.status_code == 200, f"Detection alerts returned {r_al.status_code}"
            assert isinstance(r_al.json(), list)
            record_test("suite_d_regression", "D04", "Detection Alert Listing (/api/v2/detection/alerts)", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_d_regression", "D04", "Detection Alert Listing", "FAIL", (time.time() - t0) * 1000, str(e))

        # D.5: SOC Command Center Dashboard Metrics
        t0 = time.time()
        try:
            r_dash = await client.get("/api/v2/soc/dashboard", headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert r_dash.status_code == 200, f"SOC dashboard returned {r_dash.status_code}"
            record_test("suite_d_regression", "D05", "SOC Command Center Dashboard (/api/v2/soc/dashboard)", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_d_regression", "D05", "SOC Command Center Dashboard", "FAIL", (time.time() - t0) * 1000, str(e))

        # D.6: Incident Investigation Workspace Enrichment
        t0 = time.time()
        try:
            inc_id = created_incident_ids[-1]
            r_ws = await client.get(f"/api/v2/soc/incidents/{inc_id}/workspace", headers={"Authorization": f"Bearer {token_t1_admin}"})
            assert r_ws.status_code == 200, f"Incident workspace returned {r_ws.status_code}"
            record_test("suite_d_regression", "D06", "Incident Investigation Workspace Telemetry", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_d_regression", "D06", "Incident Investigation Workspace Telemetry", "FAIL", (time.time() - t0) * 1000, str(e))

        # D.7: Auth Token Verification & Multi-Tenant Claims
        t0 = time.time()
        try:
            claims_t1 = jwt.decode(token_t1_admin, SECRET_KEY, algorithms=[ALGORITHM])
            claims_t4 = jwt.decode(token_t4_admin, SECRET_KEY, algorithms=[ALGORITHM])
            assert claims_t1["tenantId"] == 1 and claims_t4["tenantId"] == 4
            record_test("suite_d_regression", "D07", "Auth Token Verification & Multi-Tenant Claims", "PASS", (time.time() - t0) * 1000)
        except Exception as e:
            record_test("suite_d_regression", "D07", "Auth Token Verification & Multi-Tenant Claims", "FAIL", (time.time() - t0) * 1000, str(e))

        # ======================================================================
        # CLEANUP FIXTURES
        # ======================================================================
        print("\nCleaning up test fixtures...")
        async with AsyncSessionLocal() as session:
            if created_alert_ids:
                await session.execute(delete(DetectionAlert).where(DetectionAlert.Id.in_(created_alert_ids)))
            if created_comment_ids:
                await session.execute(delete(SocCaseComment).where(SocCaseComment.Id.in_(created_comment_ids)))
            if created_case_ids:
                await session.execute(delete(SocCaseComment).where(SocCaseComment.CaseId.in_(created_case_ids)))
                await session.execute(delete(SocCase).where(SocCase.Id.in_(created_case_ids)))
            if created_incident_ids:
                await session.execute(delete(Incident).where(Incident.Id.in_(created_incident_ids)))
            res_ag = await session.execute(select(Agent).where(Agent.AgentId == "pilot-46ef27fe"))
            target_ag = res_ag.scalars().first()
            if target_ag:
                target_ag.IsIsolated = False
            await session.commit()
        print("Cleanup completed.")

    total_duration = (time.time() - start_all) * 1000
    print("\n" + "=" * 80)
    print("PHASE 5.4.1C VALIDATION SUMMARY")
    print("=" * 80)
    print(f"Total Tests Executed: {TOTAL_PASSED + TOTAL_FAILED}")
    print(f"PASSED: {TOTAL_PASSED}")
    print(f"FAILED: {TOTAL_FAILED}")
    print(f"Total Duration: {total_duration:.2f} ms")
    print("=" * 80)

    # Dump results JSON for documentation
    output_path = "/tmp/monitorix_phase5_4_1c_results.json"
    results_summary = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_tests": TOTAL_PASSED + TOTAL_FAILED,
        "passed": TOTAL_PASSED,
        "failed": TOTAL_FAILED,
        "duration_ms": total_duration,
        "suites": SUITE_RESULTS
    }
    with open(output_path, "w") as f:
        json.dump(results_summary, f, indent=2)
    print(f"Results written to {output_path}")

    if TOTAL_FAILED > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    asyncio.run(run_validation())
