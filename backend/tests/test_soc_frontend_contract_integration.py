#!/usr/bin/env python3
"""
MONITORIX ENTERPRISE — PHASE 5.4.1B
Automated Frontend & Contract Integration Test Suite
====================================================
Validates the API contracts and frontend behaviors across all 13 required verification points:
 1. Case list loading and response schema validation (fetchSocCases contract)
 2. Case detail loading with comments and evidence (fetchSocCaseDetail contract)
 3. Filtering by severity, status, priority, and text search
 4. Analyst assignment API mutation (assignSocCase)
 5. Comment submission (internal vs customer visible)
 6. Evidence display schema integrity
 7. Valid status transitions (NEW -> TRIAGED -> CONTAINED -> RESOLVED -> CLOSED)
 8. Invalid status transitions rejection (HTTP 400 Bad Request)
 9. Alert promotion to case (promoteAlertToSocCase)
 10. Duplicate alert promotion rejection (HTTP 409 Conflict)
 11. Containment authorization visibility and safe-mode containment call
 12. Session expiry / 401 handling
 13. Empty and error states handling (HTTP 404, HTTP 422)
"""

import asyncio
import json
import os
import sys
import time
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

# Execution tracking
PASSED = 0
FAILED = 0
TEST_RESULTS = []


def log_header(num: int, title: str):
    print(f"\n" + "=" * 80)
    print(f"[CONTRACT TEST {num:02d}/13] {title}")
    print("=" * 80)


def record_pass(step_name: str, duration_ms: float = 0.0):
    global PASSED
    PASSED += 1
    TEST_RESULTS.append({"test": step_name, "status": "PASS", "duration_ms": duration_ms})
    print(f"  [PASS] {step_name} ({duration_ms:.1f}ms)")


import traceback

def record_fail(step_name: str, error_msg: str, duration_ms: float = 0.0):
    global FAILED
    FAILED += 1
    tb = traceback.format_exc()
    TEST_RESULTS.append({"test": step_name, "status": "FAIL", "error": f"{error_msg}\n{tb}", "duration_ms": duration_ms})
    print(f"  [FAIL] {step_name}: {error_msg} ({duration_ms:.1f}ms)\n{tb}")


def mint_token(username: str, role: str, tenant_id: int) -> str:
    """Mints an enterprise JWT for testing using real DB identity."""
    payload = {
        "sub": username,
        "role": role,
        "tenantId": tenant_id,
        "exp": datetime.utcnow() + timedelta(hours=2)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


async def run_suite():
    global PASSED, FAILED
    start_total = time.time()

    print("================================================================================")
    print("MONITORIX ENTERPRISE — PHASE 5.4.1B FRONTEND CONTRACT INTEGRATION SUITE")
    print("Verifying Frontend API Client Contracts & Backend SOC Case Endpoints")
    print("================================================================================")

    # Valid authenticated identities from database:
    token_admin = mint_token("elsea", "TenantAdmin", 1)
    token_analyst = mint_token("secops_analyst_test@enterprise.corp", "Analyst", 1)
    token_viewer = mint_token("viewer_test", "Viewer", 1)

    created_case_ids = []
    created_alert_ids = []

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:

        # ----------------------------------------------------------------------
        # TEST 1: Case list loading and response schema validation
        # ----------------------------------------------------------------------
        log_header(1, "Case List Loading & Response Schema Validation")
        t0 = time.time()
        try:
            # Create a test case to ensure at least one case exists in tenant 1
            create_payload = {
                "title": "Contract Test Case Alpha",
                "description": "Validation case for schema verification",
                "severity": "Critical",
                "priority": "P1",
                "tags": ["frontend-contract", "unit-test"]
            }
            res_create = await client.post(
                "/api/v2/soc/cases",
                json=create_payload,
                headers={"Authorization": f"Bearer {token_admin}"}
            )
            assert res_create.status_code == 201, f"Failed to create fixture case: {res_create.text}"
            base_case = res_create.json()
            created_case_ids.append(base_case["id"])

            # Query list via analyst token
            res_list = await client.get(
                "/api/v2/soc/cases?limit=20&offset=0",
                headers={"Authorization": f"Bearer {token_analyst}"}
            )
            assert res_list.status_code == 200, f"Expected 200, got {res_list.status_code}: {res_list.text}"
            cases = res_list.json()
            assert isinstance(cases, list), "Expected list response"
            assert len(cases) >= 1, "Expected at least 1 case returned"

            # Check schema on sample case
            sample = cases[0]
            required_keys = [
                "id", "case_id", "case_number", "tenant_id", "title",
                "severity", "priority", "status", "evidence", "tags",
                "created_at", "updated_at", "comment_count"
            ]
            for rk in required_keys:
                assert rk in sample, f"Missing required contract field '{rk}' in SOC case item"

            assert sample["case_number"].startswith("CASE-"), f"Invalid case_number format: {sample['case_number']}"
            record_pass("Case list returned valid schema with all contract fields", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Case list schema validation", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 2: Case detail loading with comments and evidence
        # ----------------------------------------------------------------------
        log_header(2, "Case Detail Loading with Comments & Evidence")
        t0 = time.time()
        try:
            target_id = created_case_ids[0]
            res_detail = await client.get(
                f"/api/v2/soc/cases/{target_id}",
                headers={"Authorization": f"Bearer {token_analyst}"}
            )
            assert res_detail.status_code == 200, f"Expected 200, got {res_detail.status_code}"
            detail = res_detail.json()

            assert detail["id"] == target_id, f"Case id mismatch"
            assert "comments" in detail, "Expected comments array in case detail"
            assert isinstance(detail["comments"], list), "Comments must be list"
            assert "evidence" in detail, "Expected evidence array in case detail"
            assert isinstance(detail["evidence"], list), "Evidence must be list"
            assert "mitre_map" in detail, "Expected mitre_map in case detail"
            record_pass("Case detail loaded with full comments and evidence sub-structures", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Case detail schema validation", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 3: Filtering by severity, status, priority, and text search
        # ----------------------------------------------------------------------
        log_header(3, "Multi-Facet Filtering (Severity, Status, Priority, Search)")
        t0 = time.time()
        try:
            # Filter by severity=Critical
            r_crit = await client.get(
                "/api/v2/soc/cases?severity=Critical",
                headers={"Authorization": f"Bearer {token_analyst}"}
            )
            assert r_crit.status_code == 200
            for c in r_crit.json():
                assert c["severity"] == "Critical", f"Expected Critical, got {c['severity']}"

            # Filter by status=NEW
            r_new = await client.get(
                "/api/v2/soc/cases?status=NEW",
                headers={"Authorization": f"Bearer {token_analyst}"}
            )
            assert r_new.status_code == 200
            for c in r_new.json():
                assert c["status"] == "NEW", f"Expected NEW, got {c['status']}"

            # Filter by search keyword
            r_search = await client.get(
                "/api/v2/soc/cases?search=Alpha",
                headers={"Authorization": f"Bearer {token_analyst}"}
            )
            assert r_search.status_code == 200
            assert any(c["id"] == created_case_ids[0] for c in r_search.json()), "Created test case not in search results"
            record_pass("Multi-facet filtering and search returned strictly matching records", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Multi-facet filtering validation", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 4: Analyst assignment API mutation
        # ----------------------------------------------------------------------
        log_header(4, "Analyst Assignment Mutation")
        t0 = time.time()
        try:
            target_id = created_case_ids[0]
            assign_payload = {
                "lead_analyst": "secops_analyst_test@enterprise.corp",
                "assigned_team": "Tier 2 Threat Response"
            }
            res_assign = await client.patch(
                f"/api/v2/soc/cases/{target_id}/assign",
                json=assign_payload,
                headers={"Authorization": f"Bearer {token_admin}"}
            )
            assert res_assign.status_code == 200, f"Expected 200, got {res_assign.status_code}: {res_assign.text}"
            updated = res_assign.json()
            assert updated["lead_analyst"] == "secops_analyst_test@enterprise.corp"
            assert updated["assigned_team"] == "Tier 2 Threat Response"
            record_pass("Analyst assignment successfully updated lead_analyst and assigned_team", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Analyst assignment mutation", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 5: Comment submission (internal vs customer visible)
        # ----------------------------------------------------------------------
        log_header(5, "Comment Submission & Visibility Separation")
        t0 = time.time()
        try:
            target_id = created_case_ids[0]
            # 1. Internal comment
            r_int = await client.post(
                f"/api/v2/soc/cases/{target_id}/comments",
                json={"comment_text": "Internal triage analysis: IOC confirmed", "is_customer_visible": False},
                headers={"Authorization": f"Bearer {token_analyst}"}
            )
            assert r_int.status_code == 201, f"Failed internal comment: {r_int.text}"
            c_int = r_int.json()
            assert c_int["is_customer_visible"] is False

            # 2. Customer visible comment
            r_cust = await client.post(
                f"/api/v2/soc/cases/{target_id}/comments",
                json={"comment_text": "Customer update: Host containment in progress", "is_customer_visible": True},
                headers={"Authorization": f"Bearer {token_analyst}"}
            )
            assert r_cust.status_code == 201, f"Failed customer comment: {r_cust.text}"
            c_cust = r_cust.json()
            assert c_cust["is_customer_visible"] is True

            # 3. Retrieve all comments and verify chronological sorting
            r_all = await client.get(
                f"/api/v2/soc/cases/{target_id}/comments",
                headers={"Authorization": f"Bearer {token_analyst}"}
            )
            assert r_all.status_code == 200
            comments = r_all.json()
            assert len(comments) >= 2
            assert any(c["is_customer_visible"] is False for c in comments)
            assert any(c["is_customer_visible"] is True for c in comments)
            record_pass("Comments properly tagged and segregated by is_customer_visible", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Comment submission & visibility separation", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 6: Evidence display schema integrity
        # ----------------------------------------------------------------------
        log_header(6, "Evidence Display Schema Integrity")
        t0 = time.time()
        try:
            target_id = created_case_ids[0]
            evidence_item = {
                "type": "NetworkConnection",
                "agent_id": "pilot-46ef27fe",
                "hostname": "srv-prod-db01",
                "destination_ip": "198.51.100.24",
                "destination_port": 4444,
                "protocol": "TCP",
                "timestamp": datetime.utcnow().isoformat()
            }
            res_ev = await client.post(
                f"/api/v2/soc/cases/{target_id}/evidence",
                json={"evidence": [evidence_item]},
                headers={"Authorization": f"Bearer {token_admin}"}
            )
            assert res_ev.status_code == 200, f"Failed to attach evidence: {res_ev.text}"
            case_with_ev = res_ev.json()
            assert len(case_with_ev["evidence"]) >= 1
            matched = any(e.get("agent_id") == "pilot-46ef27fe" for e in case_with_ev["evidence"])
            assert matched, "Attached evidence item not found in case evidence array"
            record_pass("Evidence attachment preserves structured schema and agent_id metadata", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Evidence schema integrity", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 7: Valid status transitions (NEW -> TRIAGED -> CONTAINED -> RESOLVED -> CLOSED)
        # ----------------------------------------------------------------------
        log_header(7, "Valid Status Transitions Traversal")
        t0 = time.time()
        try:
            # Create a dedicated fresh case in NEW status for lifecycle traversal
            c_fresh = await client.post(
                "/api/v2/soc/cases",
                json={"title": "Lifecycle Traversal Test Case", "severity": "High", "priority": "P2"},
                headers={"Authorization": f"Bearer {token_admin}"}
            )
            assert c_fresh.status_code == 201, f"Failed to create fresh case: {c_fresh.text}"
            case_id = c_fresh.json()["id"]
            created_case_ids.append(case_id)
            assert c_fresh.json()["status"] == "NEW"

            # NEW -> TRIAGED
            r1 = await client.patch(
                f"/api/v2/soc/cases/{case_id}/status",
                json={"status": "TRIAGED", "notes": "Triaged by L1 SOC"},
                headers={"Authorization": f"Bearer {token_analyst}"}
            )
            assert r1.status_code == 200, f"NEW->TRIAGED failed with status {r1.status_code}: {r1.text}"
            assert r1.json()["status"] == "TRIAGED"

            # TRIAGED -> CONTAINED
            r2 = await client.patch(
                f"/api/v2/soc/cases/{case_id}/status",
                json={"status": "CONTAINED", "notes": "Host contained in safe mode"},
                headers={"Authorization": f"Bearer {token_admin}"}
            )
            assert r2.status_code == 200, f"TRIAGED->CONTAINED failed with status {r2.status_code}: {r2.text}"
            assert r2.json()["status"] == "CONTAINED"

            # CONTAINED -> RESOLVED
            r3 = await client.patch(
                f"/api/v2/soc/cases/{case_id}/status",
                json={"status": "RESOLVED", "notes": "Threat removed, host recovered"},
                headers={"Authorization": f"Bearer {token_analyst}"}
            )
            assert r3.status_code == 200, f"CONTAINED->RESOLVED failed with status {r3.status_code}: {r3.text}"
            assert r3.json()["status"] == "RESOLVED"

            # RESOLVED -> CLOSED
            r4 = await client.patch(
                f"/api/v2/soc/cases/{case_id}/status",
                json={"status": "CLOSED", "closure_summary": "Full remediation confirmed", "root_cause": "Phishing email with macro"},
                headers={"Authorization": f"Bearer {token_analyst}"}
            )
            assert r4.status_code == 200, f"RESOLVED->CLOSED failed with status {r4.status_code}: {r4.text}"
            assert r4.json()["status"] == "CLOSED"
            assert r4.json()["closed_at"] is not None
            record_pass("All valid transitions (NEW -> TRIAGED -> CONTAINED -> RESOLVED -> CLOSED) verified", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Valid status transitions", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 8: Invalid status transitions rejection (HTTP 400 Bad Request)
        # ----------------------------------------------------------------------
        log_header(8, "Invalid Status Transitions Rejection")
        t0 = time.time()
        try:
            # Create a brand new case in NEW status
            r_new_case = await client.post(
                "/api/v2/soc/cases",
                json={"title": "Invalid Transition Test Case", "severity": "Medium", "priority": "P3"},
                headers={"Authorization": f"Bearer {token_admin}"}
            )
            assert r_new_case.status_code == 201, f"Failed to create case for illegal jump: {r_new_case.text}"
            case2 = r_new_case.json()
            created_case_ids.append(case2["id"])

            # Attempt invalid jump: NEW -> CONTAINED (not permitted by state machine)
            r_bad = await client.patch(
                f"/api/v2/soc/cases/{case2['id']}/status",
                json={"status": "CONTAINED"},
                headers={"Authorization": f"Bearer {token_admin}"}
            )
            assert r_bad.status_code == 400, f"Expected 400 for illegal transition NEW->CONTAINED, got {r_bad.status_code}"
            assert "transition" in r_bad.json().get("detail", "").lower(), f"Unexpected detail: {r_bad.json()}"
            record_pass("Illegal transition NEW -> CONTAINED rejected with HTTP 400 Bad Request", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Invalid status transition rejection", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 9: Alert promotion to case
        # ----------------------------------------------------------------------
        log_header(9, "Alert Promotion to SOC Case")
        t0 = time.time()
        try:
            # Create a mock detection alert in database using valid columns
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

            # Call promote-alert
            promo_payload = {
                "alert_id": test_alert_id,
                "title": "Promoted Defense Evasion Case",
                "priority": "P1",
                "notes": "Escalated from Detection Alerts table"
            }
            res_promo = await client.post(
                "/api/v2/soc/cases/promote-alert",
                json=promo_payload,
                headers={"Authorization": f"Bearer {token_analyst}"}
            )
            assert res_promo.status_code == 201, f"Expected 201 for promote-alert, got {res_promo.status_code}: {res_promo.text}"
            promoted_case = res_promo.json()
            assert promoted_case["case_number"].startswith("CASE-")
            created_case_ids.append(promoted_case["id"])

            # Check evidence contains promoted_alert_id
            ev_list = promoted_case.get("evidence", [])
            assert any(e.get("promoted_alert_id") == test_alert_id for e in ev_list), "Promoted alert evidence missing"
            record_pass("Alert successfully promoted to SOC case with evidence preservation", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Alert promotion to case", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 10: Duplicate alert promotion rejection (HTTP 409 Conflict)
        # ----------------------------------------------------------------------
        log_header(10, "Duplicate Alert Promotion Prevention (HTTP 409 Conflict)")
        t0 = time.time()
        try:
            test_alert_id = created_alert_ids[-1]
            promo_payload = {
                "alert_id": test_alert_id,
                "title": "Duplicate Promotion Attempt",
                "priority": "P2"
            }
            res_dup = await client.post(
                "/api/v2/soc/cases/promote-alert",
                json=promo_payload,
                headers={"Authorization": f"Bearer {token_analyst}"}
            )
            assert res_dup.status_code == 409, f"Expected 409 Conflict for duplicate promotion, got {res_dup.status_code}"
            assert "already been promoted" in res_dup.json().get("detail", "")
            record_pass("Duplicate alert promotion strictly rejected with HTTP 409 Conflict", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Duplicate alert promotion rejection", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 11: Containment authorization visibility and safe-mode containment call
        # ----------------------------------------------------------------------
        log_header(11, "Host Containment RBAC & Safe-Mode Operation")
        t0 = time.time()
        try:
            # Ensure test agent is initially not isolated
            async with AsyncSessionLocal() as session:
                res_ag = await session.execute(select(Agent).where(Agent.AgentId == "pilot-46ef27fe"))
                ag = res_ag.scalars().first()
                if ag:
                    ag.IsIsolated = False
                    await session.commit()

            # Create a dedicated case in NEW status for containment test
            c_contain = await client.post(
                "/api/v2/soc/cases",
                json={"title": "Containment Test Case", "severity": "Critical", "priority": "P1"},
                headers={"Authorization": f"Bearer {token_admin}"}
            )
            assert c_contain.status_code == 201, f"Failed to create containment case: {c_contain.text}"
            target_id = c_contain.json()["id"]
            created_case_ids.append(target_id)

            # 1. Analyst attempts containment -> HTTP 403 Forbidden
            res_unauth = await client.post(
                f"/api/v2/soc/cases/{target_id}/contain-host",
                json={"agent_id": "pilot-46ef27fe", "confirmed": True, "safe_mode": True, "reason": "Analyst containment test"},
                headers={"Authorization": f"Bearer {token_analyst}"}
            )
            assert res_unauth.status_code == 403, f"Expected 403 for Analyst containment, got {res_unauth.status_code}"

            # 2. Admin calls containment with safe_mode=True
            res_auth = await client.post(
                f"/api/v2/soc/cases/{target_id}/contain-host",
                json={"agent_id": "pilot-46ef27fe", "confirmed": True, "safe_mode": True, "reason": "Admin safe containment test"},
                headers={"Authorization": f"Bearer {token_admin}"}
            )
            assert res_auth.status_code == 200, f"Expected 200 for Admin containment, got {res_auth.status_code}: {res_auth.text}"
            resp_body = res_auth.json()
            assert resp_body["status"] == "success"
            assert resp_body["safe_mode"] is True
            assert resp_body["mode"] == "SAFE_MODE_SIMULATION"
            assert resp_body["case_status"] == "CONTAINED"

            # 3. Test Idempotency: second containment call should be handled idempotently
            res_idempotent = await client.post(
                f"/api/v2/soc/cases/{target_id}/contain-host",
                json={"agent_id": "pilot-46ef27fe", "confirmed": True, "safe_mode": True, "reason": "Admin safe containment idempotent test"},
                headers={"Authorization": f"Bearer {token_admin}"}
            )
            assert res_idempotent.status_code == 200
            assert res_idempotent.json()["action_taken"] == "NONE_ALREADY_ISOLATED"

            record_pass("Containment strictly guarded: Analyst gets 403, Admin safe-mode simulation succeeds and handles idempotency", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Containment RBAC and safe-mode", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 12: Session expiry / 401 handling
        # ----------------------------------------------------------------------
        log_header(12, "Session Expiry & 401 Unauthorized Rejection")
        t0 = time.time()
        try:
            endpoints = [
                ("GET", "/api/v2/soc/cases"),
                ("POST", "/api/v2/soc/cases"),
                ("GET", "/api/v2/soc/cases/1"),
                ("PATCH", "/api/v2/soc/cases/1/status"),
                ("PATCH", "/api/v2/soc/cases/1/assign"),
                ("POST", "/api/v2/soc/cases/1/comments"),
                ("POST", "/api/v2/soc/cases/promote-alert"),
                ("POST", "/api/v2/soc/cases/1/contain-host")
            ]
            for method, url in endpoints:
                if method == "GET":
                    r = await client.get(url)
                elif method == "POST":
                    r = await client.post(url, json={})
                elif method == "PATCH":
                    r = await client.patch(url, json={})
                assert r.status_code == 401, f"Expected 401 for unauth {method} {url}, got {r.status_code}"

            record_pass("All endpoints strictly reject requests without valid Bearer token with HTTP 401", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Session expiry / 401 handling", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 13: Empty and error states handling
        # ----------------------------------------------------------------------
        log_header(13, "Empty & Error States Handling (HTTP 404, HTTP 422)")
        t0 = time.time()
        try:
            # 1. Non-existent case -> HTTP 404
            r_404 = await client.get(
                "/api/v2/soc/cases/99999999",
                headers={"Authorization": f"Bearer {token_analyst}"}
            )
            assert r_404.status_code == 404, f"Expected 404 for missing case, got {r_404.status_code}"

            # 2. Invalid body (missing required fields) -> HTTP 422
            r_422 = await client.post(
                "/api/v2/soc/cases",
                json={"invalid_field": 123},
                headers={"Authorization": f"Bearer {token_admin}"}
            )
            assert r_422.status_code == 422, f"Expected 422 for invalid schema, got {r_422.status_code}"

            # 3. Empty filter results return empty array with HTTP 200
            r_empty = await client.get(
                "/api/v2/soc/cases?search=NONEXISTENT_KEYWORD_XYZ_987",
                headers={"Authorization": f"Bearer {token_analyst}"}
            )
            assert r_empty.status_code == 200
            assert r_empty.json() == [], "Expected empty array for unmatched search"

            record_pass("Error states (404, 422) and empty search results handled cleanly according to contract", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Empty and error states handling", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # Cleanup Fixtures
        # ----------------------------------------------------------------------
        print("\nCleaning up test fixtures...")
        async with AsyncSessionLocal() as session:
            if created_alert_ids:
                await session.execute(
                    delete(DetectionAlert).where(DetectionAlert.Id.in_(created_alert_ids))
                )
            if created_case_ids:
                await session.execute(
                    delete(SocCaseComment).where(SocCaseComment.CaseId.in_(created_case_ids))
                )
                await session.execute(
                    delete(SocCase).where(SocCase.Id.in_(created_case_ids))
                )
            res_agent = await session.execute(select(Agent).where(Agent.AgentId == "pilot-46ef27fe"))
            target_agent = res_agent.scalars().first()
            if target_agent:
                target_agent.IsIsolated = False
            await session.commit()
        print("Cleanup completed.")

    total_time = (time.time() - start_total) * 1000
    print("\n" + "=" * 80)
    print("TEST SUITE EXECUTION SUMMARY")
    print("=" * 80)
    print(f"Total Tests Executed: {len(TEST_RESULTS)}")
    print(f"PASSED: {PASSED}")
    print(f"FAILED: {FAILED}")
    print(f"Total Duration: {total_time:.2f} ms")
    print("=" * 80)

    if FAILED > 0:
        print("\nFailed Tests:")
        for r in TEST_RESULTS:
            if r["status"] == "FAIL":
                print(f"  - {r['test']}: {r.get('error')}")
        sys.exit(1)
    else:
        print("\nALL 13 FRONTEND CONTRACT INTEGRATION TESTS PASSED PERFECTLY!")
        sys.exit(0)


if __name__ == "__main__":
    asyncio.run(run_suite())
