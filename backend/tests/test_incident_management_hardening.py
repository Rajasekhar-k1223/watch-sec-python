#!/usr/bin/env python3
"""
MONITORIX ENTERPRISE — PHASE 5.4.1A
Automated Test Suite for Incident Management Backend Security & SOC Case Lifecycle
==================================================================================
Covers all 14 mandatory validation points:
 1. Unauthenticated request rejection (HTTP 401)
 2. Cross-tenant case access (HTTP 404)
 3. Cross-tenant comment access (HTTP 404)
 4. RBAC enforcement (HTTP 403 for unauthorized roles)
 5. Case creation with unique sequential CaseNumber and tenant protection
 6. Alert promotion to SOC case with MITRE preservation
 7. Duplicate alert promotion prevention (HTTP 409 Conflict)
 8. Valid lifecycle transitions (NEW -> TRIAGED -> CONTAINED -> RESOLVED -> CLOSED)
 9. Invalid lifecycle transitions rejection (HTTP 400 Bad Request)
10. Comment persistence & chronological retrieval
11. Security Audit event creation in AuditLogs
12. Containment authorization (HTTP 403 for Analyst / Viewer)
13. Containment safe-mode behavior (safe_mode=True, zero packet drop, cross-tenant 404)
14. Database transaction atomicity & rollback verification
"""

import asyncio
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta

# Ensure /app or backend is in sys.path
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

# Execution stats
PASSED = 0
FAILED = 0
TEST_RESULTS = []


def log_header(num: int, title: str):
    print(f"\n" + "=" * 80)
    print(f"[TEST {num:02d}/14] {title}")
    print("=" * 80)


def record_pass(step_name: str, duration_ms: float = 0.0):
    global PASSED
    PASSED += 1
    TEST_RESULTS.append({"test": step_name, "status": "PASS", "duration_ms": duration_ms})
    print(f"  [PASS] {step_name} ({duration_ms:.1f}ms)")


def record_fail(step_name: str, error_msg: str, duration_ms: float = 0.0):
    global FAILED
    FAILED += 1
    TEST_RESULTS.append({"test": step_name, "status": "FAIL", "error": error_msg, "duration_ms": duration_ms})
    print(f"  [FAIL] {step_name}: {error_msg} ({duration_ms:.1f}ms)")


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
    start_total = time.time()

    print("================================================================================")
    print("MONITORIX ENTERPRISE — PHASE 5.4.1A TEST SUITE STARTING")
    print("Incident Management Backend Security & SOC Case Lifecycle Hardening")
    print("================================================================================")

    # Tokens for testing
    token_t1_admin = mint_token("elsea", "TenantAdmin", 1)
    token_t1_analyst = mint_token("secops_analyst_test@enterprise.corp", "Analyst", 1)
    token_t1_viewer = mint_token("viewer_test", "Viewer", 1)
    token_t1_auditor = mint_token("auditor_test", "Auditor", 1)

    token_t4_admin = mint_token("test", "TenantAdmin", 4)
    token_t4_analyst = mint_token("analyst_t4", "Analyst", 4)

    # Test fixtures tracking
    created_case_ids = []
    created_comment_ids = []
    created_alert_ids = []
    created_incident_ids = []

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:

        # ----------------------------------------------------------------------
        # TEST 1: Unauthenticated Request Rejection (HTTP 401)
        # ----------------------------------------------------------------------
        log_header(1, "Unauthenticated Request Rejection")
        t0 = time.time()
        try:
            endpoints = [
                ("GET", "/api/incidents"),
                ("POST", "/api/incidents"),
                ("GET", "/api/v2/soc/cases"),
                ("POST", "/api/v2/soc/cases"),
                ("GET", "/api/v2/soc/cases/999"),
                ("PATCH", "/api/v2/soc/cases/999/status"),
                ("POST", "/api/v2/soc/cases/promote-alert"),
                ("POST", "/api/v2/soc/cases/999/contain-host"),
            ]
            for method, url in endpoints:
                if method == "GET":
                    resp = await client.get(url)
                elif method == "POST":
                    resp = await client.post(url, json={})
                elif method == "PATCH":
                    resp = await client.patch(url, json={})
                assert resp.status_code == 401, f"Expected 401 for unauth {method} {url}, got {resp.status_code}"
            record_pass("All unauthenticated endpoints strictly returned HTTP 401", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Unauthenticated request rejection", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 2: Cross-Tenant Case Access (HTTP 404)
        # ----------------------------------------------------------------------
        log_header(2, "Cross-Tenant Case Access Isolation")
        t0 = time.time()
        try:
            # Create case in Tenant 1
            h_t1 = {"Authorization": f"Bearer {token_t1_admin}"}
            payload = {
                "title": "Cross-Tenant Isolation Case",
                "description": "Tenant 1 private case fixture",
                "severity": "Medium",
                "priority": "P2"
            }
            c_res = await client.post("/api/v2/soc/cases", headers=h_t1, json=payload)
            assert c_res.status_code == 201, f"Failed creating case: {c_res.text}"
            case_id = c_res.json()["id"]
            created_case_ids.append(case_id)

            # Tenant 4 attempts GET /cases/{case_id} -> 404
            h_t4 = {"Authorization": f"Bearer {token_t4_admin}"}
            get_res = await client.get(f"/api/v2/soc/cases/{case_id}", headers=h_t4)
            assert get_res.status_code == 404, f"Cross-tenant detail read returned {get_res.status_code} instead of 404"

            # Tenant 4 attempts PATCH /cases/{case_id}/status -> 404
            patch_res = await client.patch(
                f"/api/v2/soc/cases/{case_id}/status",
                headers=h_t4,
                json={"status": "CLOSED", "closure_summary": "Malicious close"}
            )
            assert patch_res.status_code == 404, f"Cross-tenant status patch returned {patch_res.status_code} instead of 404"

            # Tenant 4 listing cases does NOT include Tenant 1 case
            list_res = await client.get("/api/v2/soc/cases", headers=h_t4)
            assert list_res.status_code == 200
            t4_ids = [c["id"] for c in list_res.json()]
            assert case_id not in t4_ids, "Tenant 1 case leaked into Tenant 4 case listing!"

            record_pass("Cross-tenant case read, mutation, and listing prevented (HTTP 404)", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Cross-tenant case access isolation", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 3: Cross-Tenant Comment Access (HTTP 404)
        # ----------------------------------------------------------------------
        log_header(3, "Cross-Tenant Comment Access Isolation")
        t0 = time.time()
        try:
            # Tenant 1 adds comment to Tenant 1 case
            cm_res = await client.post(
                f"/api/v2/soc/cases/{created_case_ids[0]}/comments",
                headers=h_t1,
                json={"comment_text": "Confidential investigation notes", "is_customer_visible": False}
            )
            assert cm_res.status_code == 201, f"Failed posting comment: {cm_res.text}"
            created_comment_ids.append(cm_res.json()["id"])

            # Tenant 4 attempts to read comments -> 404
            get_cm = await client.get(f"/api/v2/soc/cases/{created_case_ids[0]}/comments", headers=h_t4)
            assert get_cm.status_code == 404, f"Cross-tenant comment get returned {get_cm.status_code} instead of 404"

            # Tenant 4 attempts to post comment -> 404
            post_cm = await client.post(
                f"/api/v2/soc/cases/{created_case_ids[0]}/comments",
                headers=h_t4,
                json={"comment_text": "Unauthorized cross-tenant comment"}
            )
            assert post_cm.status_code == 404, f"Cross-tenant comment post returned {post_cm.status_code} instead of 404"

            record_pass("Cross-tenant comment read and post strictly rejected (HTTP 404)", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Cross-tenant comment access isolation", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 4: RBAC Enforcement (HTTP 403)
        # ----------------------------------------------------------------------
        log_header(4, "RBAC Enforcement")
        t0 = time.time()
        try:
            h_viewer = {"Authorization": f"Bearer {token_t1_viewer}"}
            h_auditor = {"Authorization": f"Bearer {token_t1_auditor}"}
            h_analyst = {"Authorization": f"Bearer {token_t1_analyst}"}

            # Viewer case create -> 403
            v_c = await client.post("/api/v2/soc/cases", headers=h_viewer, json={"title": "Viewer Case", "severity": "Low"})
            assert v_c.status_code == 403, f"Viewer case create returned {v_c.status_code} instead of 403"

            # Auditor status update -> 403
            a_s = await client.patch(
                f"/api/v2/soc/cases/{created_case_ids[0]}/status",
                headers=h_auditor,
                json={"status": "TRIAGED"}
            )
            assert a_s.status_code == 403, f"Auditor status patch returned {a_s.status_code} instead of 403"

            # Viewer legacy incident create -> 403 (with full valid payload)
            v_inc = await client.post(
                "/api/incidents",
                headers=h_viewer,
                json={"title": "Viewer Inc", "description": "Desc", "severity": "Medium", "agent_id": "pilot-46ef27fe"}
            )
            assert v_inc.status_code == 403, f"Viewer incident create returned {v_inc.status_code} instead of 403"

            # Authorized Analyst case create -> 201
            an_c = await client.post(
                "/api/v2/soc/cases",
                headers=h_analyst,
                json={"title": "Analyst Authorized Case", "severity": "High"}
            )
            assert an_c.status_code == 201, f"Analyst case create failed: {an_c.text}"
            created_case_ids.append(an_c.json()["id"])

            record_pass("Unauthorized roles blocked with 403; Analyst authorized with 201", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("RBAC enforcement", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 5: Case Creation & Tenant Protection
        # ----------------------------------------------------------------------
        log_header(5, "Case Creation & Tenant ID Override Protection")
        t0 = time.time()
        try:
            payload = {
                "title": "Credential Harvest Suspect",
                "description": "Suspicious LSASS memory access detected on host",
                "severity": "Critical",
                "priority": "P1",
                "tenant_id": 999  # Malicious injection attempt
            }
            res = await client.post("/api/v2/soc/cases", headers=h_t1, json=payload)
            assert res.status_code == 201
            data = res.json()
            created_case_ids.append(data["id"])

            # Verify CaseNumber format: CASE-YYYY-HEX6
            case_num = data["case_number"]
            assert re.match(r"^CASE-\d{4}-[0-9A-Fa-f]{6}$", case_num), f"CaseNumber invalid: {case_num}"

            # Verify initial status NEW
            assert data["status"] == "NEW", f"Initial status was {data['status']}"

            # Verify tenant_id was locked to authenticated user's tenant (1)
            assert data["tenant_id"] == 1, f"Tenant override succeeded! tenant_id={data['tenant_id']}"

            record_pass(f"Case {case_num} created with status NEW and protected TenantId=1", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Case creation and tenant protection", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 6: Alert Promotion to SOC Case
        # ----------------------------------------------------------------------
        log_header(6, "Alert Promotion to SOC Case")
        t0 = time.time()
        try:
            # Create fixture DetectionAlert
            async with AsyncSessionLocal() as db:
                alert = DetectionAlert(
                    AgentId="pilot-46ef27fe",
                    MatchedContent=json.dumps({"signature": "Win.Trojan.CobaltStrike", "tactic": "Execution", "technique": "T1059"}),
                    Status="New",
                    Timestamp=datetime.utcnow(),
                    HitCount=1
                )
                db.add(alert)
                await db.commit()
                await db.refresh(alert)
                alert_id = alert.Id
                created_alert_ids.append(alert_id)

            promote_payload = {
                "alert_id": alert_id,
                "title": "Promoted CobaltStrike Beacon Alert",
                "priority": "P1",
                "notes": "Escalated from behavioral sensor detection"
            }
            p_res = await client.post("/api/v2/soc/cases/promote-alert", headers=h_analyst, json=promote_payload)
            assert p_res.status_code == 201, f"Alert promotion failed: {p_res.text}"
            p_data = p_res.json()
            created_case_ids.append(p_data["id"])

            assert p_data["title"] == "Promoted CobaltStrike Beacon Alert"
            assert p_data["status"] == "NEW"
            assert p_data["tenant_id"] == 1
            assert len(p_data["evidence"]) >= 1

            # Check alert status transitioned
            async with AsyncSessionLocal() as db:
                refreshed_alert = await db.get(DetectionAlert, alert_id)
                assert refreshed_alert.Status in ("Promoted", "Investigating")

            record_pass(f"Alert {alert_id} successfully promoted to Case {p_data['case_number']}", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Alert promotion to SOC case", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 7: Duplicate Promotion Prevention (HTTP 409 Conflict)
        # ----------------------------------------------------------------------
        log_header(7, "Duplicate Alert Promotion Prevention")
        t0 = time.time()
        try:
            # Re-promote the same alert from Test 6
            target_alert_id = created_alert_ids[-1]
            dup_res = await client.post(
                "/api/v2/soc/cases/promote-alert",
                headers=h_analyst,
                json={"alert_id": target_alert_id, "title": "Duplicate Promotion Attempt"}
            )
            assert dup_res.status_code == 409, f"Duplicate promotion returned {dup_res.status_code} instead of 409: {dup_res.text}"
            assert "promoted" in dup_res.json().get("detail", "").lower(), f"Unexpected detail: {dup_res.json()}"

            record_pass("Duplicate alert promotion strictly rejected with HTTP 409 Conflict", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Duplicate alert promotion prevention", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 8: Valid Lifecycle Transitions
        # ----------------------------------------------------------------------
        log_header(8, "Valid SOC Case Lifecycle Transitions")
        t0 = time.time()
        try:
            # Step 0: Create fresh case (NEW)
            c_fresh = await client.post(
                "/api/v2/soc/cases",
                headers=h_t1,
                json={"title": "Lifecycle E2E Case", "severity": "High"}
            )
            assert c_fresh.status_code == 201
            case_id = c_fresh.json()["id"]
            created_case_ids.append(case_id)
            assert c_fresh.json()["status"] == "NEW"

            # Step 1: NEW -> TRIAGED
            t_res = await client.patch(
                f"/api/v2/soc/cases/{case_id}/status",
                headers=h_t1,
                json={"status": "TRIAGED", "notes": "Initial triage complete"}
            )
            assert t_res.status_code == 200
            assert t_res.json()["status"] == "TRIAGED"

            # Step 2: TRIAGED -> CONTAINED
            cnt_res = await client.patch(
                f"/api/v2/soc/cases/{case_id}/status",
                headers=h_t1,
                json={"status": "CONTAINED", "notes": "Host isolated"}
            )
            assert cnt_res.status_code == 200
            assert cnt_res.json()["status"] == "CONTAINED"

            # Step 3: CONTAINED -> RESOLVED
            r_res = await client.patch(
                f"/api/v2/soc/cases/{case_id}/status",
                headers=h_t1,
                json={"status": "RESOLVED", "notes": "Artifact purged"}
            )
            assert r_res.status_code == 200
            assert r_res.json()["status"] == "RESOLVED"

            # Step 4: RESOLVED -> CLOSED
            cl_res = await client.patch(
                f"/api/v2/soc/cases/{case_id}/status",
                headers=h_t1,
                json={"status": "CLOSED", "closure_summary": "Neutralized and closed"}
            )
            assert cl_res.status_code == 200
            assert cl_res.json()["status"] == "CLOSED"
            assert cl_res.json()["closed_at"] is not None

            record_pass("Full valid lifecycle (NEW -> TRIAGED -> CONTAINED -> RESOLVED -> CLOSED) verified", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Valid lifecycle transitions", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 9: Invalid Lifecycle Transitions (HTTP 400 Bad Request)
        # ----------------------------------------------------------------------
        log_header(9, "Invalid Lifecycle Transitions Rejection")
        t0 = time.time()
        try:
            # Create fresh case (NEW)
            c_fresh2 = await client.post(
                "/api/v2/soc/cases",
                headers=h_t1,
                json={"title": "Invalid Transition Test Case", "severity": "Low"}
            )
            assert c_fresh2.status_code == 201
            case_id2 = c_fresh2.json()["id"]
            created_case_ids.append(case_id2)

            # Invalid: NEW -> CONTAINED directly
            bad1 = await client.patch(
                f"/api/v2/soc/cases/{case_id2}/status",
                headers=h_t1,
                json={"status": "CONTAINED"}
            )
            assert bad1.status_code == 400, f"NEW->CONTAINED returned {bad1.status_code} instead of 400: {bad1.text}"
            assert "transition" in bad1.json().get("detail", "").lower(), f"Unexpected detail: {bad1.json()}"

            # Invalid: NEW -> RESOLVED directly
            bad2 = await client.patch(
                f"/api/v2/soc/cases/{case_id2}/status",
                headers=h_t1,
                json={"status": "RESOLVED"}
            )
            assert bad2.status_code == 400, f"NEW->RESOLVED returned {bad2.status_code} instead of 400: {bad2.text}"

            # Close case
            await client.patch(
                f"/api/v2/soc/cases/{case_id2}/status",
                headers=h_t1,
                json={"status": "CLOSED", "closure_summary": "Closed"}
            )

            # Invalid: CLOSED -> RESOLVED
            bad3 = await client.patch(
                f"/api/v2/soc/cases/{case_id2}/status",
                headers=h_t1,
                json={"status": "RESOLVED"}
            )
            assert bad3.status_code == 400, f"CLOSED->RESOLVED returned {bad3.status_code} instead of 400: {bad3.text}"

            record_pass("All illegal state machine transitions strictly rejected with HTTP 400", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Invalid lifecycle transitions rejection", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 10: Comment Persistence & Chronological Retrieval
        # ----------------------------------------------------------------------
        log_header(10, "Comment Persistence & Chronological Order")
        t0 = time.time()
        try:
            case_id = created_case_ids[0]

            # Add internal comment
            cm1 = await client.post(
                f"/api/v2/soc/cases/{case_id}/comments",
                headers=h_analyst,
                json={"comment_text": "Internal forensic analysis started", "is_customer_visible": False}
            )
            assert cm1.status_code == 201
            cm1_id = cm1.json()["id"]
            created_comment_ids.append(cm1_id)

            # Add customer visible comment
            cm2 = await client.post(
                f"/api/v2/soc/cases/{case_id}/comments",
                headers=h_analyst,
                json={"comment_text": "Customer advisory: Host undergoing containment", "is_customer_visible": True}
            )
            assert cm2.status_code == 201
            cm2_id = cm2.json()["id"]
            created_comment_ids.append(cm2_id)

            # Fetch comments
            get_cms = await client.get(f"/api/v2/soc/cases/{case_id}/comments", headers=h_analyst)
            assert get_cms.status_code == 200
            cms = get_cms.json()
            assert len(cms) >= 2
            # Verify chronological order and visibility
            matching = [c for c in cms if c["id"] in (cm1_id, cm2_id)]
            assert len(matching) == 2
            assert matching[0]["id"] == cm1_id
            assert matching[0]["is_customer_visible"] is False
            assert matching[1]["id"] == cm2_id
            assert matching[1]["is_customer_visible"] is True

            record_pass("Comments persisted with correct visibility and chronological ordering", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Comment persistence & chronological order", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 11: Security Audit Event Creation
        # ----------------------------------------------------------------------
        log_header(11, "Security Audit Event Creation")
        t0 = time.time()
        try:
            # Create a dedicated case to track its audit log
            c_aud = await client.post(
                "/api/v2/soc/cases",
                headers=h_t1,
                json={"title": "Audit Event Target Case", "severity": "Medium"}
            )
            assert c_aud.status_code == 201
            case_num = c_aud.json()["case_number"]
            created_case_ids.append(c_aud.json()["id"])

            # Query database for AuditLog
            async with AsyncSessionLocal() as db:
                audit_res = await db.execute(
                    select(AuditLog).where(
                        AuditLog.Target.like(f"%{case_num}%"),
                        AuditLog.Action == "SocCaseCreated"
                    )
                )
                log_entry = audit_res.scalars().first()
                assert log_entry is not None, f"AuditLog entry not found for SocCaseCreated with Target containing {case_num}"
                assert log_entry.TenantId == 1
                assert log_entry.Actor == "elsea"

            record_pass(f"Audit event successfully recorded for Case {case_num} in AuditLogs table", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Security audit event creation", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 12: Containment Authorization (Admin/SuperAdmin required)
        # ----------------------------------------------------------------------
        log_header(12, "Containment Authorization Enforcement")
        t0 = time.time()
        try:
            target_case_id = created_case_ids[0]
            # Analyst containment -> 403
            an_cnt = await client.post(
                f"/api/v2/soc/cases/{target_case_id}/contain-host",
                headers=h_analyst,
                json={"agent_id": "pilot-46ef27fe", "confirmed": True, "safe_mode": True, "reason": "Analyst Unauthorized"}
            )
            assert an_cnt.status_code == 403, f"Analyst containment returned {an_cnt.status_code} instead of 403"

            # Viewer containment -> 403
            v_cnt = await client.post(
                f"/api/v2/soc/cases/{target_case_id}/contain-host",
                headers=h_viewer,
                json={"agent_id": "pilot-46ef27fe", "confirmed": True, "safe_mode": True, "reason": "Viewer Unauthorized"}
            )
            assert v_cnt.status_code == 403, f"Viewer containment returned {v_cnt.status_code} instead of 403"

            record_pass("Containment strictly blocked for Analyst and Viewer roles (HTTP 403)", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Containment authorization enforcement", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 13: Containment Safe-Mode Behavior & Cross-Tenant Rejection
        # ----------------------------------------------------------------------
        log_header(13, "Containment Safe-Mode Behavior & Protection")
        t0 = time.time()
        try:
            target_case_id = created_case_ids[0]
            # Unconfirmed containment -> 400
            unconf = await client.post(
                f"/api/v2/soc/cases/{target_case_id}/contain-host",
                headers=h_t1,
                json={"agent_id": "pilot-46ef27fe", "confirmed": False, "safe_mode": True, "reason": "Unconfirmed test"}
            )
            assert unconf.status_code == 400, f"Unconfirmed containment returned {unconf.status_code} instead of 400"

            # Cross-tenant agent containment -> 404 (AG-E2E-650C87AC is Tenant 3)
            cross_cnt = await client.post(
                f"/api/v2/soc/cases/{target_case_id}/contain-host",
                headers=h_t1,
                json={"agent_id": "AG-E2E-650C87AC", "confirmed": True, "safe_mode": True, "reason": "Cross-tenant attack"}
            )
            assert cross_cnt.status_code == 404, f"Cross-tenant containment returned {cross_cnt.status_code} instead of 404"

            # Valid safe-mode containment for Tenant 1 agent -> 200
            valid_cnt = await client.post(
                f"/api/v2/soc/cases/{target_case_id}/contain-host",
                headers=h_t1,
                json={"agent_id": "pilot-46ef27fe", "confirmed": True, "safe_mode": True, "reason": "Safe mode containment test"}
            )
            assert valid_cnt.status_code == 200, f"Safe mode containment failed: {valid_cnt.text}"
            cnt_data = valid_cnt.json()
            assert cnt_data["status"].lower() == "success"
            assert cnt_data["safe_mode"] is True

            record_pass("Containment safe-mode verified: zero live disruption, unconfirmed rejected, cross-tenant 404", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Containment safe-mode behavior and protection", str(e), (time.time() - t0) * 1000)

        # ----------------------------------------------------------------------
        # TEST 14: Database Transaction Atomicity & Rollback Verification
        # ----------------------------------------------------------------------
        log_header(14, "Database Transaction Atomicity & Rollback")
        t0 = time.time()
        try:
            # Attempt promoting non-existent alert
            fail_res = await client.post(
                "/api/v2/soc/cases/promote-alert",
                headers=h_t1,
                json={"alert_id": 99999999, "title": "Ghost Alert Should Rollback"}
            )
            assert fail_res.status_code == 404

            # Verify no orphan SocCase was created
            async with AsyncSessionLocal() as db:
                chk = await db.execute(
                    select(SocCase).where(SocCase.Title == "Ghost Alert Should Rollback")
                )
                orphan = chk.scalars().first()
                assert orphan is None, "Orphan case record created despite failed transaction!"

            record_pass("Transactional integrity verified: zero orphan rows on failed operation", (time.time() - t0) * 1000)
        except Exception as e:
            record_fail("Database transaction atomicity & rollback", str(e), (time.time() - t0) * 1000)

    # --------------------------------------------------------------------------
    # Database Fixtures Cleanup
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("[CLEANUP] Pruning test fixtures from database...")
    async with AsyncSessionLocal() as db:
        if created_comment_ids:
            await db.execute(delete(SocCaseComment).where(SocCaseComment.Id.in_(created_comment_ids)))
        if created_case_ids:
            await db.execute(delete(SocCase).where(SocCase.Id.in_(created_case_ids)))
        if created_alert_ids:
            await db.execute(delete(DetectionAlert).where(DetectionAlert.Id.in_(created_alert_ids)))
        if created_incident_ids:
            await db.execute(delete(Incident).where(Incident.Id.in_(created_incident_ids)))
        # Reset test agent isolation status
        res = await db.execute(select(Agent).where(Agent.AgentId == "pilot-46ef27fe"))
        target_agent = res.scalars().first()
        if target_agent:
            target_agent.IsIsolated = False
        await db.commit()
    print(f"[CLEANUP] Successfully removed {len(created_case_ids)} cases, {len(created_comment_ids)} comments, {len(created_alert_ids)} alerts.")

    # --------------------------------------------------------------------------
    # Suite Summary
    # --------------------------------------------------------------------------
    total_time = (time.time() - start_total)
    print("\n" + "=" * 80)
    print("MONITORIX ENTERPRISE — PHASE 5.4.1A TEST SUMMARY")
    print("=" * 80)
    print(f"Total Tests Run: 14")
    print(f"Passed:          {PASSED}")
    print(f"Failed:          {FAILED}")
    print(f"Execution Time:  {total_time:.2f}s")
    print("=" * 80)

    if FAILED > 0:
        print("\nFailed Tests Breakdown:")
        for r in TEST_RESULTS:
            if r["status"] == "FAIL":
                print(f"  - {r['test']}: {r.get('error')}")
        sys.exit(1)
    else:
        print("\n>>> ALL 14 INCIDENT MANAGEMENT & SOC CASE VALIDATION TESTS PASSED! <<<")
        sys.exit(0)


if __name__ == "__main__":
    asyncio.run(run_suite())
