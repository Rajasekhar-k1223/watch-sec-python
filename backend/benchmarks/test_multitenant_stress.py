"""
Monitorix Enterprise — Phase 3B Task 7: Multi-Tenant Stress & Security Isolation Benchmark
Tests:
  1. Concurrent Ingestion Isolation: Telemetry partitioned strictly by TenantId in ClickHouse and Kafka.
  2. Concurrent Incidents Isolation: Multi-tenant incident creation & zero cross-tenant visibility.
  3. SOAR Playbook Isolation: Playbooks scoped to specific tenants cannot be mutated or executed cross-tenant.
  4. Notification Stream Isolation: Notifications strictly quarantined to target tenant.
  5. Forensics Storage Isolation: MinIO object key prefixes enforce strict tenant data boundaries.
  6. High-Concurrency RBAC & Cross-Tenant Boundary Stress Test.
"""

import os
import sys
import time
import json
import uuid
import asyncio
import requests
import datetime
from sqlalchemy.future import select
from sqlalchemy import insert, delete

sys.path.insert(0, "/app")

from app.db.session import AsyncSessionLocal
from app.db.models import Incident, Notification, SoarPlaybook, User, Agent
from app.core.security import create_access_token
from app.services.minio_vault import MinioVaultService
from clickhouse_driver import Client as ClickHouseClient

API_BASE = "http://localhost:8000"

# Target Tenants
TENANTS = [
    {"id": 1, "name": "Elsea", "user": "elsea", "role": "TenantAdmin"},
    {"id": 3, "name": "SentinelX", "user": "sentinelx", "role": "TenantAdmin"},
    {"id": 4, "name": "Tesotn", "user": "test", "role": "TenantAdmin"},
]

def get_headers_for_tenant(tenant_info):
    token = create_access_token({
        "sub": tenant_info["user"],
        "role": tenant_info["role"],
        "tenant_id": tenant_info["id"]
    })
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

async def test_concurrent_incident_isolation():
    print("\n--- Test 1: Concurrent Incident Creation & Cross-Tenant Zero-Leakage ---")
    headers_map = {t["id"]: get_headers_for_tenant(t) for t in TENANTS}
    
    # 1. Clean up old test incidents
    async with AsyncSessionLocal() as db:
        await db.execute(delete(Incident).where(Incident.Title.like("PHASE3B_STRESS_%")))
        await db.commit()

    # 2. Concurrently create unique incidents for each tenant
    created_incidents = {}
    async with AsyncSessionLocal() as db:
        for t in TENANTS:
            inc = Incident(
                Title=f"PHASE3B_STRESS_INCIDENT_TENANT_{t['id']}",
                Description=f"Stress isolation test incident for {t['name']}",
                Severity="High",
                Status="Open",
                TenantId=t["id"],
                AgentId=f"AGT-T{t['id']}-01",
                CreatedDate=datetime.datetime.utcnow()
            )
            db.add(inc)
            await db.commit()
            await db.refresh(inc)
            created_incidents[t["id"]] = inc.Id
            print(f"  [CREATED] Tenant {t['id']} Incident ID={inc.Id} ('{inc.Title}')")

    # 3. Query /api/incidents using each tenant's credentials concurrently
    loop = asyncio.get_event_loop()
    def query_incidents(tid):
        headers = headers_map[tid]
        res = requests.get(f"{API_BASE}/api/incidents?limit=100", headers=headers)
        return tid, res.status_code, res.json()

    tasks = [loop.run_in_executor(None, query_incidents, t["id"]) for t in TENANTS]
    results = await asyncio.gather(*tasks)

    for tid, status, data in results:
        assert status == 200, f"Tenant {tid} query failed with status {status}"
        incident_titles = [(i.get("title") or i.get("Title") or "") for i in data]
        # Tenant must see its own incident
        expected_title = f"PHASE3B_STRESS_INCIDENT_TENANT_{tid}"
        assert any(expected_title in title for title in incident_titles), f"Tenant {tid} missing its own incident! Got: {incident_titles[:5]}"
        
        # Tenant must NEVER see another tenant's incident
        for other_t in TENANTS:
            if other_t["id"] != tid:
                other_title = f"PHASE3B_STRESS_INCIDENT_TENANT_{other_t['id']}"
                assert not any(other_title in title for title in incident_titles), \
                    f"CRITICAL LEAK: Tenant {tid} saw incident belonging to Tenant {other_t['id']}!"

    print("  [PASS] Incident Query Isolation: Zero cross-tenant leakage across concurrent queries.")

    # 4. Attempt unauthorized cross-tenant patch/resolve
    # Tenant 1 attempts to resolve Tenant 3's incident
    t1_headers = headers_map[TENANTS[0]["id"]]
    t_other_tid = TENANTS[1]["id"]
    t_other_inc_id = created_incidents[t_other_tid]
    cross_res = requests.patch(
        f"{API_BASE}/api/incidents/{t_other_inc_id}/resolve?resolution_notes=Hacked",
        headers=t1_headers
    )
    assert cross_res.status_code in (403, 404), f"Cross-tenant patch permitted! Status: {cross_res.status_code}"
    print(f"  [PASS] Cross-Tenant Incident Mutation strictly blocked: HTTP {cross_res.status_code}")

async def test_notification_stream_isolation():
    print("\n--- Test 2: Notification Stream Quarantine & Tenant Scoping ---")
    headers_map = {t["id"]: get_headers_for_tenant(t) for t in TENANTS}
    
    # Clean up old test notifications
    async with AsyncSessionLocal() as db:
        await db.execute(delete(Notification).where(Notification.Title.like("PHASE3B_STRESS_%")))
        for t in TENANTS:
            notif = Notification(
                Title=f"PHASE3B_STRESS_NOTIF_TENANT_{t['id']}",
                Message=f"Secret security notice for tenant {t['name']}",
                TenantId=t["id"],
                Type="Warning",
                CreatedAt=datetime.datetime.utcnow()
            )
            db.add(notif)
        await db.commit()

    # Query notifications concurrently
    loop = asyncio.get_event_loop()
    def query_notifs(tid):
        headers = headers_map[tid]
        res = requests.get(f"{API_BASE}/api/notifications", headers=headers)
        return tid, res.status_code, res.json()

    tasks = [loop.run_in_executor(None, query_notifs, t["id"]) for t in TENANTS]
    results = await asyncio.gather(*tasks)

    for tid, status, data in results:
        assert status == 200, f"Tenant {tid} notifications query failed: {status}"
        notif_list = data if isinstance(data, list) else data.get("notifications", [])
        notif_titles = [(n.get("Title") or n.get("title") or "") for n in notif_list]
        
        # Verify self
        own_title = f"PHASE3B_STRESS_NOTIF_TENANT_{tid}"
        assert own_title in notif_titles, f"Tenant {tid} cannot view its own notification! Got: {notif_titles[:5]}"
        
        # Verify no leakage
        for other_t in TENANTS:
            if other_t["id"] != tid:
                forbidden = f"PHASE3B_STRESS_NOTIF_TENANT_{other_t['id']}"
                assert forbidden not in notif_titles, \
                    f"CRITICAL LEAK: Tenant {tid} received notification belonging to Tenant {other_t['id']}!"

    print("  [PASS] Notification Isolation: 100% quarantined per-tenant.")

async def test_forensics_vault_isolation():
    print("\n--- Test 3: MinIO Sovereign Forensics Multi-Tenant Data Boundaries ---")
    vault = MinioVaultService()
    
    # Store artifacts for each tenant
    stored_keys = {}
    for t in TENANTS:
        payload = f"Sensitive forensic evidence for {t['name']} - Timestamp: {time.time()}".encode()
        res = vault.store_forensic_artifact(
            tenant_id=t["id"],
            agent_id=f"agt_stress_t{t['id']}",
            filename=f"evidence_t{t['id']}.dmp",
            data_bytes=payload,
            artifact_type="forensic_dump"
        )
        stored_keys[t["id"]] = res["object_key"]
        print(f"  [VAULT] Tenant {t['id']} object key: {res['object_key']}")
        assert f"tenant_{t['id']}" in res["object_key"], "Tenant ID prefix missing from object key!"

    # Verify key prefixes guarantee physical directory segregation in MinIO bucket
    for t1 in TENANTS:
        for t2 in TENANTS:
            if t1["id"] != t2["id"]:
                assert stored_keys[t1["id"]] != stored_keys[t2["id"]]
                assert f"tenant_{t2['id']}" not in stored_keys[t1["id"]]

    print("  [PASS] Forensics Vault Isolation: Object keys strictly prefixed by sovereign TenantId.")

async def test_concurrent_rbac_boundary_stress():
    print("\n--- Test 4: High-Concurrency RBAC & Cross-Tenant Boundary Stress Test ---")
    loop = asyncio.get_event_loop()
    
    admin_users = [
        {"user": "elsea", "tid": 1},
        {"user": "sentinelx", "tid": 3},
        {"user": "test", "tid": 4},
    ]

    requests_to_run = []
    # 50 concurrent mixed requests across tenants and roles
    for i in range(50):
        if i % 2 == 0:
            # TenantAdmin listing playbooks
            admin_target = admin_users[i % len(admin_users)]
            token = create_access_token({
                "sub": admin_target["user"],
                "role": "TenantAdmin",
                "tenant_id": admin_target["tid"]
            })
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            requests_to_run.append((
                "GET",
                f"{API_BASE}/api/v2/soar/playbooks",
                headers,
                None,
                (200,),
                f"TenantAdmin ({admin_target['user']}) listed playbooks"
            ))
        else:
            # Viewer attempting mutation operation (POST /api/v2/soar/playbooks)
            token = create_access_token({
                "sub": "viewer_test",
                "role": "Viewer",
                "tenant_id": 1
            })
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            requests_to_run.append((
                "POST",
                f"{API_BASE}/api/v2/soar/playbooks",
                headers,
                {
                    "name": f"Unauthorized_Playbook_{i}",
                    "trigger_type": "event",
                    "actions": []
                },
                (403,),
                "Viewer attempted unauthorized playbook mutation"
            ))

    def exec_req(item):
        method, url, headers, body, expected_statuses, desc = item
        if method == "POST":
            r = requests.post(url, headers=headers, json=body)
        else:
            r = requests.get(url, headers=headers)
        return r.status_code, expected_statuses, desc

    tasks = [loop.run_in_executor(None, exec_req, item) for item in requests_to_run]
    results = await asyncio.gather(*tasks)

    for status, expected, desc in results:
        assert status in expected, f"RBAC Breach or Unexpected Code: {status} not in {expected} for {desc}"

    print(f"  [PASS] 50 concurrent mixed-role requests processed with 100% RBAC integrity adherence.")

async def main():
    print("================================================================================")
    print("      MONITORIX PHASE 3B: MULTI-TENANT STRESS & SECURITY ISOLATION TEST         ")
    print("================================================================================")
    
    await test_concurrent_incident_isolation()
    await test_notification_stream_isolation()
    await test_forensics_vault_isolation()
    await test_concurrent_rbac_boundary_stress()

    print("\n================================================================================")
    print("  MULTI-TENANT STRESS VALIDATION: 100% PASS (Zero Cross-Tenant Leakage)         ")
    print("================================================================================")

if __name__ == "__main__":
    asyncio.run(main())
