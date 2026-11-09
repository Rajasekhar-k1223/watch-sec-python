#!/usr/bin/env python3
"""
Monitorix Fleet-Wide Mutual TLS (mTLS) Migration & Validation Orchestrator
==========================================================================
Executes controlled, staged migration of all eligible registered agents to
individual X.509 cryptographic identities and strict Mutual TLS:

Stages:
  Stage A-D: Single dedicated pilot test agent migration & telemetry validation.
  Stage E-F: 10% Canary group migration & health monitoring.
  Stage G:   Batch migration of remaining eligible registered agents.
  Stage H:   Authoritative fleet-wide verification & 0 plaintext dependency audit.
"""

import os
import sys
import json
import time
import datetime
from datetime import timedelta
import stat
import grpc
import requests

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from sqlalchemy.future import select
from sqlalchemy import and_, or_

# App imports
from app.db.session import AsyncSessionLocal
from app.db.models import Agent, DeviceCertificate, AgentEnrollmentToken
from app.services import ca_service
from app import telemetry_pb2, telemetry_pb2_grpc

API_BASE = os.getenv("API_BASE", "http://127.0.0.1:8000")
GRPC_HOST = os.getenv("GRPC_HOST", "watch-sec-grpc-gateway:50051")
CERT_STORE_BASE = "/app/storage/agent_certs"

def log_stage(stage_code: str, title: str):
    print("\n" + "=" * 80)
    print(f"[{stage_code}] {title}")
    print("=" * 80)

def ensure_agent_cert_dir(agent_id: str) -> str:
    path = os.path.join(CERT_STORE_BASE, agent_id)
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path

def generate_agent_key_and_csr(agent_id: str, tenant_id: int):
    """Generates an agent RSA-2048 private key and signed CSR locally."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Monitorix Sovereign Edge"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"Tenant-{tenant_id}"),
        x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
    ])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return key, key_pem, csr_pem

async def enroll_agent_mtls(agent_id: str, tenant_id: int) -> dict:
    """Enrolls an agent via PKI service, signs CSR, saves certs, and enables RequireMtls."""
    cert_dir = ensure_agent_cert_dir(agent_id)
    key_path = os.path.join(cert_dir, "agent.key")
    cert_path = os.path.join(cert_dir, "agent.crt")
    ca_path = os.path.join(cert_dir, "ca_chain.pem")

    # 1. Generate local key & CSR
    key, key_pem, csr_pem = generate_agent_key_and_csr(agent_id, tenant_id)

    # 2. Issue 10-minute single-use enrollment token
    now = datetime.datetime.utcnow()
    token_str = f"enr_fleet_{agent_id[:16]}_{int(now.timestamp())}"
    
    async with AsyncSessionLocal() as db:
        token_record = AgentEnrollmentToken(
            Token=token_str,
            TenantId=tenant_id,
            CreatedBy="fleet_migrator",
            MaxUses=1,
            UsesCount=0,
            ExpiresAt=now + timedelta(minutes=10),
            IsRevoked=False,
            CreatedAt=now
        )
        db.add(token_record)
        await db.commit()

    # 3. Submit enrollment CSR
    resp = requests.post(
        f"{API_BASE}/api/v2/pki/enroll",
        json={
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "enrollment_token": token_str,
            "csr_pem": csr_pem
        },
        timeout=10
    )
    if resp.status_code != 201:
        raise RuntimeError(f"Enrollment API returned {resp.status_code}: {resp.text}")

    enroll_data = resp.json()

    # 4. Save credentials with strict permissions
    with open(key_path, "wb") as f:
        f.write(key_pem)
    os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR) # 0600

    with open(cert_path, "w") as f:
        f.write(enroll_data["certificate_pem"])
    os.chmod(cert_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH) # 0644

    with open(ca_path, "w") as f:
        f.write(enroll_data["ca_chain_pem"])
    os.chmod(ca_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH) # 0644

    return {
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "serial_number": enroll_data["serial_number"],
        "expires_at": enroll_data["expires_at"],
        "key_path": key_path,
        "cert_path": cert_path,
        "ca_path": ca_path,
        "key_pem": key_pem,
        "cert_pem": enroll_data["certificate_pem"].encode("utf-8"),
        "ca_pem": enroll_data["ca_chain_pem"].encode("utf-8"),
    }

def verify_agent_mtls_stream(credentials: dict, event_count: int = 2) -> dict:
    """Tests establishing an authenticated mTLS channel and streaming telemetry."""
    t_start = time.perf_counter()

    ssl_creds = grpc.ssl_channel_credentials(
        root_certificates=credentials["ca_pem"],
        private_key=credentials["key_pem"],
        certificate_chain=credentials["cert_pem"]
    )
    options = (('grpc.ssl_target_name_override', 'grpc-gateway',),)
    channel = grpc.secure_channel(GRPC_HOST, ssl_creds, options=options)
    stub = telemetry_pb2_grpc.TelemetryGatewayStub(channel)

    t_handshake_start = time.perf_counter()

    def event_stream():
        for i in range(event_count):
            yield telemetry_pb2.AgentEvent(
                agent_id=credentials["agent_id"],
                tenant_id=str(credentials["tenant_id"]),
                event_type="SecurityTelemetry",
                payload=json.dumps({"seq": i, "mtls_migrated": True, "ts": datetime.datetime.utcnow().isoformat()}),
                timestamp=datetime.datetime.utcnow().isoformat()
            )

    resp = stub.StreamEvents(event_stream(), timeout=10.0)
    t_end = time.perf_counter()

    channel.close()

    handshake_latency_ms = (t_end - t_handshake_start) * 1000
    return {
        "success": resp.success,
        "events_processed": resp.events_processed,
        "handshake_latency_ms": round(handshake_latency_ms, 2),
        "total_time_ms": round((t_end - t_start) * 1000, 2)
    }

async def run_fleet_migration():
    print("################################################################################")
    print("      MONITORIX PHASE 1D: CONTROLLED FLEET-WIDE mTLS MIGRATION ENGINE           ")
    print("################################################################################")

    # --------------------------------------------------------------------------
    # STEP 1: Query All Eligible Agents
    # --------------------------------------------------------------------------
    async with AsyncSessionLocal() as db:
        res = await db.execute(
            select(Agent).where(
                or_(
                    Agent.Status != "DECOMMISSIONED",
                    Agent.Status == None
                )
            ).order_by(Agent.TenantId, Agent.AgentId)
        )
        eligible_agents = res.scalars().all()

        # Check existing active certificates
        cert_res = await db.execute(
            select(DeviceCertificate).where(DeviceCertificate.Status == "ACTIVE")
        )
        active_certs = cert_res.scalars().all()
        active_cert_map = {c.AgentId: c for c in active_certs}

    print(f"[*] Total Eligible Agents in Fleet: {len(eligible_agents)}")
    print(f"[*] Agents with existing active certificates: {len(active_cert_map)}")

    unmigrated = [a for a in eligible_agents if a.AgentId not in active_cert_map]
    print(f"[*] Agents requiring mTLS Migration: {len(unmigrated)}")

    # --------------------------------------------------------------------------
    # STAGE A-D: Single Dedicated Pilot Agent Migration
    # --------------------------------------------------------------------------
    log_stage("STAGE A-D", "Dedicated Single Pilot Agent Migration & Telemetry Ingestion")
    pilot_target = unmigrated[0]
    print(f"[*] Selected Pilot Target: {pilot_target.AgentId} (Tenant: {pilot_target.TenantId}, Host: {pilot_target.Hostname})")
    
    t0 = time.perf_counter()
    pilot_creds = await enroll_agent_mtls(pilot_target.AgentId, pilot_target.TenantId)
    t_enroll = (time.perf_counter() - t0) * 1000
    print(f"  [+] Enrolled Pilot: Serial={pilot_creds['serial_number'][:16]}... in {t_enroll:.2f}ms")

    pilot_stream_res = verify_agent_mtls_stream(pilot_creds, event_count=3)
    assert pilot_stream_res["success"], "Pilot stream failed!"
    print(f"  [+] mTLS Telemetry Verified: {pilot_stream_res['events_processed']} events streamed (Handshake: {pilot_stream_res['handshake_latency_ms']}ms)")
    print("  [✓] STAGE A-D COMPLETE: Pilot agent successfully migrated.")

    # --------------------------------------------------------------------------
    # STAGE E-F: 10% Canary Group Migration
    # --------------------------------------------------------------------------
    log_stage("STAGE E-F", "10% Canary Fleet Group Migration & Health Monitoring")
    remaining_unmigrated = [a for a in unmigrated if a.AgentId != pilot_target.AgentId]
    canary_size = max(1, int(len(eligible_agents) * 0.10)) # 10% of total fleet
    canary_agents = remaining_unmigrated[:canary_size]

    print(f"[*] Selected Canary Group ({len(canary_agents)} agents): {[a.AgentId for a in canary_agents]}")
    canary_results = []

    for agent in canary_agents:
        t_c0 = time.perf_counter()
        creds = await enroll_agent_mtls(agent.AgentId, agent.TenantId)
        stream_res = verify_agent_mtls_stream(creds, event_count=2)
        elapsed = (time.perf_counter() - t_c0) * 1000
        assert stream_res["success"], f"Canary agent {agent.AgentId} failed!"
        canary_results.append({
            "agent_id": agent.AgentId,
            "tenant_id": agent.TenantId,
            "handshake_ms": stream_res["handshake_latency_ms"],
            "total_ms": elapsed
        })
        print(f"  [+] Canary Agent {agent.AgentId} (Tenant {agent.TenantId}) migrated & verified ({stream_res['handshake_latency_ms']}ms)")

    avg_canary_handshake = sum(c["handshake_ms"] for c in canary_results) / len(canary_results)
    print(f"  [✓] STAGE E-F COMPLETE: 10% Canary Group verified. Average mTLS Handshake: {avg_canary_handshake:.2f}ms")

    # --------------------------------------------------------------------------
    # STAGE G: Batch Migration of Remaining Fleet Agents
    # --------------------------------------------------------------------------
    log_stage("STAGE G", "Controlled Batch Migration of Remaining Fleet Agents")
    remaining_fleet = remaining_unmigrated[canary_size:]
    print(f"[*] Remaining Fleet to Migrate: {len(remaining_fleet)} agents in controlled batches")

    batch_size = 15
    batches = [remaining_fleet[i:i + batch_size] for i in range(0, len(remaining_fleet), batch_size)]
    batch_results = []

    for b_idx, batch in enumerate(batches, start=1):
        print(f"\n--- Migrating Batch {b_idx}/{len(batches)} ({len(batch)} agents) ---")
        for agent in batch:
            try:
                creds = await enroll_agent_mtls(agent.AgentId, agent.TenantId)
                stream_res = verify_agent_mtls_stream(creds, event_count=2)
                assert stream_res["success"]
                batch_results.append({
                    "agent_id": agent.AgentId,
                    "tenant_id": agent.TenantId,
                    "status": "MIGRATED",
                    "handshake_ms": stream_res["handshake_latency_ms"]
                })
                print(f"  [✓] Batch {b_idx}: Agent {agent.AgentId:<28} (Tenant {agent.TenantId:>2}) -> mTLS Active ({stream_res['handshake_latency_ms']}ms)")
            except Exception as e:
                print(f"  [✗] Batch {b_idx}: FAILED for {agent.AgentId}: {e}")
                batch_results.append({
                    "agent_id": agent.AgentId,
                    "tenant_id": agent.TenantId,
                    "status": "FAILED",
                    "error": str(e)
                })

    # --------------------------------------------------------------------------
    # STAGE H: Authoritative Database Verification & Fleet Audit
    # --------------------------------------------------------------------------
    log_stage("STAGE H", "Authoritative Database Fleet Audit & Plaintext Elimination Verification")
    async with AsyncSessionLocal() as db:
        final_agents_res = await db.execute(
            select(Agent).where(
                or_(
                    Agent.Status != "DECOMMISSIONED",
                    Agent.Status == None
                )
            )
        )
        all_active_agents = final_agents_res.scalars().all()

        final_certs_res = await db.execute(
            select(DeviceCertificate).where(DeviceCertificate.Status == "ACTIVE")
        )
        all_active_certs = final_certs_res.scalars().all()
        cert_lookup = {c.AgentId: c for c in all_active_certs}

        mtls_enforced_count = sum(1 for a in all_active_agents if a.RequireMtls)
        has_active_cert_count = sum(1 for a in all_active_agents if a.AgentId in cert_lookup)
        plaintext_dependent_count = sum(1 for a in all_active_agents if not a.RequireMtls or a.AgentId not in cert_lookup)

    print(f"[*] Total Active/Eligible Fleet Agents:      {len(all_active_agents)}")
    print(f"[*] Agents with RequireMtls = TRUE:          {mtls_enforced_count}/{len(all_active_agents)}")
    print(f"[*] Agents with ACTIVE DeviceCertificate:    {has_active_cert_count}/{len(all_active_agents)}")
    print(f"[*] Plaintext gRPC Dependent Agents:         {plaintext_dependent_count} (Must be 0)")

    assert plaintext_dependent_count == 0, f"Critical: {plaintext_dependent_count} agents remain unmigrated!"
    print("\n" + "=" * 80)
    print("      ALL ELIGIBLE MONITORIX AGENTS SUCCESSFULLY MIGRATED TO STRICT mTLS!      ")
    print("=" * 80)
    print("100% Cryptographic Identity. Zero Plaintext Ingestion. Full Fleet Hardened.")

    # Return performance metrics summary
    all_handshakes = [c["handshake_ms"] for c in canary_results] + [b["handshake_ms"] for b in batch_results if b["status"] == "MIGRATED"]
    return {
        "total_migrated": len(eligible_agents),
        "canary_count": len(canary_agents),
        "batch_count": len(batch_results),
        "avg_handshake_ms": round(sum(all_handshakes) / len(all_handshakes), 2),
        "min_handshake_ms": round(min(all_handshakes), 2),
        "max_handshake_ms": round(max(all_handshakes), 2),
    }

if __name__ == '__main__':
    import asyncio
    metrics = asyncio.run(run_fleet_migration())
    print("\n[Performance Metrics Summary]:", json.dumps(metrics, indent=2))

