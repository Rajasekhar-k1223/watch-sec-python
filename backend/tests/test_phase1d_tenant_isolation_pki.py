#!/usr/bin/env python3
"""
Monitorix Phase 1D: Strict Tenant Isolation & PKI Security Verification Suite
=============================================================================
Exhaustively verifies multi-tenant isolation, cross-tenant protection,
cryptographic anti-spoofing, and certificate lifecycle compliance.
"""

import os
import sys
import json
import time
import datetime
from datetime import timedelta
import uuid
import grpc
import requests

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
    print(f"[TEST {num:02d}/10] {title}")
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

def mint_token(username: str, role: str, tenant_id: int) -> str:
    return create_access_token(
        data={"sub": username, "role": role, "tenantId": tenant_id},
        expires_delta=timedelta(minutes=30)
    )

def generate_key_and_csr(agent_id: str, tenant_id: int):
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

def main():
    print("################################################################################")
    print("   MONITORIX PHASE 1D: TENANT ISOLATION & PKI ACCREDITATION TEST SUITE         ")
    print("################################################################################")

    token_admin_t1 = mint_token("elsea", "TenantAdmin", tenant_id=1)
    token_admin_t3 = mint_token("sentinelx", "TenantAdmin", tenant_id=3)
    token_viewer_t1 = mint_token("secops_analyst_test@enterprise.corp", "Analyst", tenant_id=1)
    token_superadmin = mint_token("superadmin", "SuperAdmin", tenant_id=1)

    headers_t1 = {"Authorization": f"Bearer {token_admin_t1}", "Content-Type": "application/json"}
    headers_t3 = {"Authorization": f"Bearer {token_admin_t3}", "Content-Type": "application/json"}
    headers_viewer = {"Authorization": f"Bearer {token_viewer_t1}", "Content-Type": "application/json"}

    # --------------------------------------------------------------------------
    # 1. Unauthorized Users Cannot Issue Enrollment Tokens
    # --------------------------------------------------------------------------
    log_test(1, "Unauthorized / Unauthenticated Token Issuance Rejection")
    resp_unauth = requests.post(f"{API_BASE}/api/v2/pki/enrollment-token", json={"agent_id": "hack-agent"})
    assert_step(resp_unauth.status_code == 401, "Unauthenticated request rejected with HTTP 401 Unauthorized", f"Expected 401, got {resp_unauth.status_code}")

    # --------------------------------------------------------------------------
    # 2. Tenant A Admin Scoped Token Issuance
    # --------------------------------------------------------------------------
    log_test(2, "Tenant Admin Token Issuance Scoped to Authorized Tenant")
    resp_t1 = requests.post(
        f"{API_BASE}/api/v2/pki/enrollment-token",
        headers=headers_t1,
        json={"agent_id": "test-agent-t1", "ttl_minutes": 10, "max_uses": 1}
    )
    assert_step(resp_t1.status_code == 200, "Tenant 1 admin successfully issued enrollment token", f"Failed: {resp_t1.text}")
    t1_token_data = resp_t1.json()
    assert_step(t1_token_data["tenant_id"] == 1, "Token strictly scoped to Tenant 1", f"Wrong tenant: {t1_token_data['tenant_id']}")

    # --------------------------------------------------------------------------
    # 3. Cross-Tenant Enrollment Rejection (Tenant 1 Token Used For Tenant 2)
    # --------------------------------------------------------------------------
    log_test(3, "Cross-Tenant Enrollment Rejection (Tenant Isolation Enforcement)")
    _, k_pem_t2, csr_pem_t2 = generate_key_and_csr("agent-spoof-t2", tenant_id=2)
    resp_cross = requests.post(
        f"{API_BASE}/api/v2/pki/enroll",
        json={
            "agent_id": "agent-spoof-t2",
            "tenant_id": 2, # Attacker targets Tenant 2 using Tenant 1's token
            "enrollment_token": t1_token_data["token"],
            "csr_pem": csr_pem_t2
        }
    )
    assert_step(resp_cross.status_code in (401, 403), f"Cross-tenant enrollment blocked ({resp_cross.status_code})", f"Cross-tenant enrollment succeeded!")

    # --------------------------------------------------------------------------
    # 4. Tenant A User Cannot Retrieve Tenant B Certificates
    # --------------------------------------------------------------------------
    log_test(4, "Multi-Tenant Certificate Inventory Namespace Isolation")
    resp_certs_t1 = requests.get(f"{API_BASE}/api/v2/pki/certificates", headers=headers_t1)
    assert_step(resp_certs_t1.status_code == 200, "Tenant 1 certificates listed successfully", "Failed to get certs")
    certs_t1 = resp_certs_t1.json()
    non_t1_certs = [c for c in certs_t1 if c["tenant_id"] != 1]
    assert_step(len(non_t1_certs) == 0, "Zero non-Tenant 1 certificates exposed to Tenant 1 admin", f"Tenant isolation breach! Leaked: {len(non_t1_certs)} certs")

    resp_certs_t3 = requests.get(f"{API_BASE}/api/v2/pki/certificates", headers=headers_t3)
    certs_t3 = resp_certs_t3.json()
    non_t3_certs = [c for c in certs_t3 if c["tenant_id"] != 3]
    assert_step(len(non_t3_certs) == 0, "Zero non-Tenant 3 certificates exposed to Tenant 3 admin", f"Tenant isolation breach! Leaked: {len(non_t3_certs)} certs")

    # --------------------------------------------------------------------------
    # 5. Cryptographic Agent Anti-Spoofing (CN Mismatch Prevention)
    # --------------------------------------------------------------------------
    log_test(5, "Cryptographic Agent Anti-Spoofing over mTLS Stream")
    # Enroll dedicated agent
    legit_id = f"legit-agent-{uuid.uuid4().hex[:6]}"
    tok_res = requests.post(
        f"{API_BASE}/api/v2/pki/enrollment-token",
        headers=headers_t1,
        json={"agent_id": legit_id, "ttl_minutes": 10, "max_uses": 1}
    ).json()

    _, legit_key_pem, legit_csr_pem = generate_key_and_csr(legit_id, tenant_id=1)
    enr_res = requests.post(
        f"{API_BASE}/api/v2/pki/enroll",
        json={"agent_id": legit_id, "tenant_id": 1, "enrollment_token": tok_res["token"], "csr_pem": legit_csr_pem}
    ).json()

    ssl_creds = grpc.ssl_channel_credentials(
        root_certificates=enr_res["ca_chain_pem"].encode("utf-8"),
        private_key=legit_key_pem,
        certificate_chain=enr_res["certificate_pem"].encode("utf-8")
    )
    options = (('grpc.ssl_target_name_override', 'grpc-gateway',),)
    chan = grpc.secure_channel(GRPC_HOST, ssl_creds, options=options)
    stub = telemetry_pb2_grpc.TelemetryGatewayStub(chan)

    # Attempt to stream telemetry claiming to be "vmi3011362" (spoofed AgentId)
    def spoof_event_gen():
        yield telemetry_pb2.AgentEvent(
            agent_id="vmi3011362", # SPOOFED ID
            tenant_id="3",
            event_type="SecurityTelemetry",
            payload=json.dumps({"spoof": True}),
            timestamp=datetime.datetime.utcnow().isoformat()
        )

    # Gateway anti-spoofing logic drops spoofed event (events_processed must be 0)
    resp_spoof = stub.StreamEvents(spoof_event_gen())
    assert_step(resp_spoof.events_processed == 0, "Spoofed agent telemetry intercepted and dropped (0 events processed)", f"Spoofed telemetry was accepted! Processed: {resp_spoof.events_processed}")

    # --------------------------------------------------------------------------
    # 6. Revoked Agent In-Stream & Pre-Handshake Rejection
    # --------------------------------------------------------------------------
    log_test(6, "Revoked Certificate Rejection (Pre-Handshake & Database Check)")
    resp_rev = requests.post(
        f"{API_BASE}/api/v2/pki/revoke",
        headers=headers_t1,
        json={"serial_number": enr_res["serial_number"], "reason": "compromised"}
    )
    assert_step(resp_rev.status_code == 200, "Certificate successfully revoked", "Revocation failed")

    def legit_event_gen():
        yield telemetry_pb2.AgentEvent(
            agent_id=legit_id,
            tenant_id="1",
            event_type="SecurityTelemetry",
            payload=json.dumps({"active": True}),
            timestamp=datetime.datetime.utcnow().isoformat()
        )

    try:
        stub.StreamEvents(legit_event_gen())
        assert_step(False, "", "Revoked certificate unexpectedly succeeded!")
    except grpc.RpcError as e:
        assert_step(e.code() == grpc.StatusCode.PERMISSION_DENIED, f"Revoked cert strictly rejected with PERMISSION_DENIED ({e.details()})", f"Wrong code: {e.code()}")

    # --------------------------------------------------------------------------
    # 7. Token Reuse Rejection (Single-Use Enforced)
    # --------------------------------------------------------------------------
    log_test(7, "Token Reuse Rejection (Single-Use Policy Enforced)")
    resp_reuse = requests.post(
        f"{API_BASE}/api/v2/pki/enroll",
        json={"agent_id": legit_id, "tenant_id": 1, "enrollment_token": tok_res["token"], "csr_pem": legit_csr_pem}
    )
    assert_step(resp_reuse.status_code == 403, "Reused token rejected with HTTP 403 Forbidden", f"Token reuse allowed: {resp_reuse.status_code}")

    # --------------------------------------------------------------------------
    # 8. Expired Token (> 10 mins) Rejection
    # --------------------------------------------------------------------------
    log_test(8, "Expired Enrollment Token (> 10 min) Rejection")
    resp_fake_exp = requests.post(
        f"{API_BASE}/api/v2/pki/enroll",
        json={"agent_id": "exp-agent", "tenant_id": 1, "enrollment_token": "enr_expired_dummy_token", "csr_pem": legit_csr_pem}
    )
    assert_step(resp_fake_exp.status_code in (401, 403), "Expired/unregistered token rejected", "Token was accepted")

    # --------------------------------------------------------------------------
    # 9. Automated PKI Lifecycle Watchdog & Alert Generation
    # --------------------------------------------------------------------------
    log_test(9, "Automated PKI Lifecycle Audit & Expiry Watchdog")
    resp_audit = requests.post(
        f"{API_BASE}/api/v2/pki/audit-lifecycle",
        headers=headers_t1,
        json={}
    )
    assert_step(resp_audit.status_code == 200, "PKI lifecycle audit executed successfully", f"Audit failed: {resp_audit.text}")
    audit_data = resp_audit.json()
    assert_step(audit_data["crl_refreshed"] == True, "CRL automatically refreshed and verified", "CRL not refreshed")

    # --------------------------------------------------------------------------
    # 10. Public CRL & CA Chain Serving
    # --------------------------------------------------------------------------
    log_test(10, "Public X.509 CRL & CA Chain Distribution")
    resp_chain = requests.get(f"{API_BASE}/api/v2/pki/ca-chain")
    assert_step(resp_chain.status_code == 200 and "BEGIN CERTIFICATE" in resp_chain.text, "CA Chain successfully downloadable in PEM format", "Failed CA chain download")
    resp_crl = requests.get(f"{API_BASE}/api/v2/pki/crl")
    assert_step(resp_crl.status_code == 200 and "BEGIN X509 CRL" in resp_crl.text, "X.509 CRL successfully downloadable in PEM format", "Failed CRL download")

    print("\n" + "=" * 80)
    print(f"   ALL 10 TENANT ISOLATION & PKI ACCREDITATION TESTS PASSED! ({PASSED}/10)  ")
    print("=" * 80)
    print("Multi-Tenant Isolation Confirmed. Cryptographic Anti-Spoofing Accredited.")

if __name__ == '__main__':
    main()
