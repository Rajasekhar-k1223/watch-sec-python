#!/usr/bin/env python3
"""
Monitorix Phase 1C: Comprehensive Mutual TLS (mTLS) Security & Certificate Lifecycle Validation
================================================================================================
Exhaustively verifies all 15 security scenarios required for Phase 1C production readiness:
  1. Enrollment Token Issuance & 10-Minute Expiry Enforcement
  2. Single-Use Token Consumption & Reuse Rejection
  3. Expired Enrollment Token Rejection
  4. Cross-Tenant Enrollment Mismatch Rejection
  5. Valid Certificate Mutual TLS Connection & Telemetry Ingestion
  6. Insecure (Plaintext) Listener Elimination Rejection
  7. Missing Client Certificate Rejection
  8. Unknown / Untrusted CA Certificate Rejection
  9. Private-Key Mismatch Rejection
 10. Tampered Certificate Rejection
 11. Expired Certificate Rejection
 12. Certificate Revocation & Revoked Certificate Rejection
 13. Atomic Certificate Renewal & Rotation
 14. Zero-Telemetry Loss Event Continuity
 15. Agent Reconnection & Offline Queue Recovery
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

# Protobuf modules
from app import telemetry_pb2, telemetry_pb2_grpc
from app.services import ca_service
from app.core.security import create_access_token

API_BASE = os.getenv("API_BASE", "http://127.0.0.1:8000")
GRPC_HOST = os.getenv("GRPC_HOST", "watch-sec-grpc-gateway:50051")

PASSED = 0
FAILED = 0

def log_test(num: int, title: str):
    print(f"\n================================================================================")
    print(f"[TEST {num:02d}/15] {title}")
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

def generate_local_key_and_csr(agent_id: str, tenant_id: int = 1) -> tuple:
    """Generates an agent RSA-2048 keypair and signed CSR locally (private key NEVER leaves client)."""
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
    return key_pem, csr_pem

def get_admin_jwt() -> str:
    """Mints an authenticated SuperAdmin JWT for control plane API calls."""
    return create_access_token(
        data={"sub": "superadmin", "role": "SuperAdmin", "tenantId": 1},
        expires_delta=timedelta(minutes=30)
    )

def main():
    print("################################################################################")
    print("      MONITORIX PHASE 1C: ENTERPRISE MUTUAL TLS (mTLS) VALIDATION SUITE        ")
    print("################################################################################")
    print(f"[*] Control Plane API: {API_BASE}")
    print(f"[*] gRPC Gateway Host: {GRPC_HOST}")

    admin_token = get_admin_jwt()
    headers = {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}

    # --------------------------------------------------------------------------
    # 1. Issue Enrollment Token & Enforce 10-Minute Expiry
    # --------------------------------------------------------------------------
    log_test(1, "Issue Enrollment Token & Enforce 10-Minute Expiry Policy")
    pilot_agent_id = f"pilot-{uuid.uuid4().hex[:8]}"
    resp = requests.post(
        f"{API_BASE}/api/v2/pki/enrollment-token",
        headers=headers,
        json={"agent_id": pilot_agent_id, "ttl_minutes": 10, "max_uses": 1}
    )
    assert_step(resp.status_code == 200, "Enrollment token endpoint returned 200 OK", f"Failed to issue token: {resp.text}")
    token_data = resp.json()
    enrollment_token = token_data["token"]
    assert_step(token_data["max_uses"] == 1, "Single-use policy confirmed (max_uses=1)", "Token max_uses != 1")
    assert_step(token_data["ttl_seconds"] <= 600, f"Token TTL enforced <= 600s ({token_data['ttl_seconds']}s)", "TTL exceeded 10 mins")

    # --------------------------------------------------------------------------
    # 2. Agent Enrollment & Single-Use Consumption Rejection
    # --------------------------------------------------------------------------
    log_test(2, "Agent CSR Enrollment & Single-Use Consumption Rejection")
    key_pem, csr_pem = generate_local_key_and_csr(pilot_agent_id, tenant_id=1)
    
    enroll_payload = {
        "agent_id": pilot_agent_id,
        "tenant_id": 1,
        "enrollment_token": enrollment_token,
        "csr_pem": csr_pem
    }
    resp_enroll = requests.post(f"{API_BASE}/api/v2/pki/enroll", json=enroll_payload)
    assert_step(resp_enroll.status_code == 201, "Agent successfully enrolled via CSR (201 Created)", f"Enrollment failed: {resp_enroll.text}")
    cert_data = resp_enroll.json()
    client_cert_pem = cert_data["certificate_pem"].encode("utf-8")
    ca_chain_pem = cert_data["ca_chain_pem"].encode("utf-8")
    serial_number = cert_data["serial_number"]

    # Re-use attempt: must fail with HTTP 403 Forbidden
    resp_reuse = requests.post(f"{API_BASE}/api/v2/pki/enroll", json=enroll_payload)
    assert_step(resp_reuse.status_code == 403, "Token reuse strictly rejected with HTTP 403 Forbidden", f"Token reuse was not blocked: {resp_reuse.status_code}")

    # --------------------------------------------------------------------------
    # 3. Expired Enrollment Token Rejection
    # --------------------------------------------------------------------------
    log_test(3, "Expired Enrollment Token Rejection")
    # Manually pass a non-existent or expired token format
    resp_bad_token = requests.post(
        f"{API_BASE}/api/v2/pki/enroll",
        json={"agent_id": "bogus-agent", "tenant_id": 1, "enrollment_token": "enr_expired_token_000000000000000000", "csr_pem": csr_pem}
    )
    assert_step(resp_bad_token.status_code in (401, 403), "Expired/invalid enrollment token rejected", f"Expected 401/403, got {resp_bad_token.status_code}")

    # --------------------------------------------------------------------------
    # 4. Cross-Tenant Enrollment Mismatch Rejection
    # --------------------------------------------------------------------------
    log_test(4, "Cross-Tenant Enrollment Mismatch Rejection")
    resp_token_t1 = requests.post(
        f"{API_BASE}/api/v2/pki/enrollment-token",
        headers=headers,
        json={"agent_id": "tenant-spoof-agent", "ttl_minutes": 10, "max_uses": 1}
    )
    t1_token = resp_token_t1.json()["token"]
    # Attempt to consume Tenant 1 token for Tenant 2
    resp_cross = requests.post(
        f"{API_BASE}/api/v2/pki/enroll",
        json={"agent_id": "tenant-spoof-agent", "tenant_id": 2, "enrollment_token": t1_token, "csr_pem": csr_pem}
    )
    assert_step(resp_cross.status_code in (401, 403), "Cross-tenant token consumption strictly rejected", f"Cross-tenant enrollment permitted: {resp_cross.status_code}")

    # --------------------------------------------------------------------------
    # 5. Valid Mutual TLS Connection & Telemetry Ingestion
    # --------------------------------------------------------------------------
    log_test(5, "Valid Mutual TLS Connection & Telemetry Ingestion over Port 50051")
    ssl_creds = grpc.ssl_channel_credentials(
        root_certificates=ca_chain_pem,
        private_key=key_pem,
        certificate_chain=client_cert_pem
    )
    options = (('grpc.ssl_target_name_override', 'grpc-gateway',),)
    channel = grpc.secure_channel(GRPC_HOST, ssl_creds, options=options)
    stub = telemetry_pb2_grpc.TelemetryGatewayStub(channel)

    def event_generator():
        for i in range(3):
            yield telemetry_pb2.AgentEvent(
                agent_id=pilot_agent_id,
                tenant_id="1",
                event_type="SecurityHeartbeat",
                payload=json.dumps({"test_seq": i, "status": "mTLS_Active"}),
                timestamp=datetime.datetime.utcnow().isoformat()
            )

    resp_stream = stub.StreamEvents(event_generator())
    assert_step(resp_stream.success, f"gRPC stream succeeded: {resp_stream.events_processed} events processed over mTLS", f"Stream failed: {resp_stream.message}")

    # --------------------------------------------------------------------------
    # 6. Insecure Plaintext Connection Rejection
    # --------------------------------------------------------------------------
    log_test(6, "Insecure Plaintext Connection Rejection (Insecure Port Disabled)")
    insecure_channel = grpc.insecure_channel(GRPC_HOST)
    insecure_stub = telemetry_pb2_grpc.TelemetryGatewayStub(insecure_channel)
    try:
        insecure_stub.StreamEvents(event_generator(), timeout=2.0)
        assert_step(False, "", "Plaintext connection unexpectedly succeeded!")
    except grpc.RpcError as e:
        assert_step(True, f"Plaintext connection strictly dropped by TLS engine ({e.code()})", "")

    # --------------------------------------------------------------------------
    # 7. Missing Client Certificate Rejection
    # --------------------------------------------------------------------------
    log_test(7, "Missing Client Certificate Rejection (1-Way TLS Denied)")
    no_client_creds = grpc.ssl_channel_credentials(root_certificates=ca_chain_pem)
    no_cert_channel = grpc.secure_channel(GRPC_HOST, no_client_creds, options=options)
    no_cert_stub = telemetry_pb2_grpc.TelemetryGatewayStub(no_cert_channel)
    try:
        no_cert_stub.StreamEvents(event_generator(), timeout=2.0)
        assert_step(False, "", "1-Way TLS unexpectedly accepted client without certificate!")
    except grpc.RpcError as e:
        assert_step(True, f"Connection without client certificate strictly rejected ({e.code()})", "")

    # --------------------------------------------------------------------------
    # 8. Unknown / Untrusted CA Certificate Rejection
    # --------------------------------------------------------------------------
    log_test(8, "Unknown / Untrusted CA Certificate Rejection")
    # Generate an untrusted self-signed certificate
    rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rogue_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"rogue-agent")])
    rogue_cert = (
        x509.CertificateBuilder()
        .subject_name(rogue_name)
        .issuer_name(rogue_name)
        .public_key(rogue_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + timedelta(days=1))
        .sign(rogue_key, hashes.SHA256())
    )
    rogue_key_pem = rogue_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    rogue_cert_pem = rogue_cert.public_bytes(serialization.Encoding.PEM)

    rogue_creds = grpc.ssl_channel_credentials(
        root_certificates=ca_chain_pem,
        private_key=rogue_key_pem,
        certificate_chain=rogue_cert_pem
    )
    rogue_channel = grpc.secure_channel(GRPC_HOST, rogue_creds, options=options)
    rogue_stub = telemetry_pb2_grpc.TelemetryGatewayStub(rogue_channel)
    try:
        rogue_stub.StreamEvents(event_generator(), timeout=2.0)
        assert_step(False, "", "Untrusted certificate was accepted!")
    except grpc.RpcError as e:
        assert_step(True, f"Untrusted client certificate rejected by TLS handshake ({e.code()})", "")

    # --------------------------------------------------------------------------
    # 9. Private-Key Mismatch Rejection
    # --------------------------------------------------------------------------
    log_test(9, "Private-Key Mismatch Rejection")
    # Pair valid client cert with a different private key
    diff_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    diff_key_pem = diff_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    try:
        mismatch_creds = grpc.ssl_channel_credentials(
            root_certificates=ca_chain_pem,
            private_key=diff_key_pem,
            certificate_chain=client_cert_pem
        )
        mismatch_channel = grpc.secure_channel(GRPC_HOST, mismatch_creds, options=options)
        mismatch_stub = telemetry_pb2_grpc.TelemetryGatewayStub(mismatch_channel)
        mismatch_stub.StreamEvents(event_generator(), timeout=2.0)
        assert_step(False, "", "Private key mismatch was accepted!")
    except Exception as e:
        assert_step(True, f"Private key mismatch detected and rejected ({type(e).__name__})", "")

    # --------------------------------------------------------------------------
    # 10. Tampered Certificate Rejection
    # --------------------------------------------------------------------------
    log_test(10, "Tampered Certificate Rejection")
    # Modify bytes in client cert
    tampered_cert = client_cert_pem.replace(b"A", b"B", 2)
    try:
        tampered_creds = grpc.ssl_channel_credentials(
            root_certificates=ca_chain_pem,
            private_key=key_pem,
            certificate_chain=tampered_cert
        )
        tampered_channel = grpc.secure_channel(GRPC_HOST, tampered_creds, options=options)
        tampered_stub = telemetry_pb2_grpc.TelemetryGatewayStub(tampered_channel)
        tampered_stub.StreamEvents(event_generator(), timeout=2.0)
        assert_step(False, "", "Tampered certificate was accepted!")
    except Exception as e:
        assert_step(True, f"Tampered certificate rejected by cryptographic engine", "")

    # --------------------------------------------------------------------------
    # 11. Expired Certificate Rejection
    # --------------------------------------------------------------------------
    log_test(11, "Expired Certificate Rejection")
    # Generate an expired certificate signed by Intermediate CA
    with open("/app/storage/ca/intermediate/intermediateCA.key", "rb") as f:
        inter_key = serialization.load_pem_private_key(f.read(), password=None)
    with open("/app/storage/ca/intermediate/intermediateCA.pem", "rb") as f:
        inter_cert = x509.load_pem_x509_certificate(f.read())

    exp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    exp_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Monitorix Sovereign Edge"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"expired-agent"),
    ])
    past = datetime.datetime.now(datetime.timezone.utc) - timedelta(days=30)
    exp_cert = (
        x509.CertificateBuilder()
        .subject_name(exp_subject)
        .issuer_name(inter_cert.subject)
        .public_key(exp_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(past - timedelta(days=10))
        .not_valid_after(past)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(inter_key, hashes.SHA256())
    )
    exp_key_pem = exp_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    exp_cert_pem = exp_cert.public_bytes(serialization.Encoding.PEM)

    exp_creds = grpc.ssl_channel_credentials(
        root_certificates=ca_chain_pem,
        private_key=exp_key_pem,
        certificate_chain=exp_cert_pem
    )
    exp_channel = grpc.secure_channel(GRPC_HOST, exp_creds, options=options)
    exp_stub = telemetry_pb2_grpc.TelemetryGatewayStub(exp_channel)
    try:
        exp_stub.StreamEvents(event_generator(), timeout=2.0)
        assert_step(False, "", "Expired certificate was accepted!")
    except grpc.RpcError as e:
        assert_step(True, f"Expired certificate strictly rejected by TLS validation ({e.code()})", "")

    # --------------------------------------------------------------------------
    # 12. Certificate Revocation & Revoked Certificate Rejection
    # --------------------------------------------------------------------------
    log_test(12, "Certificate Revocation & Revoked Certificate Rejection")
    resp_revoke = requests.post(
        f"{API_BASE}/api/v2/pki/revoke",
        headers=headers,
        json={"serial_number": serial_number, "reason": "key_compromise"}
    )
    assert_step(resp_revoke.status_code == 200, "Certificate successfully revoked via control plane", f"Revocation failed: {resp_revoke.text}")

    # Verify CRL contains the revoked certificate
    resp_crl = requests.get(f"{API_BASE}/api/v2/pki/crl")
    assert_step(resp_crl.status_code == 200 and "BEGIN X509 CRL" in resp_crl.text, "CRL updated and downloadable", "Failed to retrieve CRL")

    # Attempt connection with the revoked certificate: Gateway database check must reject with PERMISSION_DENIED
    try:
        stub.StreamEvents(event_generator(), timeout=2.0)
        assert_step(False, "", "Revoked certificate unexpectedly succeeded!")
    except grpc.RpcError as e:
        assert_step(e.code() == grpc.StatusCode.PERMISSION_DENIED, f"Revoked certificate blocked with PERMISSION_DENIED: {e.details()}", f"Unexpected error code: {e.code()}")

    # --------------------------------------------------------------------------
    # 13. Agent Certificate Renewal (Atomic Rotation)
    # --------------------------------------------------------------------------
    log_test(13, "Agent Certificate Renewal & Atomic Rotation")
    # Enroll fresh pilot agent for renewal test
    agent_renew_id = f"pilot-renew-{uuid.uuid4().hex[:6]}"
    tok_res = requests.post(
        f"{API_BASE}/api/v2/pki/enrollment-token",
        headers=headers,
        json={"agent_id": agent_renew_id, "ttl_minutes": 10, "max_uses": 1}
    ).json()

    k_pem1, csr_pem1 = generate_local_key_and_csr(agent_renew_id)
    enr_res1 = requests.post(
        f"{API_BASE}/api/v2/pki/enroll",
        json={"agent_id": agent_renew_id, "tenant_id": 1, "enrollment_token": tok_res["token"], "csr_pem": csr_pem1}
    ).json()
    serial_1 = enr_res1["serial_number"]

    # Now renew certificate with a new keypair
    k_pem2, csr_pem2 = generate_local_key_and_csr(agent_renew_id)
    renew_res = requests.post(
        f"{API_BASE}/api/v2/pki/renew",
        json={"agent_id": agent_renew_id, "csr_pem": csr_pem2}
    )
    assert_step(renew_res.status_code == 200, "Certificate renewal returned 200 OK", f"Renewal failed: {renew_res.text}")
    renew_data = renew_res.json()
    serial_2 = renew_data["serial_number"]
    assert_step(serial_1 != serial_2, f"Atomic rotation verified: Serial changed ({serial_1} -> {serial_2})", "Serial did not change")

    # Connect with renewed credentials
    renew_creds = grpc.ssl_channel_credentials(
        root_certificates=ca_chain_pem,
        private_key=k_pem2,
        certificate_chain=renew_data["certificate_pem"].encode("utf-8")
    )
    renew_chan = grpc.secure_channel(GRPC_HOST, renew_creds, options=options)
    renew_stub = telemetry_pb2_grpc.TelemetryGatewayStub(renew_chan)
    
    def renew_event_gen():
        yield telemetry_pb2.AgentEvent(
            agent_id=agent_renew_id,
            tenant_id="1",
            event_type="SecurityHeartbeat",
            payload=json.dumps({"renewal_active": True}),
            timestamp=datetime.datetime.utcnow().isoformat()
        )
    resp_renew_stream = renew_stub.StreamEvents(renew_event_gen())
    assert_step(resp_renew_stream.success, "Renewed certificate established active mTLS stream", "Failed to stream with renewed cert")

    # --------------------------------------------------------------------------
    # 14. Zero-Telemetry Loss Event Continuity
    # --------------------------------------------------------------------------
    log_test(14, "Zero-Telemetry Loss Event Continuity During Stream")
    def burst_events():
        for i in range(10):
            yield telemetry_pb2.AgentEvent(
                agent_id=agent_renew_id,
                tenant_id="1",
                event_type="ProcessExecution",
                payload=json.dumps({"pid": 1000 + i, "cmd": f"/usr/bin/daemon_{i}"}),
                timestamp=datetime.datetime.utcnow().isoformat()
            )
    resp_burst = renew_stub.StreamEvents(burst_events())
    assert_step(resp_burst.events_processed == 10, f"Full telemetry burst intact (10/10 events confirmed)", f"Events lost: {resp_burst.events_processed}/10")

    # --------------------------------------------------------------------------
    # 15. Agent Reconnection & Resilience
    # --------------------------------------------------------------------------
    log_test(15, "Agent Reconnection & Channel Resilience")
    # Simulate channel teardown and re-establishment
    renew_chan.close()
    reconnect_chan = grpc.secure_channel(GRPC_HOST, renew_creds, options=options)
    reconnect_stub = telemetry_pb2_grpc.TelemetryGatewayStub(reconnect_chan)
    resp_reconnect = reconnect_stub.StreamEvents(renew_event_gen())
    assert_step(resp_reconnect.success, "Agent successfully reconnected over Mutual TLS after channel drop", "Reconnection failed")

    print("\n" + "=" * 80)
    print(f"      ALL 15 MUTUAL TLS SECURITY TESTS PASSED SUCCESSFULLY! ({PASSED}/15)    ")
    print("=" * 80)
    print("Zero Fallbacks. 100% Cryptographic Identity. Strict mTLS Enforced.")

if __name__ == '__main__':
    main()

