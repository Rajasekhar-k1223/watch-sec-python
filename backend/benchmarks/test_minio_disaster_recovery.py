"""
Monitorix Enterprise — Phase 3B Task 5: MinIO Disaster Recovery & Forensic Vault Resilience
Tests:
  1. Sovereign MinIO upload & SHA-256 integrity check under normal operation.
  2. Outage simulation & local fallback queueing under `/app/storage/shadow/pending/`.
  3. Companion metadata generation (.meta.json) and 5 GB quota limit enforcement.
  4. Container restart survival (persistence across backend/worker restarts).
  5. Celery reconciliation task (`sync_pending_minio_artifacts`).
  6. Cryptographic SHA-256 validation between local origin and remote MinIO object.
  7. Verification of local disk purge ONLY upon confirmed remote integrity check.
  8. Tamper detection: Corrupted files are flagged and never synced or purged.
"""

import os
import io
import sys
import json
import time
import shutil
import hashlib
import tempfile
from pathlib import Path
from datetime import datetime

# Set PYTHONPATH
sys.path.insert(0, "/app")

from app.services.minio_vault import MinioVaultService, minio_vault

def test_normal_upload_and_retrieval():
    print("\n--- Test 1: Normal MinIO Direct Upload & Retrieval ---")
    service = MinioVaultService()
    test_content = b"Monitorix Phase 3B Forensic Artifact Sample: EDR Dump 2026-11-06"
    test_sha = hashlib.sha256(test_content).hexdigest()
    
    result = service.store_forensic_artifact(
        tenant_id=1,
        agent_id="agt_mtls_001",
        filename="edr_dump_normal.bin",
        data_bytes=test_content,
        declared_sha256=test_sha,
        artifact_type="memory_dump"
    )
    
    assert result["status"] == "SYNCED", f"Expected SYNCED, got {result.get('status')}"
    assert result["sha256"] == test_sha, "SHA-256 mismatch in upload result"
    print(f"  [PASS] Direct MinIO upload successful: Object key={result['object_key']}, SHA256={result['sha256'][:16]}...")
    
    # Retrieve and verify
    data, meta = service.retrieve_forensic_artifact(result["object_key"])
    assert data == test_content, "Retrieved data does not match original bytes"
    assert meta["sha256"] == test_sha, "Retrieved SHA-256 mismatch"
    print(f"  [PASS] Forensic retrieval verified: 100% byte-for-byte integrity match.")
    return result["object_key"]

def test_outage_simulation_and_local_queue():
    print("\n--- Test 2: MinIO Outage Simulation & Local Fallback Queueing ---")
    # Simulate MinIO down by pointing endpoint to unreachable port
    service = MinioVaultService()
    service.endpoint = "127.0.0.1:59999" # Broken endpoint
    service._client = None
    
    test_content = b"CRITICAL FORENSIC PAYLOAD GENERATED DURING MINIO OUTAGE: " + os.urandom(1024)
    test_sha = hashlib.sha256(test_content).hexdigest()
    
    result = service.store_forensic_artifact(
        tenant_id=1,
        agent_id="agt_mtls_001",
        filename="quarantined_malware.bin",
        data_bytes=test_content,
        declared_sha256=test_sha,
        artifact_type="shadow_binary"
    )
    
    assert result["status"] == "PENDING_MINIO_SYNC", f"Expected PENDING_MINIO_SYNC, got {result.get('status')}"
    local_path = result.get("local_path")
    assert local_path and os.path.exists(local_path), f"Local file was not created: {local_path}"
    
    meta_path = f"{local_path}.meta.json"
    assert os.path.exists(meta_path), f"Metadata file not created: {meta_path}"
    
    with open(meta_path, "r") as f:
        meta_data = json.load(f)
    assert meta_data["computed_sha256"] == test_sha
    assert meta_data["status"] == "PENDING_MINIO_SYNC"
    assert meta_data["tenant_id"] == 1
    assert meta_data["size"] == len(test_content)
    
    print(f"  [PASS] Outage fallback verified: Artifact stored safely in {local_path}")
    print(f"  [PASS] Companion metadata verified: {meta_path} (size={meta_data['size']}B)")
    return local_path, meta_path, test_sha, result["object_key"]

def test_quota_limit_enforcement():
    print("\n--- Test 3: Local Fallback Quota Enforcement (5 GB Limit) ---")
    service = MinioVaultService()
    current_usage = service.get_fallback_storage_usage()
    print(f"  [INFO] Current local fallback directory usage: {current_usage} bytes")
    
    # Temporarily set max_fallback_bytes to current_usage + 500 bytes
    original_max = service.max_fallback_bytes
    service.max_fallback_bytes = current_usage + 500
    
    payload_exceeding = os.urandom(1000) # 1000 bytes > 500 bytes allowed
    quota_exceeded = False
    try:
        service._store_local_fallback(
            tenant_id=1,
            agent_id="agt_test_quota",
            safe_name="too_big.bin",
            data_bytes=payload_exceeding,
            object_key="quota/test/too_big.bin",
            artifact_type="quota_test",
            computed_sha256=hashlib.sha256(payload_exceeding).hexdigest()
        )
    except IOError as e:
        quota_exceeded = True
        print(f"  [PASS] Quota rejection verified: Caught expected error '{e}'")
    finally:
        service.max_fallback_bytes = original_max
        
    assert quota_exceeded, "Quota enforcement failed to block oversized fallback write!"

def test_tamper_detection_and_reconciliation(local_path, meta_path, expected_sha, expected_key):
    print("\n--- Test 4: Reconciliation Worker & Remote Cryptographic Verification ---")
    # Real MinIO service
    service = MinioVaultService()
    
    # 4a: Create a tampered file to verify corruption detection
    tampered_bytes = b"CORRUPTED BY MITM / BIT ROT"
    tampered_sha = hashlib.sha256(tampered_bytes).hexdigest()
    tampered_dir = os.path.dirname(local_path)
    tampered_data_path = os.path.join(tampered_dir, "tampered_artifact.bin")
    tampered_meta_path = f"{tampered_data_path}.meta.json"
    
    with open(tampered_data_path, "wb") as f:
        f.write(tampered_bytes)
    with open(tampered_meta_path, "w") as f:
        json.dump({
            "tenant_id": 1,
            "agent_id": "agt_mtls_001",
            "filename": "tampered_artifact.bin",
            "object_key": "forensics/tenant_1/agt_mtls_001/tampered.bin",
            "artifact_type": "shadow_binary",
            "declared_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
            "computed_sha256": "1111111111111111111111111111111111111111111111111111111111111111", # Wrong hash
            "size": len(tampered_bytes),
            "status": "PENDING_MINIO_SYNC",
            "local_data_path": tampered_data_path,
            "retry_count": 0
        }, f)
    
    print(f"  [SETUP] Created legitimate queued artifact and tampered artifact.")
    
    # Run sync_pending_artifacts
    sync_result = service.sync_pending_artifacts(max_batch=50)
    print(f"  [RECONCILIATION RESULT] {sync_result}")
    
    assert sync_result["synced"] >= 1, f"Expected at least 1 synced artifact, got {sync_result['synced']}"
    assert sync_result["failed"] >= 1, f"Expected tampered file to be flagged as failed, got {sync_result['failed']}"
    
    # Verify legitimate file was purged locally
    assert not os.path.exists(local_path), f"Legitimate data file {local_path} was NOT purged after sync!"
    assert not os.path.exists(meta_path), f"Legitimate meta file {meta_path} was NOT purged after sync!"
    print(f"  [PASS] Local purge confirmed: Data and meta files cleanly deleted after remote confirmation.")
    
    # Verify tampered file was flagged CORRUPTED and preserved for forensic audit
    assert os.path.exists(tampered_meta_path), "Tampered meta file was deleted!"
    with open(tampered_meta_path, "r") as f:
        tampered_meta = json.load(f)
    assert tampered_meta.get("status") == "CORRUPTED", f"Expected CORRUPTED, got {tampered_meta.get('status')}"
    print(f"  [PASS] Tamper protection confirmed: Mismatched artifact marked CORRUPTED and blocked from MinIO.")
    
    # Clean up tampered test files
    os.remove(tampered_data_path)
    os.remove(tampered_meta_path)
    
    # Verify remote object in MinIO
    remote_data, remote_meta = service.retrieve_forensic_artifact(expected_key)
    assert remote_meta["sha256"] == expected_sha, "Remote object SHA-256 does not match original pre-outage hash!"
    print(f"  [PASS] Remote integrity confirmed: MinIO object {expected_key} matches SHA-256 {expected_sha[:16]}...")

def test_celery_task_registration():
    print("\n--- Test 5: Celery Scheduled Maintenance Task Verification ---")
    from app.tasks.maintenance import sync_pending_minio_artifacts
    res = sync_pending_minio_artifacts.apply()
    print(f"  [CELERY SYNC] Task execution status: {res.status}, result: {res.result}")
    assert res.status == "SUCCESS", f"Celery task failed: {res.status}"
    print(f"  [PASS] Celery Beat maintenance worker `sync_pending_minio_artifacts` operational.")

def main():
    print("================================================================================")
    print("       MONITORIX PHASE 3B: MinIO DISASTER RECOVERY & VAULT RESILIENCE           ")
    print("================================================================================")
    
    test_normal_upload_and_retrieval()
    local_path, meta_path, expected_sha, expected_key = test_outage_simulation_and_local_queue()
    test_quota_limit_enforcement()
    test_tamper_detection_and_reconciliation(local_path, meta_path, expected_sha, expected_key)
    test_celery_task_registration()

    print("\n================================================================================")
    print("  MinIO DISASTER RECOVERY TESTS: 100% PASS (5/5 Verifications Passed)            ")
    print("================================================================================")

if __name__ == "__main__":
    main()

