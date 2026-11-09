"""
[Phase 2A & 3A] Sovereign MinIO Forensic Vault Service
Provides cryptographic artifact storage, checksum verification, forensic retrieval,
and durable local fallback with automated reconciliation worker when MinIO is unreachable.
"""

import os
import io
import json
import glob
import hmac
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

logger = logging.getLogger("MinioVault")

class MinioVaultService:
    def __init__(self):
        raw_endpoint = os.getenv("MINIO_ENDPOINT", "minio:9000")
        # Replace sentinel_minio with minio to satisfy RFC 1123 hostname validation
        self.endpoint = raw_endpoint.replace("sentinel_minio", "minio")
        self.access_key = os.getenv("MINIO_ACCESS_KEY", "monitorix_admin_252b9ada")
        self.secret_key = os.getenv("MINIO_SECRET_KEY", "4VEaljYZdcK8o0uO8-nBcvSWodfWRgn2wKx5ig")
        self.secure = os.getenv("MINIO_SECURE", "false").lower() in ("true", "1", "yes")
        self.forensic_bucket = os.getenv("MINIO_FORENSIC_BUCKET", "monitorix-forensics")
        self.fallback_dir = os.getenv("MINIO_FALLBACK_DIR", "/app/storage/shadow/pending")
        self.max_fallback_bytes = int(os.getenv("MINIO_MAX_FALLBACK_BYTES", str(5 * 1024 * 1024 * 1024))) # 5 GB
        self._client: Optional[Any] = None

    def get_client(self) -> Any:
        if self._client is None:
            try:
                import urllib3
                from minio import Minio
                http_pool = urllib3.PoolManager(
                    timeout=urllib3.Timeout(connect=1.5, read=5.0),
                    retries=urllib3.Retry(total=1, connect=1, read=1)
                )
                self._client = Minio(
                    endpoint=self.endpoint,
                    access_key=self.access_key,
                    secret_key=self.secret_key,
                    secure=self.secure,
                    http_client=http_pool
                )
                self.ensure_bucket(self.forensic_bucket)
            except ImportError:
                logger.warning("[MinioVault] minio SDK not installed in environment; object storage disabled")
                return None
            except Exception as e:
                logger.warning(f"[MinioVault] Client connection initialization warning: {e}")
                return None
        return self._client

    def ensure_bucket(self, bucket_name: str):
        if not self._client:
            return
        try:
            if not self._client.bucket_exists(bucket_name):
                self._client.make_bucket(bucket_name)
                logger.info(f"[MinioVault] Created bucket: {bucket_name}")
        except Exception as e:
            logger.warning(f"[MinioVault] Bucket ensure check warning: {e}")

    def get_fallback_storage_usage(self) -> int:
        """Calculates total bytes occupied by pending local fallback artifacts."""
        total_size = 0
        if not os.path.exists(self.fallback_dir):
            return 0
        for dirpath, _, filenames in os.walk(self.fallback_dir):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                try:
                    total_size += os.path.getsize(fp)
                except OSError:
                    pass
        return total_size

    def _store_local_fallback(
        self,
        tenant_id: int,
        agent_id: str,
        safe_name: str,
        data_bytes: bytes,
        object_key: str,
        artifact_type: str,
        computed_sha256: str,
        declared_sha256: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Stores artifact on local persistent disk when MinIO is unreachable.
        Enforces 5 GB storage quota and writes atomic companion metadata.
        """
        current_usage = self.get_fallback_storage_usage()
        if current_usage + len(data_bytes) > self.max_fallback_bytes:
            logger.error(
                f"[MinioVault] Local fallback storage quota exceeded! "
                f"Usage: {current_usage} bytes, Max: {self.max_fallback_bytes} bytes"
            )
            raise IOError("Local fallback storage quota exceeded (5 GB limit)")

        now = datetime.utcnow()
        agent_clean = str(agent_id).replace(":", "_").replace("/", "_")
        target_dir = os.path.join(
            self.fallback_dir,
            f"tenant_{tenant_id}",
            f"agent_{agent_clean}",
            now.strftime("%Y%m%d")
        )
        os.makedirs(target_dir, exist_ok=True)

        timestamp_prefix = now.strftime("%H%M%S")
        local_filename = f"{timestamp_prefix}_{safe_name}"
        data_path = os.path.join(target_dir, local_filename)
        meta_path = f"{data_path}.meta.json"

        # 1. Write data file atomically
        tmp_data = f"{data_path}.tmp"
        with open(tmp_data, "wb") as f:
            f.write(data_bytes)
        os.rename(tmp_data, data_path)

        # 2. Write metadata file
        metadata = {
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "filename": safe_name,
            "object_key": object_key,
            "artifact_type": artifact_type,
            "declared_sha256": declared_sha256,
            "computed_sha256": computed_sha256,
            "size": len(data_bytes),
            "status": "PENDING_MINIO_SYNC",
            "created_at": now.isoformat(),
            "local_data_path": data_path,
            "retry_count": 0
        }
        tmp_meta = f"{meta_path}.tmp"
        with open(tmp_meta, "w") as f:
            json.dump(metadata, f, indent=2)
        os.rename(tmp_meta, meta_path)

        logger.warning(
            f"[MinioVault Fallback] MinIO unavailable. Queued artifact locally: "
            f"{data_path} (size={len(data_bytes)}B, sha256={computed_sha256})"
        )

        return {
            "bucket": self.forensic_bucket,
            "object_key": object_key,
            "size": len(data_bytes),
            "sha256": computed_sha256,
            "verified": True,
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "status": "PENDING_MINIO_SYNC",
            "local_path": data_path
        }

    def store_forensic_artifact(
        self,
        tenant_id: int,
        agent_id: str,
        filename: str,
        data_bytes: bytes,
        declared_sha256: Optional[str] = None,
        artifact_type: str = "shadow"
    ) -> Dict[str, Any]:
        """
        Validates artifact checksum and uploads to sovereign MinIO storage.
        Falls back to local disk with persistent tracking if MinIO is unreachable.
        """
        # 1. Compute raw bytes SHA-256
        computed_sha256 = hashlib.sha256(data_bytes).hexdigest().lower()

        # 2. Cryptographic digest comparison if declared
        if declared_sha256:
            declared_clean = declared_sha256.strip().lower()
            if not hmac.compare_digest(computed_sha256, declared_clean):
                raise ValueError(
                    f"Forensic SHA-256 mismatch: declared={declared_clean}, computed={computed_sha256}"
                )

        # 3. Object key layout: {artifact_type}/{tenant_id}/{agent_id}/{YYYYMMDD}/{timestamp}_{safe_name}
        now = datetime.utcnow()
        safe_name = os.path.basename(filename)
        agent_clean = str(agent_id).replace(":", "_").replace("/", "_")
        object_key = (
            f"{artifact_type}/tenant_{tenant_id}/agent_{agent_clean}/"
            f"{now.strftime('%Y%m%d')}/{now.strftime('%H%M%S')}_{safe_name}"
        )

        client = None
        try:
            client = self.get_client()
        except Exception as e:
            logger.warning(f"[MinioVault] Client resolution failed: {e}")

        if not client:
            return self._store_local_fallback(
                tenant_id=tenant_id,
                agent_id=agent_id,
                safe_name=safe_name,
                data_bytes=data_bytes,
                object_key=object_key,
                artifact_type=artifact_type,
                computed_sha256=computed_sha256,
                declared_sha256=declared_sha256
            )

        metadata = {
            "x-amz-meta-sha256": computed_sha256,
            "x-amz-meta-tenant-id": str(tenant_id),
            "x-amz-meta-agent-id": str(agent_id),
            "x-amz-meta-filename": safe_name,
            "x-amz-meta-uploaded-at": now.isoformat()
        }

        stream = io.BytesIO(data_bytes)
        try:
            client.put_object(
                bucket_name=self.forensic_bucket,
                object_name=object_key,
                data=stream,
                length=len(data_bytes),
                metadata=metadata
            )
            logger.info(
                f"[MinioVault] Stored artifact {object_key} (size={len(data_bytes)}B, sha256={computed_sha256})"
            )
            return {
                "bucket": self.forensic_bucket,
                "object_key": object_key,
                "size": len(data_bytes),
                "sha256": computed_sha256,
                "verified": True,
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "status": "SYNCED"
            }
        except Exception as upload_err:
            logger.warning(f"[MinioVault] Direct upload failed ({upload_err}). Falling back to local storage.")
            return self._store_local_fallback(
                tenant_id=tenant_id,
                agent_id=agent_id,
                safe_name=safe_name,
                data_bytes=data_bytes,
                object_key=object_key,
                artifact_type=artifact_type,
                computed_sha256=computed_sha256,
                declared_sha256=declared_sha256
            )

    def retrieve_forensic_artifact(
        self,
        object_key: str,
        bucket_name: Optional[str] = None
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        Retrieves artifact from MinIO and validates stored checksum.
        """
        bucket = bucket_name or self.forensic_bucket
        client = self.get_client()

        if not client:
            raise ConnectionError("MinIO client unavailable")

        response = client.get_object(bucket, object_key)
        try:
            data = response.read()
        finally:
            response.close()
            response.release_conn()

        computed_sha256 = hashlib.sha256(data).hexdigest().lower()

        # Fetch metadata
        stat = client.stat_object(bucket, object_key)
        stored_sha256 = stat.metadata.get("x-amz-meta-sha256", "").lower()

        if stored_sha256 and not hmac.compare_digest(computed_sha256, stored_sha256):
            raise ValueError(
                f"Retrieved artifact integrity failure: stored={stored_sha256}, computed={computed_sha256}"
            )

        return data, {
            "bucket": bucket,
            "object_key": object_key,
            "size": len(data),
            "sha256": computed_sha256,
            "stored_metadata": stat.metadata
        }

    def sync_pending_artifacts(self, max_batch: int = 100) -> Dict[str, Any]:
        """
        Reconciliation worker: Sweeps local pending artifacts, uploads to MinIO,
        verifies remote checksum, and deletes local copy only upon confirmation.
        """
        if not os.path.exists(self.fallback_dir):
            return {"synced": 0, "failed": 0, "bytes_synced": 0, "pending_remaining": 0}

        client = None
        try:
            client = self.get_client()
            if not client:
                return {"synced": 0, "failed": 0, "bytes_synced": 0, "pending_remaining": -1, "error": "MinIO unavailable"}
            # Test connectivity
            self.ensure_bucket(self.forensic_bucket)
        except Exception as e:
            logger.warning(f"[MinioVault Sync] MinIO still unreachable: {e}")
            return {"synced": 0, "failed": 0, "bytes_synced": 0, "pending_remaining": -1, "error": str(e)}

        meta_files = []
        for dirpath, _, filenames in os.walk(self.fallback_dir):
            for f in filenames:
                if f.endswith(".meta.json"):
                    meta_files.append(os.path.join(dirpath, f))

        synced_count = 0
        failed_count = 0
        bytes_synced = 0

        for meta_path in meta_files[:max_batch]:
            try:
                with open(meta_path, "r") as mf:
                    meta = json.load(mf)

                data_path = meta.get("local_data_path")
                if not data_path or not os.path.exists(data_path):
                    # Data file missing, clean up orphan metadata
                    try:
                        os.remove(meta_path)
                    except OSError:
                        pass
                    continue

                with open(data_path, "rb") as df:
                    data_bytes = df.read()

                # Verify local SHA-256 integrity before upload
                computed_sha = hashlib.sha256(data_bytes).hexdigest().lower()
                expected_sha = meta.get("computed_sha256", "").lower()
                if expected_sha and not hmac.compare_digest(computed_sha, expected_sha):
                    logger.error(f"[MinioVault Sync] Corruption detected for {data_path}! Aborting sync for this file.")
                    meta["status"] = "CORRUPTED"
                    with open(meta_path, "w") as mf:
                        json.dump(meta, mf)
                    failed_count += 1
                    continue

                object_key = meta.get("object_key")
                upload_metadata = {
                    "x-amz-meta-sha256": computed_sha,
                    "x-amz-meta-tenant-id": str(meta.get("tenant_id", "")),
                    "x-amz-meta-agent-id": str(meta.get("agent_id", "")),
                    "x-amz-meta-filename": meta.get("filename", ""),
                    "x-amz-meta-uploaded-at": datetime.utcnow().isoformat(),
                    "x-amz-meta-recovered-from-fallback": "true"
                }

                # Upload to MinIO
                stream = io.BytesIO(data_bytes)
                client.put_object(
                    bucket_name=self.forensic_bucket,
                    object_name=object_key,
                    data=stream,
                    length=len(data_bytes),
                    metadata=upload_metadata
                )

                # Verify remote object existence and metadata
                remote_stat = client.stat_object(self.forensic_bucket, object_key)
                remote_sha = remote_stat.metadata.get("x-amz-meta-sha256", "").lower()
                if remote_sha and not hmac.compare_digest(computed_sha, remote_sha):
                    raise ValueError(f"Remote SHA-256 mismatch after upload: {remote_sha} != {computed_sha}")

                # Purge local files ONLY after verified remote storage
                os.remove(data_path)
                os.remove(meta_path)

                synced_count += 1
                bytes_synced += len(data_bytes)
                logger.info(f"[MinioVault Sync] Successfully synced and verified remote artifact {object_key}")

            except Exception as item_err:
                logger.error(f"[MinioVault Sync] Error syncing {meta_path}: {item_err}")
                failed_count += 1

        # Clean empty directories
        for dirpath, dirnames, filenames in os.walk(self.fallback_dir, topdown=False):
            if not dirnames and not filenames and dirpath != self.fallback_dir:
                try:
                    os.rmdir(dirpath)
                except OSError:
                    pass

        remaining = max(0, len(meta_files) - synced_count)
        return {
            "synced": synced_count,
            "failed": failed_count,
            "bytes_synced": bytes_synced,
            "pending_remaining": remaining
        }

minio_vault = MinioVaultService()
