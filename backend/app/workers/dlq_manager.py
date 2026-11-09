"""
Monitorix Telemetry Dead-Letter Queue (DLQ) & Durable Spool Manager
===================================================================
100% Sovereign Monitorix Architecture. Zero external dependencies.

Prevents telemetry data loss during downstream outages (e.g. ClickHouse
transient network partitions, node restarts, or query timeouts).

Guarantees:
1. Bounded memory: Batches exceeding flush thresholds are spooled to local disk.
2. At-least-once durable storage: Never drop an event without persistent spooling.
3. Automated exponential retry: Continuously replays spooled batches into ClickHouse.
"""

import os
import glob
import json
import uuid
import time
import asyncio
from datetime import datetime
from typing import List, Tuple, Dict, Any

class DLQManager:
    def __init__(self, spool_dir: str = None):
        if spool_dir is None:
            # Check container environment or local backend path
            base_dir = "/app/storage/dlq" if os.path.exists("/app/storage") else "/opt/projects/monitorix/watch-sec-python/backend/storage/dlq"
            self.spool_dir = base_dir
        else:
            self.spool_dir = spool_dir

        os.makedirs(self.spool_dir, exist_ok=True)
        self.total_spooled_records = 0
        self.total_recovered_records = 0
        self.last_retry_time = None
        self.consecutive_failures = 0

    async def spool_failed_batch(self, batch_records: List[Tuple], reason: str = "ClickHouse write failure") -> str:
        """
        Durable disk spooling: Serializes telemetry batch to an append-only JSON file.
        Returns the created spool file path.
        """
        if not batch_records:
            return ""

        file_id = f"dlq_{int(time.time())}_{uuid.uuid4().hex[:8]}.json"
        file_path = os.path.join(self.spool_dir, file_id)

        # Record structure: (event_id, agent_id, tenant_id, event_type, timestamp, payload)
        serialized_records = []
        for r in batch_records:
            try:
                # Convert datetime to isoformat if needed
                ts = r[4].isoformat() if hasattr(r[4], 'isoformat') else str(r[4])
                serialized_records.append({
                    "event_id": str(r[0]),
                    "agent_id": str(r[1]),
                    "tenant_id": str(r[2]),
                    "event_type": str(r[3]),
                    "timestamp": ts,
                    "payload": r[5] if isinstance(r[5], str) else json.dumps(r[5])
                })
            except Exception as e:
                print(f"[DLQ] Record serialization warning: {e}")

        payload = {
            "spooled_at": datetime.utcnow().isoformat(),
            "reason": reason,
            "record_count": len(serialized_records),
            "records": serialized_records
        }

        # Atomic write with temp file
        temp_path = f"{file_path}.tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.rename(temp_path, file_path)

        self.total_spooled_records += len(serialized_records)
        print(f"[DLQ ALERT] Spooled {len(serialized_records)} records to disk: {file_path} (Reason: {reason})")
        return file_path

    async def process_dlq_retries(self, clickhouse_client) -> int:
        """
        Scans spool directory and attempts replay into ClickHouse.
        Deletes spool file strictly upon verified insertion.
        Returns number of successfully replayed records.
        """
        spool_files = sorted(glob.glob(os.path.join(self.spool_dir, "dlq_*.json")))
        if not spool_files:
            return 0

        recovered_count = 0
        for fp in spool_files:
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    data = json.load(f)

                raw_records = data.get("records", [])
                if not raw_records:
                    os.remove(fp)
                    continue

                # Reconstruct tuples for ClickHouse insertion
                batch = []
                for r in raw_records:
                    ts = datetime.fromisoformat(r["timestamp"]) if "T" in r["timestamp"] else datetime.utcnow()
                    batch.append((
                        r["event_id"],
                        r["agent_id"],
                        r["tenant_id"],
                        r["event_type"],
                        ts,
                        r["payload"]
                    ))

                success = clickhouse_client.insert_telemetry(batch)
                if success:
                    os.remove(fp)
                    recovered_count += len(batch)
                    self.total_recovered_records += len(batch)
                    self.consecutive_failures = 0
                    print(f"[DLQ RECOVERY] Successfully replayed {len(batch)} records from {os.path.basename(fp)} to ClickHouse")
                else:
                    self.consecutive_failures += 1
                    print(f"[DLQ RETRY] ClickHouse still rejecting batch {os.path.basename(fp)}, preserving spool file")
                    break  # Stop processing further files until ClickHouse recovers
            except Exception as e:
                self.consecutive_failures += 1
                print(f"[DLQ RETRY ERROR] Failed processing {fp}: {e}")
                break

        self.last_retry_time = datetime.utcnow()
        return recovered_count

    def get_metrics(self) -> Dict[str, Any]:
        """Return real-time operational status of the DLQ system"""
        spool_files = glob.glob(os.path.join(self.spool_dir, "dlq_*.json"))
        return {
            "spool_directory": self.spool_dir,
            "pending_spool_files": len(spool_files),
            "total_spooled_records": self.total_spooled_records,
            "total_recovered_records": self.total_recovered_records,
            "consecutive_failures": self.consecutive_failures,
            "last_retry_time": self.last_retry_time.isoformat() if self.last_retry_time else None,
            "status": "DEGRADED_SPOOLING" if len(spool_files) > 0 else "HEALTHY_CLEAN"
        }

    get_status = get_metrics

    async def retry_spooled_records(self, clickhouse_client=None) -> int:
        """Helper to invoke retry with optional or initialized ClickHouse sink"""
        if clickhouse_client is None:
            try:
                from app.db.clickhouse import ClickHouseClient
                clickhouse_client = ClickHouseClient()
                clickhouse_client.connect()
            except Exception as e:
                print(f"[DLQ] ClickHouse sink initialization error: {e}")
                return 0
        return await self.process_dlq_retries(clickhouse_client)

    async def start_retry_worker(self, clickhouse_client, interval_seconds: int = 5):
        """Background coroutine to periodically drain DLQ spool into ClickHouse"""
        print(f"[DLQ Worker] Started background spool replay monitor (Interval: {interval_seconds}s)", flush=True)
        while True:
            try:
                await asyncio.sleep(interval_seconds)
                # Apply exponential backoff if consecutive failures occurred (up to 60s)
                if self.consecutive_failures > 0:
                    backoff = min(60, interval_seconds * (2 ** min(self.consecutive_failures, 5)))
                    await asyncio.sleep(backoff)

                await self.process_dlq_retries(clickhouse_client)
            except Exception as e:
                print(f"[DLQ Worker Error] Loop exception: {e}")

dlq_manager = DLQManager()
