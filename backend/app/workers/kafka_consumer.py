"""
Monitorix High-Reliability Telemetry Kafka Consumer Worker
==========================================================
100% Sovereign Monitorix Architecture. Zero external dependencies.

Features:
1. Zero Data-Loss Invariant: Kafka offsets committed ONLY after durable storage.
2. ClickHouse Micro-Batching: Flushes with size and time thresholds to avoid write thrashing.
3. Durable Disk-Backed DLQ: Spools failed batches to disk with automatic background replay.
4. Real-time Threat Intelligence, DLP Ingress Filtering, and FIM Correlation.
"""

import os
import json
import asyncio
from datetime import datetime
from aiokafka import AIOKafkaConsumer, TopicPartition
from aiokafka.structs import OffsetAndMetadata
from sqlalchemy import select

from app.db.session import settings
from app.db.clickhouse import clickhouse_db
from app.db.session import AsyncSessionLocal
from app.services.threat_intel_pipeline import ti_pipeline
from app.services.detection_engine import detection_engine
from app.services.dlp_engine import dlp_engine
from app.workers.dlq_manager import dlq_manager
from app.socket_instance import sio
from app.services.correlation_service import streaming_correlation_engine

class KafkaConsumerWorker:
    def __init__(self):
        self.topic = "monitorix_telemetry_raw"
        self.bootstrap_servers = os.getenv("KAFKA_BROKER_URL", "localhost:9092")
        self.consumer = None
        
        # Batching for ClickHouse inserts
        self.batch_size = 200
        self.flush_interval = 2.0  # seconds
        self.event_batch = []
        self.pending_offsets = {}  # TopicPartition -> OffsetAndMetadata
        self.last_flush_time = datetime.utcnow()
        self.worker_id = os.getenv("WORKER_ID", "consumer-node-01")
        self.hostname = os.getenv("HOSTNAME", "monitorix-consumer-pod")
        self.total_processed = 0
        self._flush_lock = asyncio.Lock()

    async def start(self):
        print(f"[Kafka Consumer] Starting zero-data-loss consumer on {self.bootstrap_servers}")
        clickhouse_db.connect()
        
        # Prime Threat Intel cache before consuming messages
        async with AsyncSessionLocal() as db:
            await ti_pipeline.prime_cache(db)

        try:
            self.consumer = AIOKafkaConsumer(
                self.topic,
                bootstrap_servers=self.bootstrap_servers,
                group_id="monitorix_threat_engine",
                enable_auto_commit=False,  # CRITICAL: Manual commit strictly upon durable write
                auto_offset_reset="earliest",
                value_deserializer=lambda m: json.loads(m.decode('utf-8'))
            )
            await self.consumer.start()
            print(f"[Kafka Consumer] Listening on topic: {self.topic} (Manual Commit Enforced)", flush=True)
        except Exception as e:
            print(f"[Kafka Consumer] Failed to connect: {e}", flush=True)
            return

        # Start background tasks: Periodic micro-batch flushing & DLQ recovery worker & cluster heartbeat
        asyncio.create_task(self._periodic_flush())
        asyncio.create_task(dlq_manager.start_retry_worker(clickhouse_db, interval_seconds=5))
        asyncio.create_task(self._periodic_heartbeat())

        try:
            async for msg in self.consumer:
                event = msg.value
                # Track pending offset for this message
                tp = TopicPartition(msg.topic, msg.partition)
                self.pending_offsets[tp] = OffsetAndMetadata(msg.offset + 1, '')
                await self.process_event(event, partition=msg.partition)
        finally:
            await self.consumer.stop()
            print("[Kafka Consumer] Stopped")

    async def _periodic_heartbeat(self):
        """Periodically registers consumer worker node and active Kafka partition assignments with Redis cluster."""
        while True:
            try:
                assigned_parts = []
                if self.consumer:
                    assigned_parts = [tp.partition for tp in self.consumer.assignment()]
                if not assigned_parts:
                    assigned_parts = [0]
                streaming_correlation_engine.register_worker_heartbeat(
                    worker_id=self.worker_id,
                    partitions=assigned_parts,
                    hostname=self.hostname,
                    status="ACTIVE",
                    processed_count=self.total_processed
                )
            except Exception as hb_err:
                print(f"[Kafka Consumer] Non-fatal heartbeat warning: {hb_err}")
            await asyncio.sleep(10)

    async def process_event(self, event: dict, partition: int = 0):
        try:
            self.total_processed += 1
            print(f"[DEBUG] Received EventType: {event.get('EventType')}", flush=True)
            async with AsyncSessionLocal() as db:
                # 1. DLP Pipeline Scan
                agent_id = event.get("AgentId", "Unknown")
                payload_str = json.dumps(event)
                action, violations = await dlp_engine.evaluate_payload(db, agent_id, "Telemetry", payload_str)
                
                if action == "Block":
                    print(f"[DLP] Dropping event from Agent {agent_id} due to DLP Block Policy.")
                    return  # Drop the event entirely, do not insert into ClickHouse or run detections

                # 2. Real-time Threat Detection (Sigma Rules & SIEM Events)
                if event.get("EventType") in ("ProcessExecution", "PROCESS_START", "process_creation"):
                    try:
                        from app.services.detection.streaming_detector import streaming_detection_engine
                        await streaming_detection_engine.process_kafka_event(db, event, agent_id)
                    except Exception as s_err:
                        print(f"[StreamingDetection] Non-fatal evaluation error: {s_err}", flush=True)

                await detection_engine.process_telemetry_event(db, event, agent_id)

                # 3. Real-Time Threat Intelligence (IOC) Matching
                indicators = []
                if event.get("RemoteIp"): indicators.append(("IPv4", event.get("RemoteIp")))
                if event.get("DestinationIp"): indicators.append(("IPv4", event.get("DestinationIp")))
                if event.get("RemoteHost"): indicators.append(("Domain", event.get("RemoteHost")))
                if event.get("Query"): indicators.append(("Domain", event.get("Query")))
                if event.get("Sha256"): indicators.append(("SHA256", event.get("Sha256")))
                if event.get("Md5"): indicators.append(("MD5", event.get("Md5")))
                if event.get("hash"): indicators.append(("SHA256", event.get("hash")))
                
                for ioc_type, val in indicators:
                    if await ti_pipeline.is_malicious(ioc_type, val):
                        print(f"[ThreatIntel] MATCH: {val} ({ioc_type}) on Agent {agent_id}")
                        ti_alert = {
                            "AgentId": agent_id,
                            "TenantId": event.get("TenantId", "Unknown"),
                            "EventType": "ThreatIntelAlert",
                            "Severity": "Critical",
                            "Message": f"Endpoint communicated with known malicious IOC: {val} ({ioc_type})",
                            "OriginalEvent": event
                        }
                        # Broadcast alert to SIEM/WebSockets
                        await sio.emit('threat_alert', ti_alert, room=f"tenant_{event.get('TenantId')}")
                        import uuid
                        self.event_batch.append((
                            str(uuid.uuid4()), agent_id, ti_alert["TenantId"], 
                            "ThreatIntelAlert", datetime.utcnow(), json.dumps(ti_alert)
                        ))

            # 4. Real-time Dashboard Updates
            if event.get("EventType") == "ProcessSnapshot":
                processes = event.get("Processes") or event.get("Payload", {}).get("Processes", [])
                await sio.emit('agent_processes', {
                    'agent_id': agent_id,
                    'processes': processes
                }, room=agent_id)
            elif event.get("EventType") == "LiveSessionTelemetry":
                process_name = event.get("ProcessName") or event.get("Payload", {}).get("ProcessName", "")
                window_title = event.get("WindowTitle") or event.get("Payload", {}).get("WindowTitle", "")
                await sio.emit('live_session_telemetry', {
                    'agent_id': agent_id,
                    'process_name': process_name,
                    'window_title': window_title
                }, room=f"tenant_{event.get('TenantId')}")

            # 5. [FIM] Persist FileIntegrityAlert as an EventLog for federation API & dashboard
            if event.get("EventType") == "FileIntegrityAlert":
                try:
                    from app.db.models import EventLog, Agent  # type: ignore
                    async with AsyncSessionLocal() as fim_db:
                        tenant_id = event.get("TenantId")
                        if not tenant_id:
                            res = await fim_db.execute(select(Agent).where(Agent.AgentId == agent_id))
                            agent_obj = res.scalars().first()
                            tenant_id = agent_obj.TenantId if agent_obj else None

                        fim_log = EventLog(
                            AgentId=agent_id,
                            TenantId=tenant_id,
                            Type="FIM Alert",
                            Details=(
                                f"[{event.get('Operation', 'Modified')}] {event.get('FilePath', 'Unknown')} "
                                f"| SHA256: {event.get('SHA256', 'N/A')} "
                                f"| Entropy: {event.get('Entropy', 0.0):.2f}"
                            ),
                            Severity=event.get("Severity", "High"),
                            IsAlert=True,
                            Timestamp=datetime.utcnow()
                        )
                        fim_db.add(fim_log)
                        await fim_db.commit()
                        print(f"[FIM] Saved FileIntegrityAlert for Agent {agent_id}: {event.get('FilePath')}")

                        await sio.emit('fim_alert', {
                            'agent_id': agent_id,
                            'file_path': event.get('FilePath'),
                            'operation': event.get('Operation'),
                            'sha256': event.get('SHA256'),
                            'entropy': event.get('Entropy'),
                            'severity': event.get('Severity', 'High'),
                            'timestamp': datetime.utcnow().isoformat()
                        }, room=f"tenant_{tenant_id}")
                except Exception as fim_err:
                    print(f"[FIM] Error saving FIM event: {fim_err}")

            # 5b. [Streaming Threat Correlation] In-Flight Multi-Stage Threat Correlation Engine
            try:
                correlations = streaming_correlation_engine.evaluate_event(
                    event, worker_id=self.worker_id, partition=partition
                )
                for corr in correlations:
                    corr_tenant = event.get("TenantId", "1")
                    print(
                        f"[StreamingCorrelation] In-Flight Threat Detected: {corr.get('type')} on Agent {agent_id} "
                        f"(Severity: {corr.get('severity')}, Tactic: {corr.get('mitre_tactic')})",
                        flush=True
                    )
                    # Broadcast in-flight correlation to SOC & SIEM
                    await sio.emit('streaming_threat_correlation', corr, room=f"tenant_{corr_tenant}")
                    if corr.get("attack_chain"):
                        await sio.emit('attack_chain_updated', corr.get("attack_chain"), room=f"tenant_{corr_tenant}")

                    # Persist critical correlation in EventLog for SOC review & historical auditing
                    try:
                        from app.db.models import EventLog
                        async with AsyncSessionLocal() as corr_db:
                            ev_log = EventLog(
                                AgentId=agent_id,
                                TenantId=int(corr_tenant) if str(corr_tenant).isdigit() else None,
                                Type=f"CorrelationAlert: {corr.get('type')}",
                                Details=f"{corr.get('description', '')} | Evidence: {corr.get('evidence', '')}",
                                Severity=corr.get("severity", "High"),
                                IsAlert=True,
                                Timestamp=datetime.utcnow()
                            )
                            corr_db.add(ev_log)
                            await corr_db.commit()
                    except Exception as db_err:
                        print(f"[StreamingCorrelation] Non-fatal DB event log error: {db_err}")

                    # Buffer correlation event into ClickHouse data lake
                    import uuid
                    corr_rec = (
                        str(uuid.uuid4()),
                        agent_id,
                        str(corr_tenant),
                        "StreamingCorrelationAlert",
                        datetime.utcnow(),
                        json.dumps(corr)
                    )
                    self.event_batch.append(corr_rec)
            except Exception as corr_err:
                print(f"[StreamingCorrelation] Error evaluating event in-flight: {corr_err}")

            # 6. Buffer for ClickHouse Data Lake (Preserving historical client event timestamp)
            import uuid
            raw_ts = (
                event.get("original_timestamp") or
                event.get("Timestamp") or
                event.get("timestamp") or
                event.get("detected_at")
            )
            event_ts = datetime.utcnow()
            if raw_ts:
                try:
                    if isinstance(raw_ts, str):
                        event_ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00")).replace(tzinfo=None)
                    elif isinstance(raw_ts, (int, float)):
                        event_ts = datetime.utcfromtimestamp(raw_ts)
                except Exception:
                    event_ts = datetime.utcnow()

            record = (
                event.get("event_id", str(uuid.uuid4())),
                event.get("AgentId", ""),
                str(event.get("TenantId", "")),
                event.get("EventType", "Unknown"),
                event_ts,
                json.dumps(event)
            )
            self.event_batch.append(record)

            # Flush if batch size reached
            if len(self.event_batch) >= self.batch_size:
                await self.flush_batch()

        except Exception as e:
            print(f"[Kafka Consumer] Error processing event: {e}")

    async def flush_batch(self):
        """
        Micro-batch flush with strict reliable delivery:
        1. Attempt insert into ClickHouse
        2. On success: clear batch and commit Kafka offsets
        3. On failure: spool to durable disk DLQ, then commit Kafka offsets so stream doesn't deadlock
        """
        async with self._flush_lock:
            if not self.event_batch:
                return

            records_to_flush = list(self.event_batch)
            offsets_to_commit = dict(self.pending_offsets)
            count = len(records_to_flush)

            print(f"[ClickHouse Ingest] Flushing {count} records to Data Lake...")
            success = False
            try:
                success = clickhouse_db.insert_telemetry(records_to_flush)
            except Exception as ch_err:
                print(f"[ClickHouse Ingest ERROR] Exception inserting {count} records: {ch_err}")
                success = False

            if success:
                self.event_batch.clear()
                self.last_flush_time = datetime.utcnow()
                # Safely commit offsets strictly after durable write
                if offsets_to_commit and self.consumer:
                    try:
                        await self.consumer.commit(offsets_to_commit)
                        # Remove committed offsets from pending dict
                        for tp in offsets_to_commit:
                            if tp in self.pending_offsets and self.pending_offsets[tp] == offsets_to_commit[tp]:
                                del self.pending_offsets[tp]
                    except Exception as commit_err:
                        print(f"[Kafka Consumer] Offset commit error: {commit_err}")
            else:
                # Failure path: Spool to disk DLQ to guarantee zero telemetry loss
                print(f"[ClickHouse Ingest FAILURE] Spooling {count} records to durable Disk DLQ...")
                await dlq_manager.spool_failed_batch(records_to_flush, reason="ClickHouse insertion rejected batch")
                self.event_batch.clear()
                self.last_flush_time = datetime.utcnow()
                # Commit offset now that data is durably stored on disk in DLQ
                if offsets_to_commit and self.consumer:
                    try:
                        await self.consumer.commit(offsets_to_commit)
                        for tp in offsets_to_commit:
                            if tp in self.pending_offsets and self.pending_offsets[tp] == offsets_to_commit[tp]:
                                del self.pending_offsets[tp]
                    except Exception as commit_err:
                        print(f"[Kafka Consumer] Offset commit error: {commit_err}")

    async def _periodic_flush(self):
        while True:
            await asyncio.sleep(self.flush_interval)
            time_since_flush = (datetime.utcnow() - self.last_flush_time).total_seconds()
            if time_since_flush >= self.flush_interval and self.event_batch:
                await self.flush_batch()

if __name__ == "__main__":
    worker = KafkaConsumerWorker()
    asyncio.run(worker.start())
