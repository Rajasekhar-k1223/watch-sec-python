import os
import json
import asyncio
from datetime import datetime
from aiokafka import AIOKafkaConsumer

from app.db.session import settings
from app.db.clickhouse import clickhouse_db
from app.db.session import AsyncSessionLocal
from app.services.threat_intel_pipeline import ti_pipeline
from app.services.detection_engine import detection_engine
from app.services.dlp_engine import dlp_engine
from app.socket_instance import sio
from sqlalchemy import select

class KafkaConsumerWorker:
    def __init__(self):
        self.topic = "monitorix_telemetry_raw"
        self.bootstrap_servers = os.getenv("KAFKA_BROKER_URL", "localhost:9092")
        self.consumer = None
        
        # Batching for ClickHouse inserts
        self.batch_size = 500
        self.flush_interval = 2.0  # seconds
        self.event_batch = []
        self.last_flush_time = datetime.utcnow()

    async def start(self):
        print(f"[Kafka Consumer] Starting consumer on {self.bootstrap_servers}")
        clickhouse_db.connect()
        
        # Prime Threat Intel cache before consuming messages
        async with AsyncSessionLocal() as db:
            await ti_pipeline.prime_cache(db)

        try:
            self.consumer = AIOKafkaConsumer(
                self.topic,
                bootstrap_servers=self.bootstrap_servers,
                group_id="monitorix_threat_engine",
                value_deserializer=lambda m: json.loads(m.decode('utf-8'))
            )
            await self.consumer.start()
            print(f"[Kafka Consumer] Listening on topic: {self.topic}")
        except Exception as e:
            print(f"[Kafka Consumer] Failed to connect: {e}")
            return

        # Start a background task for periodic flushing
        asyncio.create_task(self._periodic_flush())

        try:
            async for msg in self.consumer:
                event = msg.value
                await self.process_event(event)
        finally:
            await self.consumer.stop()
            print("[Kafka Consumer] Stopped")

    async def process_event(self, event: dict):
        try:
            print(f"[DEBUG] Received EventType: {event.get('EventType')}", flush=True)
            async with AsyncSessionLocal() as db:
                # 1. DLP Pipeline Scan
                agent_id = event.get("AgentId", "Unknown")
                payload_str = json.dumps(event)
                action, violations = await dlp_engine.evaluate_payload(db, agent_id, "Telemetry", payload_str)
                
                if action == "Block":
                    print(f"[DLP] Dropping event from Agent {agent_id} due to DLP Block Policy.")
                    return  # Drop the event entirely, do not insert into ClickHouse or run detections

                # 2. Real-time Threat Detection
                await detection_engine.process_telemetry_event(db, event, agent_id)

                # 3. Real-Time Threat Intelligence (IOC) Matching
                indicators = []
                # Extract potential IOCs from the dynamic JSON payload
                if event.get("RemoteIp"): indicators.append(("IPv4", event.get("RemoteIp")))
                if event.get("DestinationIp"): indicators.append(("IPv4", event.get("DestinationIp")))
                if event.get("RemoteHost"): indicators.append(("Domain", event.get("RemoteHost")))
                if event.get("Query"): indicators.append(("Domain", event.get("Query")))
                if event.get("Sha256"): indicators.append(("SHA256", event.get("Sha256")))
                if event.get("Md5"): indicators.append(("MD5", event.get("Md5")))
                if event.get("hash"): indicators.append(("SHA256", event.get("hash"))) # generic hash field
                
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
                        # Store the alert in ClickHouse buffer
                        import uuid
                        self.event_batch.append((
                            str(uuid.uuid4()), agent_id, ti_alert["TenantId"], 
                            "ThreatIntelAlert", datetime.utcnow(), json.dumps(ti_alert)
                        ))

            # 4. Real-time Dashboard Updates
            if event.get("EventType") == "ProcessSnapshot":
                processes = event.get("Processes") or event.get("Payload", {}).get("Processes", [])
                print(f"[DEBUG] Emitting agent_processes for {agent_id}. Count: {len(processes)}", flush=True)
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
                        # Resolve TenantId from Agent if not present in event
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

                        # Real-time push to dashboard
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

            # 3. Buffer for ClickHouse Data Lake
            # tuple: (event_id, agent_id, tenant_id, event_type, timestamp, payload)
            # Default missing event_id to a new uuid if not present
            import uuid
            
            record = (
                event.get("event_id", str(uuid.uuid4())),
                event.get("AgentId", ""),
                str(event.get("TenantId", "")),
                event.get("EventType", "Unknown"),
                datetime.utcnow(),
                json.dumps(event)
            )
            self.event_batch.append(record)

            # Flush if batch size reached
            if len(self.event_batch) >= self.batch_size:
                await self.flush_batch()

        except Exception as e:
            print(f"[Kafka Consumer] Error processing event: {e}")

    async def flush_batch(self):
        if not self.event_batch:
            return

        print(f"[ClickHouse] Flushing {len(self.event_batch)} records to Data Lake...")
        success = clickhouse_db.insert_telemetry(self.event_batch)
        if success:
            self.event_batch.clear()
            self.last_flush_time = datetime.utcnow()
        else:
            print("[ClickHouse] Failed to flush batch")

    async def _periodic_flush(self):
        while True:
            await asyncio.sleep(self.flush_interval)
            time_since_flush = (datetime.utcnow() - self.last_flush_time).total_seconds()
            if time_since_flush >= self.flush_interval and self.event_batch:
                await self.flush_batch()

if __name__ == "__main__":
    worker = KafkaConsumerWorker()
    asyncio.run(worker.start())
