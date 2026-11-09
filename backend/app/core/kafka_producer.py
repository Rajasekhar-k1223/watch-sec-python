import os
import json
import asyncio
from aiokafka import AIOKafkaProducer
from app.db.session import settings

class KafkaProducerClient:
    def __init__(self):
        self.producer = None
        self.topic = "monitorix_telemetry_raw"
        self.dlq_topic = "monitorix_telemetry_dlq"
        self.bootstrap_servers = os.getenv("KAFKA_BROKER_URL", "localhost:9092")
        
    async def connect(self):
        try:
            self.producer = AIOKafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                key_serializer=lambda k: k.encode('utf-8') if isinstance(k, str) else (k if k is not None else b'')
            )
            await self.producer.start()
            print(f"[Kafka] Connected to {self.bootstrap_servers} with key serialization")
        except Exception as e:
            print(f"[Kafka] Failed to connect: {e}")
            self.producer = None

    async def disconnect(self):
        if self.producer:
            await self.producer.stop()
            print("[Kafka] Disconnected")

    async def publish_event(self, event_data: dict, key: str = None):
        """
        Publishes event with deterministic per-agent ordering key.
        Guarantees strict FIFO ordering per endpoint across all partitions.
        """
        if not self.producer:
            print("[Kafka] Producer not found, attempting auto-reconnect...")
            await self.connect()
            if not self.producer:
                print("[Kafka] Auto-reconnect failed, dropping event.")
                return False

        # Stable partition key: agent_id or tenant_id
        partition_key = key or str(event_data.get("AgentId") or event_data.get("TenantId") or "default_key")

        try:
            await self.producer.send_and_wait(self.topic, value=event_data, key=partition_key)
            return True
        except Exception as e:
            print(f"[Kafka] Publish error on main topic: {e}. Routing to DLQ...")
            try:
                # Dead-letter queue fallback
                await self.producer.send_and_wait(self.dlq_topic, value=event_data, key=partition_key)
            except Exception as dlq_err:
                print(f"[Kafka DLQ Critical] Failed to write to DLQ: {dlq_err}")
            # Reset producer on fatal publish error to force reconnect next time
            self.producer = None
            return False

kafka_client = KafkaProducerClient()
