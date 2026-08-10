import os
import json
import asyncio
from aiokafka import AIOKafkaProducer
from app.db.session import settings

class KafkaProducerClient:
    def __init__(self):
        self.producer = None
        self.topic = "monitorix_telemetry_raw"
        self.bootstrap_servers = os.getenv("KAFKA_BROKER_URL", "localhost:9092")
        
    async def connect(self):
        try:
            self.producer = AIOKafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
            await self.producer.start()
            print(f"[Kafka] Connected to {self.bootstrap_servers}")
        except Exception as e:
            print(f"[Kafka] Failed to connect: {e}")
            self.producer = None

    async def disconnect(self):
        if self.producer:
            await self.producer.stop()
            print("[Kafka] Disconnected")

    async def publish_event(self, event_data: dict):
        if not self.producer:
            # Fallback if Kafka is down
            return False
            
        try:
            await self.producer.send_and_wait(self.topic, event_data)
            return True
        except Exception as e:
            print(f"[Kafka] Publish error: {e}")
            return False

kafka_client = KafkaProducerClient()
