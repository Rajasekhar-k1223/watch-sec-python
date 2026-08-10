import asyncio
import json
from concurrent import futures
import grpc
from datetime import datetime

from app import telemetry_pb2
from app import telemetry_pb2_grpc
from app.core.kafka_producer import kafka_client

class TelemetryGatewayServicer(telemetry_pb2_grpc.TelemetryGatewayServicer):
    
    async def StreamEvents(self, request_iterator, context):
        print(f"[gRPC Gateway] Client stream opened...")
        events_processed = 0
        
        try:
            async for event in request_iterator:
                # Convert protobuf AgentEvent to python dictionary for Kafka
                payload_dict = {}
                try:
                    payload_dict = json.loads(event.payload)
                except Exception:
                    pass
                
                event_dict = {
                    "AgentId": event.agent_id,
                    "TenantId": event.tenant_id,
                    "EventType": event.event_type,
                    "Payload": payload_dict,
                    "Timestamp": event.timestamp or datetime.utcnow().isoformat(),
                    "_ingest_source": "grpc",
                    "_ingest_time": datetime.utcnow().isoformat()
                }
                
                # Publish instantly to Kafka Event Bus
                await kafka_client.publish_event(event_dict)
                events_processed += 1
                
        except Exception as e:
            print(f"[gRPC Gateway] Error streaming events: {e}")
            return telemetry_pb2.StreamResponse(
                success=False,
                events_processed=events_processed,
                message=str(e)
            )

        print(f"[gRPC Gateway] Client stream closed. Processed {events_processed} events.")
        return telemetry_pb2.StreamResponse(
            success=True,
            events_processed=events_processed,
            message="Stream completed successfully"
        )

async def serve():
    # Make sure Kafka is connected before accepting gRPC streams
    await kafka_client.connect()
    
    server = grpc.aio.server()
    telemetry_pb2_grpc.add_TelemetryGatewayServicer_to_server(TelemetryGatewayServicer(), server)
    server.add_insecure_port('[::]:50051')
    
    print("[gRPC Gateway] Starting high-performance listener on port 50051")
    await server.start()
    await server.wait_for_termination()

if __name__ == '__main__':
    asyncio.run(serve())
