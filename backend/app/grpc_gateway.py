import asyncio
import json
import logging
import os
from concurrent import futures
import grpc
from datetime import datetime
from sqlalchemy.future import select

from app import telemetry_pb2
from app import telemetry_pb2_grpc
from app.core.kafka_producer import kafka_client
from app.services import ca_service
from app.db.session import AsyncSessionLocal
from app.db.models import Agent, DeviceCertificate

try:
    from grpc_health.v1 import health, health_pb2, health_pb2_grpc
    HEALTH_CHECKING_AVAILABLE = True
except ImportError:
    HEALTH_CHECKING_AVAILABLE = False

GATEWAY_INSTANCE_ID = os.getenv("GATEWAY_INSTANCE_ID", "gateway-standalone")
logger = logging.getLogger(f"GrpcTelemetryGateway[{GATEWAY_INSTANCE_ID}]")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

class TelemetryGatewayServicer(telemetry_pb2_grpc.TelemetryGatewayServicer):
    
    async def StreamEvents(self, request_iterator, context):
        # 1. Extract peer authentication from Mutual TLS handshake context
        auth_context = context.auth_context()
        cn_bytes_list = auth_context.get("x509_common_name", [])
        
        if not cn_bytes_list:
            logger.warning("[mTLS] Handshake rejected: No client X.509 Common Name presented.")
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "Mutual TLS client identity missing")
            return

        client_cn = cn_bytes_list[0].decode("utf-8") if isinstance(cn_bytes_list[0], bytes) else str(cn_bytes_list[0])
        peer_addr = context.peer()
        logger.info(f"[mTLS] Authenticated peer connection from {peer_addr} with CN='{client_cn}'")

        # 2. Authoritative Database Verification: Validate Certificate Status & Tenant Ownership
        async with AsyncSessionLocal() as db:
            # Check certificate status
            cert_res = await db.execute(
                select(DeviceCertificate).where(
                    DeviceCertificate.AgentId == client_cn,
                    DeviceCertificate.Status == "ACTIVE"
                ).order_by(DeviceCertificate.IssuedAt.desc())
            )
            active_cert = cert_res.scalars().first()

            if not active_cert:
                logger.warning(f"[mTLS] Access denied for '{client_cn}': No ACTIVE DeviceCertificate found.")
                await context.abort(grpc.StatusCode.PERMISSION_DENIED, f"Agent certificate for '{client_cn}' is revoked, expired, or not enrolled")
                return

            if active_cert.ExpiresAt < datetime.utcnow():
                logger.warning(f"[mTLS] Access denied for '{client_cn}': Certificate expired on {active_cert.ExpiresAt.isoformat()}.")
                await context.abort(grpc.StatusCode.PERMISSION_DENIED, f"Agent certificate for '{client_cn}' is expired")
                return

            # Check agent operational status
            agent_res = await db.execute(select(Agent).where(Agent.AgentId == client_cn))
            agent = agent_res.scalars().first()

            if not agent:
                logger.warning(f"[mTLS] Access denied for '{client_cn}': Agent record not found in database.")
                await context.abort(grpc.StatusCode.PERMISSION_DENIED, f"Agent '{client_cn}' not registered")
                return

            if getattr(agent, "IsDecommissioned", False):
                logger.warning(f"[mTLS] Access denied for '{client_cn}': Agent is decommissioned.")
                await context.abort(grpc.StatusCode.PERMISSION_DENIED, f"Agent '{client_cn}' is decommissioned")
                return

            tenant_id = agent.TenantId

        events_processed = 0

        # 3. Process Stream with Identity Spoofing Protection
        try:
            async for event in request_iterator:
                # Anti-Spoofing: Ensure incoming telemetry matches authenticated client identity
                if event.agent_id and event.agent_id != client_cn:
                    logger.warning(f"[mTLS Spoof Attempt] Client '{client_cn}' attempted to transmit telemetry for '{event.agent_id}'! Dropping event.")
                    continue

                payload_dict = {}
                try:
                    payload_dict = json.loads(event.payload)
                except Exception:
                    pass

                event_dict = {
                    "AgentId": client_cn,
                    "TenantId": tenant_id,
                    "EventType": event.event_type or "Unknown",
                    "Payload": payload_dict,
                    "Timestamp": event.timestamp or datetime.utcnow().isoformat(),
                    "_ingest_source": "grpc_mtls",
                    "_ingest_time": datetime.utcnow().isoformat(),
                    "_client_cert_serial": active_cert.SerialNumber
                }

                # Publish to Kafka Event Bus with stable per-agent partition key
                await kafka_client.publish_event(event_dict, key=client_cn)
                events_processed += 1

                # In-Stream Revocation Check: Ensure certificate hasn't been revoked mid-stream
                if events_processed % 5 == 0:
                    async with AsyncSessionLocal() as db_check:
                        chk_res = await db_check.execute(
                            select(DeviceCertificate.Status).where(
                                DeviceCertificate.SerialNumber == active_cert.SerialNumber
                            )
                        )
                        curr_status = chk_res.scalars().first()
                        if curr_status != "ACTIVE":
                            logger.warning(f"[mTLS Revocation] Certificate serial {active_cert.SerialNumber} for '{client_cn}' was REVOKED mid-stream! Aborting.")
                            await context.abort(grpc.StatusCode.PERMISSION_DENIED, f"Certificate {active_cert.SerialNumber} has been revoked mid-stream")
                            return

        except Exception as e:
            logger.error(f"[mTLS gRPC Gateway] Error processing stream from '{client_cn}': {e}")
            return telemetry_pb2.StreamResponse(
                success=False,
                events_processed=events_processed,
                message=str(e)
            )

        logger.info(f"[{GATEWAY_INSTANCE_ID}] [mTLS gRPC Gateway] Stream closed for '{client_cn}'. Processed {events_processed} telemetry events.")
        return telemetry_pb2.StreamResponse(
            success=True,
            events_processed=events_processed,
            message=f"Mutual TLS telemetry stream processed successfully by {GATEWAY_INSTANCE_ID}"
        )

async def serve():
    logger.info(f"[{GATEWAY_INSTANCE_ID}] Initializing Hierarchical PKI credentials...")
    ca_service.initialize_pki()

    server_key, server_chain = ca_service.get_server_credentials()
    ca_chain_pem = ca_service.get_ca_cert_pem().encode("utf-8")

    server_creds = grpc.ssl_server_credentials(
        [(server_key, server_chain)],
        root_certificates=ca_chain_pem,
        require_client_auth=True  # STRICT MUTUAL TLS: Client certificate mandatory
    )

    # Connect to Kafka
    await kafka_client.connect()

    server_options = [
        ("grpc.max_concurrent_streams", 250),
        ("grpc.max_receive_message_length", 100 * 1024 * 1024),
        ("grpc.max_send_message_length", 100 * 1024 * 1024),
        ("grpc.keepalive_time_ms", 30000),
        ("grpc.keepalive_timeout_ms", 10000),
        ("grpc.keepalive_permit_without_calls", True),
        ("grpc.http2.max_pings_without_data", 0),
    ]

    server = grpc.aio.server(options=server_options)
    telemetry_pb2_grpc.add_TelemetryGatewayServicer_to_server(TelemetryGatewayServicer(), server)

    # Register standard gRPC Health Checking
    if HEALTH_CHECKING_AVAILABLE:
        health_servicer = health.aio.HealthServicer()
        health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
        await health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)
        await health_servicer.set("TelemetryGateway", health_pb2.HealthCheckResponse.SERVING)
        logger.info(f"[{GATEWAY_INSTANCE_ID}] Health checking service registered (Status: SERVING)")

    # STRICT: Bind ONLY to secure mTLS port (Insecure port 50051 completely eliminated)
    port = '[::]:50051'
    server.add_secure_port(port, server_creds)

    logger.info(f"[{GATEWAY_INSTANCE_ID}] Hardened Mutual TLS listener active on {port} (max_concurrent_streams=250)")
    await server.start()
    await server.wait_for_termination()

if __name__ == '__main__':
    asyncio.run(serve())
