import asyncio
import json
import logging
import os
import sys
import aiohttp
import socket

# Setup basic logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("UniversalForwarder")

CONFIG_PATH = os.environ.get("FORWARDER_CONFIG_PATH", "forwarder_config.json")

# Default single destination if no config file is found (for backwards compatibility)
DEFAULT_DESTINATIONS = [
    {
        "name": "Default",
        "base_url": os.environ.get("DESTINATION_BASE_URL", "http://localhost:8000"),
        "api_key": os.environ.get("DESTINATION_API_KEY", "mntx_fallback_key"),
        "tenant_id": os.environ.get("TENANT_ID", "T-DEFAULT")
    }
]

# Webhook Endpoint mappings relative to base_url
ENDPOINTS = {
    "asset_registration": "/api/v1/assets/sdk/monitorix",
    "fim": "/api/v1/integrations/monitorix/fim",
    "malware": "/api/v1/integrations/monitorix/malware",
    "network_anomaly": "/api/v1/integrations/monitorix/network-anomalies",
    "process_anomaly": "/api/v1/integrations/monitorix/process-anomalies",
    "auth_anomaly": "/api/v1/integrations/monitorix/auth-anomalies"
}

SOCKET_PATH = "/tmp/monitorix_sdk.sock"

def load_destinations():
    """Load destinations from JSON config, falling back to ENV vars."""
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                config = json.load(f)
                return config.get("destinations", DEFAULT_DESTINATIONS)
        except Exception as e:
            logger.error(f"Failed to load config {CONFIG_PATH}: {e}")
            return DEFAULT_DESTINATIONS
    return DEFAULT_DESTINATIONS

async def register_asset_to_destination(session, dest):
    """Register the asset to a specific destination."""
    url = f"{dest['base_url']}{ENDPOINTS['asset_registration']}"
    payload = {
        "hostname": socket.gethostname(),
        "ip_address": socket.gethostbyname(socket.gethostname()),
        "os_type": sys.platform
    }
    
    headers = {
        "X-Monitorix-SDK-Key": dest['api_key'],
        "X-Tenant-ID": dest['tenant_id'],
        "Content-Type": "application/json"
    }

    try:
        async with session.post(url, json=payload, headers=headers) as resp:
            if resp.status in (200, 201):
                logger.info(f"Registered asset to {dest['name']}")
            else:
                logger.warning(f"Registration to {dest['name']} returned status {resp.status}")
    except Exception as e:
        logger.error(f"Failed to register to {dest['name']}: {e}")

async def register_asset_all(session, destinations):
    """Register asset on all configured destinations concurrently."""
    tasks = [register_asset_to_destination(session, dest) for dest in destinations]
    await asyncio.gather(*tasks)

async def forward_event_to_destination(session, dest, event_type, data, endpoint_key):
    """Forward an event to a single destination."""
    url = f"{dest['base_url']}{ENDPOINTS[endpoint_key]}"
    headers = {
        "X-Monitorix-SDK-Key": dest['api_key'],
        "X-Tenant-ID": dest['tenant_id'],
        "Content-Type": "application/json"
    }

    try:
        async with session.post(url, json=data, headers=headers) as resp:
            if resp.status not in (200, 201, 202):
                logger.warning(f"Failed to forward {event_type} to {dest['name']} - Status: {resp.status}")
            else:
                logger.debug(f"Forwarded {event_type} to {dest['name']} successfully.")
    except Exception as e:
        logger.error(f"Error forwarding {event_type} to {dest['name']}: {e}")

async def forward_event_all(session, destinations, event_type, data):
    """Forward an event to all destinations."""
    type_to_endpoint_key = {
        "fim_event": "fim",
        "malware_alert": "malware",
        "network_anomaly": "network_anomaly",
        "process_anomaly": "process_anomaly",
        "auth_anomaly": "auth_anomaly"
    }
    
    endpoint_key = type_to_endpoint_key.get(event_type)
    if not endpoint_key:
        return
        
    tasks = [forward_event_to_destination(session, dest, event_type, data, endpoint_key) for dest in destinations]
    await asyncio.gather(*tasks)

async def process_stream():
    """Connect to the Monitorix local socket and process the event stream."""
    destinations = load_destinations()
    logger.info(f"Loaded {len(destinations)} destination(s).")
    
    while True:
        try:
            if not os.path.exists(SOCKET_PATH):
                logger.error(f"Socket {SOCKET_PATH} does not exist. Retrying in 5 seconds...")
                await asyncio.sleep(5)
                continue

            reader, writer = await asyncio.open_unix_connection(SOCKET_PATH)
            logger.info(f"Connected to Monitorix SDK socket at {SOCKET_PATH}")

            async with aiohttp.ClientSession() as session:
                # Register asset immediately upon connection
                await register_asset_all(session, destinations)

                while True:
                    line = await reader.readline()
                    if not line:
                        logger.warning("Connection closed by server.")
                        break
                        
                    try:
                        event = json.loads(line.decode().strip())
                        event_type = event.get("event_type")
                        data = event.get("data", {})
                        
                        if event_type:
                            await forward_event_all(session, destinations, event_type, data)
                    except json.JSONDecodeError:
                        logger.error("Failed to decode event JSON.")
                        continue
                        
        except asyncio.CancelledError:
            logger.info("Shutting down forwarder...")
            break
        except Exception as e:
            logger.error(f"Connection error: {e}. Retrying in 5 seconds...")
            await asyncio.sleep(5)

if __name__ == "__main__":
    logger.info("Starting Universal Forwarder Agent (Multi-Destination)...")
    try:
        asyncio.run(process_stream())
    except KeyboardInterrupt:
        logger.info("Universal Forwarder stopped by user.")
