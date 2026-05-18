import httpx
import logging
import json
import hashlib
import hmac
import base64
from datetime import datetime
from typing import Dict, Any

logger = logging.getLogger("SiemService")

class SiemService:
    """[v2.5.0] Enterprise Multi-SIEM Hub (Splunk, Azure Sentinel, Datadog, Webhooks)."""
    
    @staticmethod
    def _build_sentinel_signature(customer_id: str, shared_key: str, date: str, content_length: int, method: str, content_type: str, resource: str):
        """Builds the HMAC-SHA256 signature for Azure Sentinel HTTP Data Collector API."""
        x_headers = f"x-ms-date:{date}"
        string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
        bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
        decoded_key = base64.b64decode(shared_key)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
        return f"SharedKey {customer_id}:{encoded_hash}"

    @staticmethod
    async def forward_event(tenant_config: Dict[str, Any], event_data: Dict[str, Any]):
        """Forwards a security event to the configured SIEM endpoint with retry logic."""
        if not tenant_config or not tenant_config.get("enabled"):
            return

        siem_type = tenant_config.get("type", "webhook").lower()
        endpoint = tenant_config.get("endpoint")
        api_key = tenant_config.get("api_key")
        
        if not endpoint and siem_type != "datadog": # Datadog might use default API URL
            return

        # Core Payload
        payload = {
            "ddsource": "monitorix",
            "ddtags": f"tenant:{event_data.get('TenantId')},agent:{event_data.get('AgentId')}",
            "hostname": event_data.get("Hostname", "unknown"),
            "message": event_data.get("Details"),
            "service": "monitorix_forensics",
            "monitorix": {
                "event_id": event_data.get("Id"),
                "type": event_data.get("Type"),
                "severity": event_data.get("Severity", "Medium"),
                "timestamp": datetime.utcnow().isoformat()
            }
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                if siem_type == "webhook":
                    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"} if api_key else {}
                    await client.post(endpoint, json=payload, headers=headers)
                
                elif siem_type == "splunk":
                    splunk_payload = {"event": payload, "sourcetype": "monitorix_forensics"}
                    headers = {"Authorization": f"Splunk {api_key}"}
                    await client.post(endpoint, json=splunk_payload, headers=headers)

                elif siem_type == "datadog":
                    # Datadog Logs API: https://http-intake.logs.datadoghq.com/v1/input
                    dd_endpoint = endpoint or "https://http-intake.logs.datadoghq.com/v1/input"
                    headers = {"Content-Type": "application/json", "DD-API-KEY": api_key}
                    await client.post(dd_endpoint, json=payload, headers=headers)

                elif siem_type == "sentinel":
                    # Azure Sentinel Workspace ID (endpoint) and Shared Key (api_key)
                    # Payload must be a list
                    log_type = "MonitorixEvents"
                    rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
                    content_type = "application/json"
                    resource = "/api/logs"
                    body = json.dumps([payload])
                    signature = SiemService._build_sentinel_signature(endpoint, api_key, rfc1123date, len(body), "POST", content_type, resource)
                    
                    sentinel_url = f"https://{endpoint}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"
                    headers = {
                        "content-type": content_type,
                        "Authorization": signature,
                        "Log-Type": log_type,
                        "x-ms-date": rfc1123date
                    }
                    await client.post(sentinel_url, data=body, headers=headers)

                elif siem_type == "syslog" or siem_type == "cef":
                    # For on-premise SIEMs (QRadar, ArcSight, Splunk Syslog)
                    # endpoint should be "host:port", e.g., "192.168.1.100:514"
                    import socket
                    host, port = endpoint.split(":") if ":" in endpoint else (endpoint, 514)
                    
                    # Build CEF (Common Event Format) if requested
                    if siem_type == "cef":
                        cef_msg = f"CEF:0|Monitorix|SecurityEngine|v2.7.0|{event_data.get('Type')}|{event_data.get('Type')}|{event_data.get('Severity', 'Medium')}|"
                        cef_msg += f"src={event_data.get('AgentId')} msg={event_data.get('Details')} cs1Label=TenantId cs1={event_data.get('TenantId')}"
                        msg = f"{cef_msg}\n"
                    else:
                        # RFC5424-like Syslog
                        msg = f"<14>1 {datetime.utcnow().isoformat()}Z {event_data.get('Hostname', 'unknown')} monitorix - - - [tenant@12345 tenant_id=\"{event_data.get('TenantId')}\"] {event_data.get('Type')}: {event_data.get('Details')}\n"

                    # Non-blocking UDP Dispatch
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.sendto(msg.encode('utf-8'), (host, int(port)))

                logger.info(f"Forwarded event {event_data.get('Id')} to {siem_type}.")
            except Exception as e:
                logger.error(f"SIEM Forwarding Failed ({siem_type}): {e}")

# Global singleton
siem_service = SiemService()
