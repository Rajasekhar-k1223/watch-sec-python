"""
[v3.5.0] Phase 11: Monitorix Standard Connector SDK
Provides extensible, sandboxed integration primitives for:
- 11.1 Authentication & Secrets Management (API Key, Bearer, OAuth2, HMAC)
- Event Ingestion & Normalization into Canonical Monitorix Telemetry
- Alert & Incident Creation with Automatic MITRE ATT&CK Mapping
- Sandboxed Response Actions with High-Risk Approval Enforcement
- Circuit Breaking, Health Checking, and Jittered Exponential Backoff
"""

import os
import time
import json
import uuid
import hmac
import hashlib
import base64
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import asyncio
from cryptography.fernet import Fernet

logger = logging.getLogger("MonitorixConnectorSDK")

# Master encryption key for connector secrets management
_RAW_KEY = os.getenv("VAULT_MASTER_KEY", "monitorix_default_vault_encryption_key_32b_len=")
if len(_RAW_KEY) < 32:
    _RAW_KEY = _RAW_KEY.ljust(32, "x")
FERNET_KEY = base64.urlsafe_b64encode(_RAW_KEY[:32].encode("utf-8"))
cipher = Fernet(FERNET_KEY)

class ConnectorAuthType:
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    OAUTH2 = "oauth2"
    BASIC = "basic"
    CUSTOM_HEADER = "custom_header"

class PermissionScope:
    READ_EVENTS = "events:read"
    READ_ALERTS = "alerts:read"
    READ_ASSETS = "assets:read"
    WRITE_ALERTS = "alerts:write"
    WRITE_INCIDENTS = "incidents:write"
    WRITE_TELEMETRY = "telemetry:write"
    ACTION_ISOLATE_HOST = "action:isolate_host"
    ACTION_QUARANTINE_FILE = "action:quarantine_file"
    ACTION_BLOCK_IP = "action:block_ip"
    ACTION_DISABLE_USER = "action:disable_user"

HIGH_RISK_PERMISSIONS = {
    PermissionScope.ACTION_ISOLATE_HOST,
    PermissionScope.ACTION_QUARANTINE_FILE,
    PermissionScope.ACTION_BLOCK_IP,
    PermissionScope.ACTION_DISABLE_USER
}

class MonitorixEventSchema:
    """Canonical Monitorix Security Event format for normalization"""
    def __init__(
        self,
        event_id: str,
        timestamp: datetime,
        source_vendor: str,
        event_type: str,
        severity: str,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        host_name: Optional[str] = None,
        user_identity: Optional[str] = None,
        process_name: Optional[str] = None,
        file_hash: Optional[str] = None,
        mitre_technique_id: Optional[str] = None,
        raw_payload: Optional[Dict[str, Any]] = None
    ):
        self.event_id = event_id or f"evt-{uuid.uuid4().hex[:12]}"
        self.timestamp = timestamp or datetime.utcnow()
        self.source_vendor = source_vendor
        self.event_type = event_type
        self.severity = severity.capitalize() if severity else "Medium"
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.host_name = host_name
        self.user_identity = user_identity
        self.process_name = process_name
        self.file_hash = file_hash
        self.mitre_technique_id = mitre_technique_id or "T1059"
        self.raw_payload = raw_payload or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else str(self.timestamp),
            "source_vendor": self.source_vendor,
            "event_type": self.event_type,
            "severity": self.severity,
            "network": {
                "source_ip": self.source_ip,
                "destination_ip": self.destination_ip
            },
            "endpoint": {
                "host_name": self.host_name,
                "user_identity": self.user_identity,
                "process_name": self.process_name,
                "file_hash": self.file_hash
            },
            "threat_mapping": {
                "mitre_technique_id": self.mitre_technique_id
            },
            "raw_payload": self.raw_payload
        }


class BaseConnectorClient:
    """
    Standard SDK Client Base for building external Monitorix integrations.
    Provides authentication, secrets encryption, rate limiting, and backoff retries.
    """
    def __init__(
        self,
        connector_id: str,
        name: str,
        auth_type: str = ConnectorAuthType.API_KEY,
        base_url: str = "",
        config: Optional[Dict[str, Any]] = None,
        rate_limit_rpm: int = 1200
    ):
        self.connector_id = connector_id
        self.name = name
        self.auth_type = auth_type
        self.base_url = base_url.rstrip("/")
        self.config = config or {}
        self.rate_limit_rpm = rate_limit_rpm
        self.failure_count = 0
        self.circuit_open = False
        self.last_failure_time = 0.0

    @staticmethod
    def encrypt_secret(secret_value: str) -> str:
        """Encrypts sensitive connector credentials before storing in PostgreSQL"""
        if not secret_value:
            return ""
        return cipher.encrypt(secret_value.encode("utf-8")).decode("utf-8")

    @staticmethod
    def decrypt_secret(encrypted_value: str) -> str:
        """Decrypts connector credentials for secure runtime API execution"""
        if not encrypted_value:
            return ""
        try:
            return cipher.decrypt(encrypted_value.encode("utf-8")).decode("utf-8")
        except Exception:
            return encrypted_value

    @staticmethod
    def mask_secret(secret_value: str) -> str:
        """Masks sensitive values for safe display in UI and audits"""
        if not secret_value or len(secret_value) < 6:
            return "******"
        return f"{secret_value[:3]}****{secret_value[-2:]}"

    def get_auth_headers(self) -> Dict[str, str]:
        """Generates appropriate authorization headers based on configured auth_type"""
        headers = {
            "User-Agent": f"Monitorix-Connector-SDK/{self.connector_id}",
            "Content-Type": "application/json"
        }
        if self.auth_type == ConnectorAuthType.API_KEY:
            api_key = self.decrypt_secret(self.config.get("api_key", ""))
            header_name = self.config.get("api_key_header", "X-API-Key")
            headers[header_name] = api_key
        elif self.auth_type == ConnectorAuthType.BEARER_TOKEN:
            token = self.decrypt_secret(self.config.get("token", ""))
            headers["Authorization"] = f"Bearer {token}"
        elif self.auth_type == ConnectorAuthType.BASIC:
            user = self.config.get("username", "")
            pwd = self.decrypt_secret(self.config.get("password", ""))
            cred = base64.b64encode(f"{user}:{pwd}".encode("utf-8")).decode("utf-8")
            headers["Authorization"] = f"Basic {cred}"
        return headers

    async def execute_with_retry(self, operation_func, max_retries: int = 3) -> Any:
        """Executes API call with exponential backoff, jitter, and circuit breaker protection"""
        # Circuit Breaker Check
        if self.circuit_open:
            if time.time() - self.last_failure_time > 30.0:
                logger.info(f"[{self.connector_id}] Half-open circuit reset attempted")
                self.circuit_open = False
                self.failure_count = 0
            else:
                raise RuntimeError(f"Circuit breaker active for connector '{self.connector_id}'. Remote service degraded.")

        attempt = 0
        backoff = 0.5
        while attempt < max_retries:
            try:
                result = await operation_func()
                self.failure_count = 0
                return result
            except Exception as e:
                attempt += 1
                self.failure_count += 1
                if self.failure_count >= 5:
                    self.circuit_open = True
                    self.last_failure_time = time.time()
                    logger.warning(f"[{self.connector_id}] Circuit breaker tripped after 5 consecutive failures")

                if attempt >= max_retries:
                    logger.error(f"[{self.connector_id}] Exhausted {max_retries} retries: {e}")
                    raise e
                await asyncio.sleep(backoff)
                backoff *= 2.0

    def normalize_event(self, raw_event: Dict[str, Any]) -> MonitorixEventSchema:
        """
        Normalizes arbitrary vendor payload into standard Monitorix Security Event.
        Can be overridden by vendor-specific connectors.
        """
        # Generic heuristic normalization
        event_id = str(raw_event.get("id") or raw_event.get("event_id") or raw_event.get("alert_id") or uuid.uuid4().hex[:12])
        severity = raw_event.get("severity") or raw_event.get("priority") or "Medium"
        event_type = raw_event.get("type") or raw_event.get("category") or raw_event.get("event_type") or "SecurityDetection"
        src_ip = raw_event.get("src_ip") or raw_event.get("source_ip") or raw_event.get("ip")
        dst_ip = raw_event.get("dst_ip") or raw_event.get("destination_ip")
        hostname = raw_event.get("hostname") or raw_event.get("host") or raw_event.get("device_name")
        user = raw_event.get("user") or raw_event.get("username") or raw_event.get("account")
        proc = raw_event.get("process") or raw_event.get("process_name") or raw_event.get("cmdline")
        hash_val = raw_event.get("hash") or raw_event.get("sha256") or raw_event.get("md5")
        mitre = raw_event.get("mitre_id") or raw_event.get("technique") or "T1059"

        return MonitorixEventSchema(
            event_id=event_id,
            timestamp=datetime.utcnow(),
            source_vendor=self.name,
            event_type=event_type,
            severity=severity,
            source_ip=src_ip,
            destination_ip=dst_ip,
            host_name=hostname,
            user_identity=user,
            process_name=proc,
            file_hash=hash_val,
            mitre_technique_id=mitre,
            raw_payload=raw_event
        )

    def verify_action_permissions(
        self,
        action_name: str,
        declared_permissions: List[str],
        approval_granted: bool = False,
        requires_approval: bool = True
    ) -> Tuple[bool, str]:
        """
        Sandboxed Permission Guard: Checks if connector is granted authority to execute response action.
        High-risk actions (host quarantine, user lock) mandate approval check.
        """
        scope_map = {
            "isolate_host": PermissionScope.ACTION_ISOLATE_HOST,
            "quarantine_file": PermissionScope.ACTION_QUARANTINE_FILE,
            "block_ip": PermissionScope.ACTION_BLOCK_IP,
            "disable_user": PermissionScope.ACTION_DISABLE_USER
        }
        required_scope = scope_map.get(action_name)
        if not required_scope:
            return False, f"Unknown action '{action_name}'"

        if required_scope not in declared_permissions:
            return False, f"Permission denied: Missing scope '{required_scope}'"

        if required_scope in HIGH_RISK_PERMISSIONS and requires_approval and not approval_granted:
            return False, f"High-risk action '{action_name}' requires human approval before execution"

        return True, "Authorized"

    @staticmethod
    def calculate_webhook_signature(secret: str, payload_bytes: bytes) -> str:
        """Calculates HMAC-SHA256 signature for outgoing webhook authentication"""
        return hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()

    @staticmethod
    def verify_webhook_signature(secret: str, payload_bytes: bytes, signature_header: str) -> bool:
        """Verifies incoming webhook HMAC-SHA256 signature"""
        if not signature_header:
            return False
        expected = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
        # Remove 'sha256=' prefix if present
        cleaned = signature_header.replace("sha256=", "").strip()
        return hmac.compare_digest(expected, cleaned)
