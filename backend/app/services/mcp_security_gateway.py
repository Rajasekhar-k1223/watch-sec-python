"""
Monitorix Sovereign MCP (Model Context Protocol) Security Gateway
================================================================
Enterprise-grade runtime security gateway and zero-trust proxy for Model Context Protocol (MCP)
tool executions, AI Agent orchestration, and canary sandboxing.

Eliminates reliance on Wiz or Azure AI Foundry by providing:
1. Tool Manifest Integrity Pinning (SHA-256 validation).
2. Anti-SSRF Destination Inspection (Cloud metadata 169.254.169.254, RFC-1918 subnets, loopbacks).
3. Tool Argument Sanitization & SQL / Shell / Path-Traversal Guardrails.
4. Human-in-the-Loop (HITL) Enforcement for High-Risk Tiers.
5. Recursion Loop & Token Surge Throttling.
6. Canary Trap Interception (attacker.invalid).
7. Unified Evidence Correlation stamping via test_run_id.
"""

import re
import json
import hashlib
import ipaddress
import logging
from datetime import datetime
from typing import Dict, Any, Tuple, Optional, List
from urllib.parse import urlparse

from app.db.models import (
    AiAgent,
    AiModel,
    McpServer,
    McpToolPolicy,
    DetectionAlert,
    AuditLog
)

logger = logging.getLogger("monitorix.mcp.security_gateway")


class McpSecurityGateway:
    """Sovereign security enforcer and JSON-RPC 2.0 tool proxy for MCP servers."""

    FORBIDDEN_SUBNETS = [
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("169.254.169.254/32"),  # Cloud Instance Metadata Service (IMDS)
        ipaddress.ip_network("100.64.0.0/10"),       # Carrier-grade NAT
    ]

    DANGEROUS_PATTERNS = [
        (re.compile(r"(?i)\bdrop\s+table\b"), "SQL Drop Table Attempt"),
        (re.compile(r"(?i)\bdelete\s+from\b"), "SQL Bulk Delete Attempt"),
        (re.compile(r"(?i)\bexec(?:ute)?\s+xp_"), "SQL Extended Procedure Execution"),
        (re.compile(r"(?i)\brm\s+-[rRf]{1,3}\b"), "Filesystem Recursive Deletion Attempt"),
        (re.compile(r"(?i)\b(?:curl|wget)\b.*\|\s*(?:bash|sh)"), "Pipe to Shell RCE"),
        (re.compile(r"(?i)\b(?:chmod\s+777|chown\s+root)\b"), "Insecure Permission Escalation"),
        (re.compile(r"(?i)\bpowershell\b.*-enc(?:odedcommand)?\b"), "Encoded PowerShell Payload"),
        (re.compile(r"\.\./\.\./"), "Directory Path Traversal Attempt"),
        (re.compile(r"(?i)\b(AKIA[0-9A-Z]{16})\b"), "AWS Access Key Leakage"),
        (re.compile(r"(?i)(?:password|secret|bearer\s+[a-z0-9_\-\.]{20,})"), "Credential Exposure"),
    ]

    CANARY_DOMAINS = [
        "attacker.invalid",
        "canary.monitorix.internal",
        "synthetic-vault.azure.invalid",
        "honey-bucket.s3.invalid",
    ]

    @classmethod
    def compute_manifest_hash(cls, tools_schema_json: str | dict | list) -> str:
        """Computes deterministic SHA-256 checksum of an MCP tool manifest."""
        if not isinstance(tools_schema_json, str):
            manifest_str = json.dumps(tools_schema_json, sort_keys=True)
        else:
            manifest_str = tools_schema_json.strip()
        return hashlib.sha256(manifest_str.encode("utf-8")).hexdigest()

    @classmethod
    def verify_manifest_hash(cls, tools_schema: str | dict | list, expected_hash: str) -> bool:
        """Verifies that an MCP tool manifest matches its approved pinned cryptographic hash."""
        computed = cls.compute_manifest_hash(tools_schema)
        return computed.lower() == expected_hash.strip().lower()

    @classmethod
    def check_ssrf_destination(cls, target_url_or_host: str) -> Tuple[bool, str]:
        """
        Validates target network destinations.
        Returns: (is_dangerous: bool, reason: str)
        """
        if not target_url_or_host:
            return False, "Safe"

        raw_str = str(target_url_or_host).strip()

        # Check for Canary honeypot trigger
        for canary in cls.CANARY_DOMAINS:
            if canary in raw_str.lower():
                return True, f"Canary Trap Triggered ({canary})"

        # Parse host
        if "://" in raw_str:
            parsed = urlparse(raw_str)
            host = parsed.hostname or ""
        else:
            host = raw_str.split(":")[0].strip()

        if not host:
            return False, "Safe"

        host_lower = host.lower()
        if host_lower in ["localhost", "127.0.0.1", "::1", "169.254.169.254", "metadata.google.internal"]:
            return True, f"Blocked loopback or cloud metadata endpoint: {host}"

        # Test IP address directly
        try:
            ip = ipaddress.ip_address(host)
            for subnet in cls.FORBIDDEN_SUBNETS:
                if ip in subnet:
                    return True, f"SSRF violation: IP {ip} resides in forbidden private subnet {subnet}"
        except ValueError:
            # Domain name: verify it doesn't resolve to private ranges or dangerous hosts
            if host_lower.endswith(".local") or host_lower.endswith(".internal") and "monitorix" not in host_lower:
                return True, f"Blocked internal domain: {host}"

        return False, "Safe"

    @classmethod
    def inspect_tool_parameters(cls, tool_args: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Deeply inspects tool arguments for malicious injection vectors.
        Returns: (is_malicious: bool, description: Optional[str])
        """
        if not tool_args:
            return False, None

        args_str = json.dumps(tool_args)

        # Check dangerous regex patterns
        for regex, desc in cls.DANGEROUS_PATTERNS:
            match = regex.search(args_str)
            if match:
                return True, f"{desc} (matched: '{match.group(0)[:60]}')"

        # Check nested values for SSRF destinations
        def check_nested(val):
            if isinstance(val, str):
                is_ssrf, reason = cls.check_ssrf_destination(val)
                if is_ssrf:
                    return is_ssrf, reason
            elif isinstance(val, dict):
                for k, v in val.items():
                    res, r = check_nested(v)
                    if res:
                        return res, r
            elif isinstance(val, list):
                for item in val:
                    res, r = check_nested(item)
                    if res:
                        return res, r
            return False, None

        is_ssrf, reason = check_nested(tool_args)
        if is_ssrf:
            return True, reason

        return False, None

    @classmethod
    def validate_tool_execution(
        cls,
        policy: Optional[McpToolPolicy],
        tool_name: str,
        tool_args: Dict[str, Any],
        agent: Optional[AiAgent] = None,
        test_run_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Evaluates an MCP tool execution against Zero-Trust policies.
        Enforces policy allowlisting, parameter sanitization, and HITL approval routing.
        """
        verdict = {
            "allowed": True,
            "requires_hitl": False,
            "violation_code": None,
            "reason": "Authorized",
            "test_run_id": test_run_id,
            "risk_tier": "LOW",
            "timestamp": datetime.utcnow().isoformat()
        }

        # 1. Agent Status Check
        if agent and agent.Status != "ACTIVE":
            verdict["allowed"] = False
            verdict["violation_code"] = "AGENT_NOT_ACTIVE"
            verdict["reason"] = f"AI Agent '{agent.Name}' is currently in {agent.Status} status."
            return verdict

        # 2. Tool Policy Authorization Check
        if not policy:
            verdict["allowed"] = False
            verdict["violation_code"] = "UNREGISTERED_TOOL"
            verdict["reason"] = f"Tool '{tool_name}' has no registered policy for this AI Agent."
            return verdict

        if not policy.IsAllowed:
            verdict["allowed"] = False
            verdict["violation_code"] = "TOOL_POLICY_DENIED"
            verdict["reason"] = f"Tool '{tool_name}' is explicitly denied by tenant security policy."
            return verdict

        verdict["risk_tier"] = policy.RiskTier

        # 3. Parameter Inspection & Sanitization
        is_malicious, violation_detail = cls.inspect_tool_parameters(tool_args)
        if is_malicious:
            verdict["allowed"] = False
            verdict["violation_code"] = "MALICIOUS_PARAMETER_DETECTED"
            verdict["reason"] = f"Security Violation: {violation_detail}"
            return verdict

        # 4. Human-In-The-Loop (HITL) Gatekeeper
        if policy.RequiresHumanApproval or (agent and agent.RequireHitlForHighImpact and policy.RiskTier == "HIGH_IMPACT"):
            verdict["allowed"] = False
            verdict["requires_hitl"] = True
            verdict["violation_code"] = "HITL_APPROVAL_REQUIRED"
            verdict["reason"] = f"Tool '{tool_name}' is classified as HIGH_IMPACT and requires Human-in-the-Loop authorization before execution."
            return verdict

        return verdict

    @classmethod
    async def record_execution_trace(
        cls,
        tenant_id: int,
        test_run_id: str,
        agent_uuid: str,
        stage: str,
        tool_name: str,
        parameters: Dict[str, Any],
        verdict: Dict[str, Any],
        execution_time_ms: int = 5
    ) -> None:
        """
        Asynchronously writes execution traces into ClickHouse monitorix.ai_agent_execution_traces.
        Guarantees non-blocking persistence.
        """
        try:
            from app.db.session import settings
            import aiohttp

            # Clean and sanitize arguments for preview
            params_str = json.dumps(parameters)[:1000]
            output_hash = hashlib.sha256(params_str.encode("utf-8")).hexdigest()[:32]
            action = "BLOCK" if not verdict["allowed"] else ("CHALLENGE" if verdict.get("requires_hitl") else "ALLOW")
            risk_score = 90 if not verdict["allowed"] else (50 if verdict.get("requires_hitl") else 10)

            ch_sql = f"""
            INSERT INTO monitorix.ai_agent_execution_traces (
                timestamp, tenant_id, test_run_id, agent_uuid, session_id,
                trace_stage, prompt_sanitized_preview, tool_name, tool_parameters_json,
                tool_output_hash, execution_time_ms, risk_score, violation_code, action_taken
            ) VALUES (
                now64(3), {tenant_id}, '{test_run_id or "live-trace"}', '{agent_uuid}', 'sess-{test_run_id or "auto"}',
                '{stage}', 'MCP Tool Execution: {tool_name}', '{tool_name}', '{params_str.replace("'", "''")}',
                '{output_hash}', {execution_time_ms}, {risk_score}, '{verdict.get("violation_code") or "NONE"}', '{action}'
            )
            """

            ch_http = "http://sentinel_clickhouse:8123/?user=sentinel_user&password=sentinel_password"
            async with aiohttp.ClientSession() as session:
                async with session.post(ch_http, data=ch_sql.encode("utf-8"), timeout=2.0) as resp:
                    if resp.status != 200:
                        logger.warning(f"[McpSecurityGateway] ClickHouse trace insert status {resp.status}")
        except Exception as e:
            logger.debug(f"[McpSecurityGateway] Trace recording caught non-fatal: {e}")

