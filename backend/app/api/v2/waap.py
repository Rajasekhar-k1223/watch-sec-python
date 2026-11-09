"""
[v18.3.0] Monitorix WAAP API Router (Web Application & API Protection)
======================================================================
API Endpoints:
- GET  /api/v2/waap/overview       - Defense health score, total requests, blocked attacks breakdown
- GET  /api/v2/waap/rules          - WAF rules (OWASP Top 10, CRS, Rate Limits)
- GET  /api/v2/waap/events         - Intercepted HTTP attack events stream
- GET  /api/v2/waap/endpoints      - Monitored API endpoints and BOLA/IDOR posture
- GET  /api/v2/waap/ip-reputation  - Threat IP reputation and blocklist
- POST /api/v2/waap/inspect        - Real-time HTTP request inspection against WAF signatures
- POST /api/v2/waap/rules/toggle   - Enable/disable rules or update action (BLOCK/CHALLENGE/LOG)
- POST /api/v2/waap/ip-block       - 1-click active blocking of malicious client IP
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Body, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

from app.db.session import get_db
from app.services.waap_service import MonitorixWaapService

router = APIRouter()

# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class InspectHttpRequest(BaseModel):
    client_ip: Optional[str] = Field(default="127.0.0.1", example="198.51.100.77")
    method: Optional[str] = Field(default="GET", example="GET")
    uri: str = Field(..., example="/api/v1/search?q=test' UNION SELECT username,password FROM users--")
    body: Optional[str] = Field(default="", example="")
    user_agent: Optional[str] = Field(default="Mozilla/5.0", example="sqlmap/1.5.2#stable")

class ToggleRuleRequest(BaseModel):
    rule_id: str = Field(..., example="RULE-SQLI-01")
    is_enabled: bool = Field(default=True)
    action: Optional[str] = Field(default="BLOCK", example="BLOCK")

class BlockIpRequest(BaseModel):
    ip_address: str = Field(..., example="198.51.100.99")
    reason: str = Field(default="Manual SOC block", example="Repeated SQLi attack attempts")
    threat_category: Optional[str] = Field(default="MANUAL_BLOCK", example="MANUAL_BLOCK")

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/overview")
async def get_waap_overview(db: AsyncSession = Depends(get_db)):
    """Retrieve WAAP defense score, total inspected requests, and attack breakdown."""
    return await MonitorixWaapService.get_overview(db)

@router.get("/rules")
async def get_waap_rules(
    category: Optional[str] = Query(None, description="SQLI, XSS, RCE_COMMAND_INJECTION, SSRF, PATH_TRAVERSAL, API_BOLA, BOT_RATE_LIMIT"),
    is_enabled: Optional[bool] = Query(None, description="Filter active/disabled rules"),
    db: AsyncSession = Depends(get_db)
):
    """List configured WAF inspection rules."""
    return await MonitorixWaapService.get_rules(
        db,
        category=category,
        is_enabled=is_enabled
    )

@router.get("/events")
async def get_waap_events(
    attack_type: Optional[str] = Query(None, description="SQLI, XSS, RCE, SSRF, PATH_TRAVERSAL, API_BOLA, BRUTE_FORCE"),
    action_taken: Optional[str] = Query(None, description="BLOCKED, LOGGED, CHALLENGED"),
    limit: int = Query(50, description="Max events to return"),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve intercepted HTTP security events stream."""
    return await MonitorixWaapService.get_events(
        db,
        attack_type=attack_type,
        action_taken=action_taken,
        limit=limit
    )

@router.get("/endpoints")
async def get_waap_endpoints(
    min_risk: Optional[float] = Query(None, description="Minimum risk score filter"),
    auth_type: Optional[str] = Query(None, description="BEARER_JWT, API_KEY, MUTUAL_TLS, NONE"),
    db: AsyncSession = Depends(get_db)
):
    """List monitored API endpoints and OWASP API authorization posture."""
    return await MonitorixWaapService.get_endpoints(
        db,
        min_risk=min_risk,
        auth_type=auth_type
    )

@router.get("/ip-reputation")
async def get_waap_ip_reputation(
    is_blocked_only: Optional[bool] = Query(None, description="Filter actively blocked IPs"),
    db: AsyncSession = Depends(get_db)
):
    """List threat actor IP reputation and perimeter ban list."""
    return await MonitorixWaapService.get_ip_reputation(
        db,
        is_blocked_only=is_blocked_only
    )

@router.post("/inspect")
async def inspect_http_request(
    req: InspectHttpRequest,
    db: AsyncSession = Depends(get_db)
):
    """Inspect incoming HTTP/API request against active WAF regex signatures."""
    return await MonitorixWaapService.inspect_http_request(db, req.dict())

@router.post("/rules/toggle")
async def toggle_waap_rule(
    req: ToggleRuleRequest,
    db: AsyncSession = Depends(get_db)
):
    """Enable or disable a WAF rule or modify enforcement action."""
    return await MonitorixWaapService.toggle_rule(db, req.rule_id, req.is_enabled, req.action)

@router.post("/ip-block")
async def block_malicious_ip(
    req: BlockIpRequest,
    db: AsyncSession = Depends(get_db)
):
    """Manually add an IP address to the active perimeter WAF ban list."""
    return await MonitorixWaapService.block_ip(db, req.ip_address, req.reason, req.threat_category)
