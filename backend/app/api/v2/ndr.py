"""
[v18.10.0] Monitorix Advanced Network Detection & Response (NDR) API (v2)
========================================================================
Exposes sovereign NDR endpoints:
- GET /overview: Network defense score, sensor fleet stats, bandwidth, flow counts
- GET /sensors: Tap probe telemetry, packet capture ring buffer status
- GET /flows: NetFlow / IPFIX connection records with suspicious flag filtering
- GET /threats: C2 beaconing radar, DNS tunneling, and port sweep alerts
- GET /rules: Active behavioral detection rules & mitigation actions
- POST /inspect-traffic: Real-time flow and DNS packet behavioral inspector
- POST /contain-threat: 1-Click active mitigation (BLOCK_IP, KILL_SESSION, SINKHOLE)
"""

import logging
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.services.ndr_service import MonitorixNdrService

router = APIRouter()

# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class InspectTrafficRequest(BaseModel):
    source_ip: str = Field(default="10.0.1.45", example="10.0.1.45")
    destination_ip: str = Field(default="198.51.100.22", example="198.51.100.22")
    destination_port: int = Field(default=443, example=443)
    protocol: Optional[str] = Field(default="TCP", example="TCP")
    query_domain: Optional[str] = Field(default=None, example="data-chunk-01.exfil.c2-proxy.net")
    beacon_interval_sec: Optional[float] = Field(default=None, example=60.0)
    jitter_percent: Optional[float] = Field(default=None, example=0.8)
    ports_scanned_count: Optional[int] = Field(default=None, example=250)

class ContainThreatRequest(BaseModel):
    alert_id: Optional[str] = Field(default=None, example="NDR-ALERT-001")
    source_ip: Optional[str] = Field(default=None, example="10.0.1.45")
    action: Optional[str] = Field(default="BLOCK_IP", example="BLOCK_IP")

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/overview")
async def get_ndr_overview(db: AsyncSession = Depends(get_db)):
    """Retrieve holistic Network Detection & Response overview."""
    return await MonitorixNdrService.get_overview(db)

@router.get("/sensors")
async def get_ndr_sensors(
    location: Optional[str] = Query(None, description="Filter by location: Primary Datacenter, AWS Cloud, DMZ Gateway"),
    db: AsyncSession = Depends(get_db)
):
    """List network sensors, packet capture probe rates, and interface health."""
    return await MonitorixNdrService.get_sensors(db, location=location)

@router.get("/flows")
async def get_ndr_flows(
    sensor_id: Optional[str] = Query(None, description="Filter by sensor probe"),
    is_suspicious: Optional[bool] = Query(None, description="Filter suspicious/flagged flows"),
    protocol: Optional[str] = Query(None, description="Filter by protocol: TCP, UDP, ICMP"),
    db: AsyncSession = Depends(get_db)
):
    """List real-time NetFlow / IPFIX connection stream records."""
    return await MonitorixNdrService.get_flows(
        db,
        sensor_id=sensor_id,
        is_suspicious=is_suspicious,
        protocol=protocol
    )

@router.get("/threats")
async def get_ndr_threats(
    severity: Optional[str] = Query(None, description="Filter by CRITICAL, HIGH, MEDIUM, LOW"),
    status: Optional[str] = Query(None, description="Filter by OPEN, CONTAINED, DISMISSED"),
    db: AsyncSession = Depends(get_db)
):
    """List behavioral network threat detections, C2 radar alerts, and exfiltration."""
    return await MonitorixNdrService.get_threats(
        db,
        severity=severity,
        status=status
    )

@router.get("/rules")
async def get_ndr_rules(db: AsyncSession = Depends(get_db)):
    """List active NDR behavioral rules and automated mitigation policies."""
    return await MonitorixNdrService.get_rules(db)

@router.post("/inspect-traffic")
async def inspect_ndr_traffic(
    req: InspectTrafficRequest,
    db: AsyncSession = Depends(get_db)
):
    """Real-time behavioral traffic inspector analyzing C2 beaconing, DNS tunneling, and port sweeps."""
    return await MonitorixNdrService.inspect_traffic(
        db,
        source_ip=req.source_ip,
        destination_ip=req.destination_ip,
        destination_port=req.destination_port,
        protocol=req.protocol or "TCP",
        query_domain=req.query_domain,
        beacon_interval_sec=req.beacon_interval_sec,
        jitter_percent=req.jitter_percent,
        ports_scanned_count=req.ports_scanned_count
    )

@router.post("/contain-threat")
async def contain_ndr_threat(
    req: ContainThreatRequest,
    db: AsyncSession = Depends(get_db)
):
    """1-Click active network response (IP quarantine, TCP RST session kill, DNS sinkhole)."""
    if not req.alert_id and not req.source_ip:
        raise HTTPException(status_code=400, detail="Must provide either alert_id or source_ip")
    return await MonitorixNdrService.contain_threat(
        db,
        alert_id=req.alert_id,
        source_ip=req.source_ip,
        action=req.action or "BLOCK_IP"
    )
