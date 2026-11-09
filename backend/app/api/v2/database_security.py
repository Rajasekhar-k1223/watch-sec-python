"""
[v18.7.0] Monitorix Database Security & Activity Monitoring API Router
=====================================================================
Provides RESTful endpoints for:
- GET  /api/v2/database-security/overview          - Database defense score, queries, alerts
- GET  /api/v2/database-security/instances         - Monitored database clusters & instances
- GET  /api/v2/database-security/audit-logs        - Real-time query execution telemetry
- GET  /api/v2/database-security/alerts            - Mass exfiltration & DDL alerts
- POST /api/v2/database-security/inspect-query     - Real-time SQL query security evaluation
- POST /api/v2/database-security/terminate-session - 1-Click rogue DB session termination
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.services.database_security_service import MonitorixDatabaseSecurityService

router = APIRouter()

# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class InspectQueryRequest(BaseModel):
    instance_id: str = Field(default="DB-PG-PROD-PRIMARY", example="DB-PG-PROD-PRIMARY")
    db_user: str = Field(default="app_user", example="analyst_read")
    client_ip: str = Field(default="10.0.1.20", example="198.51.100.99")
    query_text: str = Field(..., example="SELECT * FROM cardholders_master")
    rows_returned: Optional[int] = Field(default=1, example=50000)

class TerminateSessionRequest(BaseModel):
    alert_id: str = Field(..., example="DB-ALERT-001")
    action: Optional[str] = Field(default="KILL_SESSION", example="KILL_SESSION")

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/overview")
async def get_database_security_overview(db: AsyncSession = Depends(get_db)):
    """Retrieve holistic Database Security and DAM telemetry overview."""
    return await MonitorixDatabaseSecurityService.get_overview(db)

@router.get("/instances")
async def get_database_instances(
    engine: Optional[str] = Query(None, description="Filter by engine: POSTGRESQL, MONGODB, MYSQL, REDIS, CLICKHOUSE"),
    db: AsyncSession = Depends(get_db)
):
    """List monitored database clusters, engines, and risk postures."""
    return await MonitorixDatabaseSecurityService.get_instances(db, engine=engine)

@router.get("/audit-logs")
async def get_database_audit_logs(
    instance_id: Optional[str] = Query(None, description="Filter by database instance"),
    is_privileged_only: Optional[bool] = Query(None, description="Filter superuser queries"),
    is_privileged: Optional[bool] = Query(None, description="Filter privileged queries"),
    query_type: Optional[str] = Query(None, description="Filter by SELECT, INSERT, DROP, ALTER"),
    db: AsyncSession = Depends(get_db)
):
    """Stream real-time query audit logs and execution times."""
    priv_filter = is_privileged if is_privileged is not None else is_privileged_only
    return await MonitorixDatabaseSecurityService.get_audit_logs(
        db,
        instance_id=instance_id,
        is_privileged_only=priv_filter,
        query_type=query_type
    )

@router.get("/alerts")
async def get_database_security_alerts(
    severity: Optional[str] = Query(None, description="Filter by CRITICAL, HIGH, MEDIUM"),
    status: Optional[str] = Query(None, description="Filter by OPEN, CONTAINED, DISMISSED"),
    db: AsyncSession = Depends(get_db)
):
    """List database security alerts (exfiltration, suspicious DDL, privilege abuse)."""
    return await MonitorixDatabaseSecurityService.get_alerts(
        db,
        severity=severity,
        status=status
    )

@router.get("/rules")
async def get_database_access_rules(db: AsyncSession = Depends(get_db)):
    """List DAM access control rules and data protection policies."""
    return await MonitorixDatabaseSecurityService.get_rules(db)

@router.post("/inspect-query")
async def inspect_sql_query(
    req: InspectQueryRequest,
    db: AsyncSession = Depends(get_db)
):
    """Real-time inspection of SQL query against DAM security policies."""
    return await MonitorixDatabaseSecurityService.inspect_sql_query(
        db,
        instance_id=req.instance_id,
        db_user=req.db_user,
        client_ip=req.client_ip,
        query_text=req.query_text,
        rows_returned=req.rows_returned or 1
    )

@router.post("/terminate-session")
async def terminate_database_session(
    req: TerminateSessionRequest,
    db: AsyncSession = Depends(get_db)
):
    """1-Click active response to terminate a rogue database session."""
    return await MonitorixDatabaseSecurityService.terminate_session(
        db,
        alert_id=req.alert_id,
        action=req.action or "KILL_SESSION"
    )
