"""
pg_helpers.py — PostgreSQL optimization helpers for Monitorix FastAPI backend.

Provides async wrappers to:
  - Call SQL Functions  (SELECT fn_name(...))
  - Call Stored Procedures (CALL proc_name(...))
  - Refresh Materialized Views (REFRESH MATERIALIZED VIEW CONCURRENTLY ...)
  - Query Views as ORM-style dicts

All helpers accept an `AsyncSession` from SQLAlchemy and are fully async.

Usage example:
    from app.db.pg_helpers import pg

    # In any async FastAPI endpoint or background task:
    kpis = await pg.call_function(db, "get_tenant_dashboard_kpis", tenant_id, 24)
    await pg.refresh_materialized_views(db)
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from sqlalchemy import text  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_sqlite(db: AsyncSession) -> bool:
    """Detect if the engine is SQLite (local dev) — skip PG-specific features."""
    try:
        url = str(db.bind.url) if db.bind else ""
    except Exception:
        url = ""
    return url.startswith("sqlite")


# ---------------------------------------------------------------------------
# SQL Functions
# ---------------------------------------------------------------------------

async def call_function(
    db: AsyncSession,
    fn_name: str,
    *args: Any,
) -> Any:
    """
    Call a PostgreSQL SQL function and return the result.

    Example:
        result = await call_function(db, "get_tenant_dashboard_kpis", 1, 24)
        # result is a dict (JSON) or list, depending on the function return type

    Falls back to None on SQLite (local dev) — callers should handle None.
    """
    if _is_sqlite(db):
        logger.debug("call_function(%s): skipped — SQLite environment", fn_name)
        return None

    # Build parameterised call: SELECT fn_name(:p0, :p1, ...)
    param_placeholders = ", ".join(f":p{i}" for i in range(len(args)))
    sql = f"SELECT {fn_name}({param_placeholders})"
    params = {f"p{i}": v for i, v in enumerate(args)}

    try:
        result = await db.execute(text(sql), params)
        row = result.fetchone()
        if row is None:
            return None
        value = row[0]
        # Psycopg2/asyncpg return JSON columns as dict/list automatically.
        return value
    except Exception as exc:
        logger.error("call_function(%s, %s) failed: %s", fn_name, args, exc)
        raise


async def get_tenant_dashboard_kpis(
    db: AsyncSession,
    tenant_id: int,
    hours: int = 24,
) -> Optional[dict]:
    """
    Wrapper for get_tenant_dashboard_kpis(tenant_id, hours).

    Returns a dict with keys:
        total_agents, online_agents, offline_agents, avg_cpu, avg_memory,
        total_events, critical_events, high_risk_agents
    """
    return await call_function(db, "get_tenant_dashboard_kpis", tenant_id, hours)


async def get_activity_stats(
    db: AsyncSession,
    agent_id: str,
    hours: int = 24,
) -> Optional[dict]:
    """
    Wrapper for get_activity_stats(agent_id, hours).

    Returns productivity + risk breakdown dict.
    """
    return await call_function(db, "get_activity_stats", agent_id, hours)


async def get_vulnerability_summary(
    db: AsyncSession,
    agent_id: str,
) -> Optional[dict]:
    """
    Wrapper for get_vulnerability_summary(agent_id).

    Returns CVE exposure summary dict.
    """
    return await call_function(db, "get_vulnerability_summary", agent_id)


async def get_agent_threat_summary(
    db: AsyncSession,
    tenant_id: int,
) -> list[dict]:
    """
    Wrapper for get_agent_threat_summary(tenant_id).

    Returns list of {agent_id, hostname, risk_level, threat_score, last_seen}.
    """
    if _is_sqlite(db):
        return []

    try:
        result = await db.execute(
            text("SELECT * FROM get_agent_threat_summary(:tenant_id)"),
            {"tenant_id": tenant_id},
        )
        rows = result.mappings().all()
        return [dict(r) for r in rows]
    except Exception as exc:
        logger.error("get_agent_threat_summary(%s) failed: %s", tenant_id, exc)
        raise


async def get_event_type_histogram(
    db: AsyncSession,
    tenant_id: int,
    hours: int = 24,
) -> Optional[list]:
    """
    Wrapper for get_event_type_histogram(tenant_id, hours).

    Returns list of {Type, count} dicts.
    """
    return await call_function(db, "get_event_type_histogram", tenant_id, hours)


# ---------------------------------------------------------------------------
# Stored Procedures
# ---------------------------------------------------------------------------

async def call_procedure(
    db: AsyncSession,
    proc_name: str,
    *args: Any,
) -> None:
    """
    Call a PostgreSQL stored procedure (CALL proc_name(...)).

    Commits the transaction on success, rolls back on failure.
    """
    if _is_sqlite(db):
        logger.debug("call_procedure(%s): skipped — SQLite environment", proc_name)
        return

    param_placeholders = ", ".join(f":p{i}" for i in range(len(args)))
    sql = f"CALL {proc_name}({param_placeholders})"
    params = {f"p{i}": v for i, v in enumerate(args)}

    try:
        await db.execute(text(sql), params)
        await db.commit()
        logger.info("call_procedure(%s, %s): success", proc_name, args)
    except Exception as exc:
        await db.rollback()
        logger.error("call_procedure(%s, %s) failed: %s", proc_name, args, exc)
        raise


async def purge_tenant_data(db: AsyncSession, tenant_id: int) -> None:
    """
    Call the master GDPR retention procedure for a tenant.
    Purges ActivityLogs, AgentReports, and EventLogs based on DataRetentionDays.
    """
    await call_procedure(db, "purge_tenant_data", tenant_id)


async def resolve_incident(
    db: AsyncSession,
    incident_id: int,
    notes: str,
    actor: str = "System",
) -> None:
    """
    Atomically resolve an Incident and write an AuditLog entry.
    """
    await call_procedure(db, "resolve_incident_with_audit", incident_id, notes, actor)


async def decommission_agent(
    db: AsyncSession,
    agent_id: str,
    actor: str = "System",
) -> None:
    """
    Atomically decommission an agent and auto-resolve its open incidents.
    """
    await call_procedure(db, "decommission_agent", agent_id, actor)


# ---------------------------------------------------------------------------
# Materialized View Refresh
# ---------------------------------------------------------------------------

# Refresh intervals (in seconds) for each materialized view.
# These are enforced by the APScheduler background task (see workers/).
MV_REFRESH_INTERVALS = {
    "mv_tenant_dashboard_stats":  5 * 60,   # 5 minutes
    "mv_agent_risk_summary":      5 * 60,   # 5 minutes
    "mv_activity_hourly_buckets": 15 * 60,  # 15 minutes
    "mv_software_vuln_exposure":  30 * 60,  # 30 minutes
}

# All materialized views in dependency order
ALL_MATERIALIZED_VIEWS = [
    "mv_tenant_dashboard_stats",
    "mv_agent_risk_summary",
    "mv_activity_hourly_buckets",
    "mv_software_vuln_exposure",
]


async def refresh_materialized_view(db: AsyncSession, view_name: str) -> None:
    """
    Concurrently refresh a single materialized view.
    CONCURRENTLY allows reads to continue during refresh (requires a unique index).
    """
    if _is_sqlite(db):
        logger.debug("refresh_materialized_view(%s): skipped — SQLite", view_name)
        return

    try:
        # CONCURRENTLY cannot run inside an active transaction
        await db.execute(text("COMMIT"))
        await db.execute(
            text(f"REFRESH MATERIALIZED VIEW CONCURRENTLY {view_name}")
        )
        logger.info("Refreshed materialized view: %s", view_name)
    except Exception as exc:
        logger.error("Failed to refresh %s: %s", view_name, exc)
        raise


async def refresh_all_materialized_views(db: AsyncSession) -> None:
    """
    Refresh all materialized views using the DB-side helper function.
    This calls refresh_all_materialized_views() PostgreSQL function.
    """
    if _is_sqlite(db):
        logger.debug("refresh_all_materialized_views: skipped — SQLite")
        return

    try:
        await db.execute(text("COMMIT"))
        await db.execute(text("SELECT refresh_all_materialized_views()"))
        logger.info("All materialized views refreshed successfully")
    except Exception as exc:
        logger.error("refresh_all_materialized_views failed: %s", exc)
        raise


# ---------------------------------------------------------------------------
# View Query Helpers
# ---------------------------------------------------------------------------

async def query_view(
    db: AsyncSession,
    view_name: str,
    where_clause: Optional[str] = None,
    params: Optional[dict] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """
    Generic helper to query any named view with optional WHERE/LIMIT/OFFSET.

    Example:
        rows = await query_view(
            db, "v_open_incidents",
            where_clause='"TenantId" = :tenant_id',
            params={"tenant_id": 1},
            limit=50
        )
    """
    sql = f'SELECT * FROM {view_name}'
    if where_clause:
        sql += f" WHERE {where_clause}"
    sql += f" LIMIT {limit} OFFSET {offset}"

    try:
        result = await db.execute(text(sql), params or {})
        rows = result.mappings().all()
        return [dict(r) for r in rows]
    except Exception as exc:
        logger.error("query_view(%s) failed: %s", view_name, exc)
        raise


async def get_agent_latest_reports(
    db: AsyncSession,
    tenant_id: Optional[int] = None,
) -> list[dict]:
    """Query v_agent_latest_report, optionally filtered by tenant."""
    where = '"TenantId" = :tid' if tenant_id else None
    params = {"tid": tenant_id} if tenant_id else None
    return await query_view(db, "v_agent_latest_report", where, params, limit=1000)


async def get_open_incidents(
    db: AsyncSession,
    tenant_id: int,
    limit: int = 50,
) -> list[dict]:
    """Query v_open_incidents for a tenant."""
    return await query_view(
        db, "v_open_incidents",
        where_clause='"TenantId" = :tid',
        params={"tid": tenant_id},
        limit=limit,
    )


async def get_active_vulnerabilities(
    db: AsyncSession,
    agent_id: str,
    limit: int = 100,
) -> list[dict]:
    """Query v_active_vulnerabilities for a specific agent."""
    return await query_view(
        db, "v_active_vulnerabilities",
        where_clause='"AgentId" = :aid',
        params={"aid": agent_id},
        limit=limit,
    )


async def get_unread_notifications(
    db: AsyncSession,
    tenant_id: int,
) -> Optional[dict]:
    """Query v_unread_notifications for a tenant."""
    rows = await query_view(
        db, "v_unread_notifications",
        where_clause='"TenantId" = :tid',
        params={"tid": tenant_id},
        limit=1,
    )
    return rows[0] if rows else None


# ---------------------------------------------------------------------------
# Materialized View Query Helpers (faster than live views)
# ---------------------------------------------------------------------------

async def get_mv_tenant_stats(
    db: AsyncSession,
    tenant_id: int,
) -> Optional[dict]:
    """
    Read from mv_tenant_dashboard_stats.
    Falls back to live query if materialized view is empty/not refreshed.
    """
    rows = await query_view(
        db, "mv_tenant_dashboard_stats",
        where_clause="tenant_id = :tid",
        params={"tid": tenant_id},
        limit=1,
    )
    return rows[0] if rows else None


async def get_mv_agent_risk_summary(
    db: AsyncSession,
    tenant_id: int,
    limit: int = 100,
) -> list[dict]:
    """Read from mv_agent_risk_summary for a tenant."""
    return await query_view(
        db, "mv_agent_risk_summary",
        where_clause="tenant_id = :tid ORDER BY threat_score DESC",
        params={"tid": tenant_id},
        limit=limit,
    )


async def get_mv_activity_trend(
    db: AsyncSession,
    agent_id: str,
    hours: int = 24,
) -> list[dict]:
    """
    Read pre-bucketed hourly activity from mv_activity_hourly_buckets.
    Returns rows sorted by hour_bucket ASC.
    """
    return await query_view(
        db, "mv_activity_hourly_buckets",
        where_clause=(
            "agent_id = :aid "
            "AND hour_bucket >= NOW() - (:hours || ' hours')::INTERVAL "
            "ORDER BY hour_bucket ASC"
        ),
        params={"aid": agent_id, "hours": str(hours)},
        limit=168,  # max 7 days × 24 hours
    )


async def get_mv_vuln_exposure(
    db: AsyncSession,
    tenant_id: int,
    limit: int = 200,
) -> list[dict]:
    """Read pre-joined CVE exposure from mv_software_vuln_exposure for a tenant."""
    return await query_view(
        db, "mv_software_vuln_exposure",
        where_clause="tenant_id = :tid ORDER BY severity ASC",
        params={"tid": tenant_id},
        limit=limit,
    )


# ---------------------------------------------------------------------------
# Convenience: Module-level namespace object
# ---------------------------------------------------------------------------

class _PgHelpers:
    """Namespace object for cleaner import: `from app.db.pg_helpers import pg`."""

    call_function              = staticmethod(call_function)
    call_procedure             = staticmethod(call_procedure)
    refresh_materialized_view  = staticmethod(refresh_materialized_view)
    refresh_all_materialized_views = staticmethod(refresh_all_materialized_views)
    query_view                 = staticmethod(query_view)

    # Functions
    get_tenant_dashboard_kpis  = staticmethod(get_tenant_dashboard_kpis)
    get_activity_stats         = staticmethod(get_activity_stats)
    get_vulnerability_summary  = staticmethod(get_vulnerability_summary)
    get_agent_threat_summary   = staticmethod(get_agent_threat_summary)
    get_event_type_histogram   = staticmethod(get_event_type_histogram)

    # Procedures
    purge_tenant_data          = staticmethod(purge_tenant_data)
    resolve_incident           = staticmethod(resolve_incident)
    decommission_agent         = staticmethod(decommission_agent)

    # Views
    get_agent_latest_reports   = staticmethod(get_agent_latest_reports)
    get_open_incidents         = staticmethod(get_open_incidents)
    get_active_vulnerabilities = staticmethod(get_active_vulnerabilities)
    get_unread_notifications   = staticmethod(get_unread_notifications)

    # Materialized views
    get_mv_tenant_stats        = staticmethod(get_mv_tenant_stats)
    get_mv_agent_risk_summary  = staticmethod(get_mv_agent_risk_summary)
    get_mv_activity_trend      = staticmethod(get_mv_activity_trend)
    get_mv_vuln_exposure       = staticmethod(get_mv_vuln_exposure)

    MV_REFRESH_INTERVALS       = MV_REFRESH_INTERVALS
    ALL_MATERIALIZED_VIEWS     = ALL_MATERIALIZED_VIEWS


pg = _PgHelpers()
