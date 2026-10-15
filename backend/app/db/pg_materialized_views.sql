-- =============================================================================
-- MONITORIX — PostgreSQL Materialized Views
-- Purpose  : Pre-computed, cached query results for dashboards & reports.
--            Data is stale until REFRESH is called (see pg_helpers.py).
-- Run      : psql -d <db> -f pg_materialized_views.sql  (OR via init-db.sql)
-- Refresh  : Called by background worker every 5 minutes (see pg_helpers.py).
-- Safe     : Uses DROP IF EXISTS + CREATE — re-runnable.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. mv_tenant_dashboard_stats
--    Pre-computes per-tenant KPIs: agent counts, avg CPU/mem, event counts,
--    and vulnerability counts.
--    Dashboard hits this instead of running 5+ live queries.
--    Refresh: Every 5 minutes (acceptable staleness for a security dashboard).
-- ---------------------------------------------------------------------------
DROP MATERIALIZED VIEW IF EXISTS mv_tenant_dashboard_stats CASCADE;

CREATE MATERIALIZED VIEW mv_tenant_dashboard_stats AS
SELECT
    a."TenantId"                                                           AS tenant_id,
    COUNT(DISTINCT a."Id")                                                  AS total_agents,
    COUNT(DISTINCT a."Id") FILTER (
        WHERE a."LastSeen" >= NOW() - INTERVAL '2 minutes'
    )                                                                       AS online_agents,
    COUNT(DISTINCT a."Id") FILTER (
        WHERE a."LastSeen" < NOW() - INTERVAL '2 minutes'
          OR  a."LastSeen" IS NULL
    )                                                                       AS offline_agents,
    ROUND(AVG(ar."CpuUsage")::NUMERIC, 2)                                   AS avg_cpu_24h,
    ROUND(AVG(ar."MemoryUsage")::NUMERIC, 2)                                AS avg_memory_24h,
    COUNT(DISTINCT el."Id")
        FILTER (WHERE el."Timestamp" >= NOW() - INTERVAL '24 hours')        AS events_24h,
    COUNT(DISTINCT el."Id")
        FILTER (WHERE el."Severity" = 'Critical'
                  AND el."Timestamp" >= NOW() - INTERVAL '24 hours')        AS critical_events_24h,
    COUNT(DISTINCT a."Id")
        FILTER (WHERE a."RiskLevel" IN ('High', 'Critical'))                AS high_risk_agents,
    NOW()                                                                   AS computed_at
FROM   "Agents" a
LEFT   JOIN "AgentReports" ar
        ON ar."AgentId" = a."AgentId"
       AND ar."Timestamp" >= NOW() - INTERVAL '24 hours'
LEFT   JOIN "EventLogs" el
        ON el."AgentId" = a."AgentId"
WHERE  (a."IsPendingUninstall" IS NULL OR a."IsPendingUninstall" = FALSE)
GROUP  BY a."TenantId"
WITH NO DATA;  -- populated on first REFRESH

-- Unique index so REFRESH CONCURRENTLY works (requires a unique column)
CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_tenant_dashboard_stats_tenant
    ON mv_tenant_dashboard_stats (tenant_id);

COMMENT ON MATERIALIZED VIEW mv_tenant_dashboard_stats IS
    'Pre-computed per-tenant dashboard KPIs. Refresh every 5 minutes via background worker.';


-- ---------------------------------------------------------------------------
-- 2. mv_agent_risk_summary
--    Per-agent: latest CPU/mem from AgentReports, vuln count, threat score.
--    Used by: agent list page, risk ranking.
--    Refresh: Every 5 minutes.
-- ---------------------------------------------------------------------------
DROP MATERIALIZED VIEW IF EXISTS mv_agent_risk_summary CASCADE;

CREATE MATERIALIZED VIEW mv_agent_risk_summary AS
SELECT
    a."AgentId"                                           AS agent_id,
    a."TenantId"                                          AS tenant_id,
    a."Hostname"                                          AS hostname,
    a."ThreatScore"                                       AS threat_score,
    a."RiskLevel"                                         AS risk_level,
    a."LastSeen"                                          AS last_seen,
    CASE WHEN a."LastSeen" >= NOW() - INTERVAL '2 minutes'
         THEN 'Online' ELSE 'Offline' END                 AS online_status,
    -- Latest telemetry snapshot
    lr."CpuUsage"                                         AS cpu_usage,
    lr."MemoryUsage"                                      AS memory_usage,
    lr."DiskUsage"                                        AS disk_usage,
    -- Vulnerability counts
    COUNT(DISTINCT sw."Id")
        FILTER (WHERE sw."HasPatchAvailable" = TRUE)      AS patchable_software_count,
    COUNT(DISTINCT sw."Id")
        FILTER (WHERE sw."Severity" = 'Critical'
                  AND sw."HasPatchAvailable" = TRUE)       AS critical_vuln_count,
    -- Recent alert count (last 24h)
    COUNT(DISTINCT da."Id")                               AS alerts_24h,
    NOW()                                                 AS computed_at
FROM "Agents" a
LEFT JOIN LATERAL (
    -- Efficient: uses ix_agent_reports_agentid_ts index
    SELECT "CpuUsage", "MemoryUsage", "DiskUsage"
    FROM   "AgentReports"
    WHERE  "AgentId" = a."AgentId"
    ORDER  BY "Timestamp" DESC
    LIMIT  1
) lr ON TRUE
LEFT JOIN "AgentSoftware" sw ON sw."AgentId" = a."AgentId"
LEFT JOIN "DetectionAlerts" da
       ON da."AgentId" = a."AgentId"
      AND da."Timestamp" >= NOW() - INTERVAL '24 hours'
WHERE (a."IsPendingUninstall" IS NULL OR a."IsPendingUninstall" = FALSE)
GROUP BY
    a."AgentId", a."TenantId", a."Hostname", a."ThreatScore",
    a."RiskLevel", a."LastSeen", lr."CpuUsage", lr."MemoryUsage", lr."DiskUsage"
WITH NO DATA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_agent_risk_summary_agent
    ON mv_agent_risk_summary (agent_id);

CREATE INDEX IF NOT EXISTS idx_mv_agent_risk_summary_tenant
    ON mv_agent_risk_summary (tenant_id, threat_score DESC);

COMMENT ON MATERIALIZED VIEW mv_agent_risk_summary IS
    'Per-agent risk summary combining telemetry, vuln counts, and alert counts. Refresh every 5 min.';


-- ---------------------------------------------------------------------------
-- 3. mv_activity_hourly_buckets
--    Pre-bucketed ActivityLogs data: per-agent, per-hour stats.
--    Covers last 7 days. Drives productivity trend charts.
--    Refresh: Every 15 minutes (trend charts don't need sub-minute freshness).
-- ---------------------------------------------------------------------------
DROP MATERIALIZED VIEW IF EXISTS mv_activity_hourly_buckets CASCADE;

CREATE MATERIALIZED VIEW mv_activity_hourly_buckets AS
SELECT
    "AgentId"                                                AS agent_id,
    "TenantId"                                               AS tenant_id,
    DATE_TRUNC('hour', "Timestamp")                          AS hour_bucket,
    COUNT(*)                                                 AS event_count,
    ROUND(SUM("DurationSeconds")::NUMERIC, 1)                AS total_duration_secs,
    ROUND(SUM("IdleSeconds")::NUMERIC, 1)                    AS total_idle_secs,
    ROUND(AVG("ProductivityScore")::NUMERIC, 2)              AS avg_productivity,
    ROUND(AVG("RiskScore")::NUMERIC, 2)                      AS avg_risk_score,
    COUNT(*) FILTER (WHERE "RiskLevel" IN ('High','Critical')) AS high_risk_events,
    NOW()                                                    AS computed_at
FROM   "ActivityLogs"
WHERE  "Timestamp" >= NOW() - INTERVAL '7 days'
GROUP  BY "AgentId", "TenantId", DATE_TRUNC('hour', "Timestamp")
WITH NO DATA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_activity_hourly_agent_hour
    ON mv_activity_hourly_buckets (agent_id, hour_bucket);

CREATE INDEX IF NOT EXISTS idx_mv_activity_hourly_tenant_hour
    ON mv_activity_hourly_buckets (tenant_id, hour_bucket DESC);

COMMENT ON MATERIALIZED VIEW mv_activity_hourly_buckets IS
    'Pre-bucketed activity trend data (hourly, last 7 days). Refresh every 15 minutes.';


-- ---------------------------------------------------------------------------
-- 4. mv_software_vuln_exposure
--    Cross-join AgentSoftware × Vulnerabilities — expensive join cached here.
--    Used by: vulnerability dashboard, CVE exposure reports.
--    Refresh: Every 30 minutes (vulnerability DB changes infrequently).
-- ---------------------------------------------------------------------------
DROP MATERIALIZED VIEW IF EXISTS mv_software_vuln_exposure CASCADE;

CREATE MATERIALIZED VIEW mv_software_vuln_exposure AS
SELECT
    sw."AgentId"            AS agent_id,
    a."TenantId"            AS tenant_id,
    a."Hostname"            AS hostname,
    sw."Name"               AS software_name,
    sw."Version"            AS installed_version,
    v."CVE"                 AS cve,
    v."Severity"            AS severity,
    v."Description"         AS description,
    v."MinVersion",
    v."MaxVersion",
    sw."HasPatchAvailable",
    NOW()                   AS computed_at
FROM "AgentSoftware" sw
JOIN "Agents" a ON a."AgentId" = sw."AgentId"
JOIN "Vulnerabilities" v
    ON LOWER(sw."Name") = LOWER(v."AffectedProduct")
WHERE sw."HasPatchAvailable" = TRUE
WITH NO DATA;

CREATE INDEX IF NOT EXISTS idx_mv_vuln_exposure_agent
    ON mv_software_vuln_exposure (agent_id, severity);

CREATE INDEX IF NOT EXISTS idx_mv_vuln_exposure_tenant
    ON mv_software_vuln_exposure (tenant_id, severity);

CREATE INDEX IF NOT EXISTS idx_mv_vuln_exposure_cve
    ON mv_software_vuln_exposure (cve);

COMMENT ON MATERIALIZED VIEW mv_software_vuln_exposure IS
    'Pre-joined AgentSoftware × Vulnerabilities. Eliminates expensive LOWER() JOIN at query time. Refresh every 30 min.';


-- ---------------------------------------------------------------------------
-- Helper: refresh_all_materialized_views()
--    A convenience function called by the Python background worker.
--    Uses CONCURRENTLY so reads are not blocked during refresh.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION refresh_all_materialized_views()
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_tenant_dashboard_stats;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_agent_risk_summary;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_activity_hourly_buckets;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_software_vuln_exposure;
END;
$$;

COMMENT ON FUNCTION refresh_all_materialized_views() IS
    'Concurrently refreshes all materialized views. Called by APScheduler every 5 minutes.';
