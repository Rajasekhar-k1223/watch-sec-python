-- =============================================================================
-- MONITORIX — PostgreSQL SQL Functions
-- Purpose  : Reusable, parameterized query logic callable from FastAPI via
--            `SELECT fn_name(args)` — eliminates repeated complex queries.
-- Run      : psql -d <db> -f pg_functions.sql   (OR via init-db.sql)
-- Safe     : All use CREATE OR REPLACE FUNCTION — idempotent.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. get_tenant_dashboard_kpis(tenant_id, hours)
--    Returns a single JSON object with all dashboard KPIs.
--    Replaces: multiple individual queries in dashboard.py /dashboard/stats
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION get_tenant_dashboard_kpis(
    p_tenant_id  INT,
    p_hours      INT DEFAULT 24
)
RETURNS JSON
LANGUAGE plpgsql
STABLE  -- safe for connection pooling; does not modify data
AS $$
DECLARE
    v_start_ts       TIMESTAMP := NOW() - (p_hours || ' hours')::INTERVAL;
    v_online_thresh  TIMESTAMP := NOW() - INTERVAL '2 minutes';
    v_result         JSON;
BEGIN
    SELECT json_build_object(
        'total_agents',   COUNT(DISTINCT a."Id"),
        'online_agents',  COUNT(DISTINCT a."Id") FILTER (WHERE a."LastSeen" >= v_online_thresh),
        'offline_agents', COUNT(DISTINCT a."Id") FILTER (WHERE a."LastSeen" <  v_online_thresh OR a."LastSeen" IS NULL),
        'avg_cpu',        ROUND(AVG(ar."CpuUsage")::NUMERIC, 2),
        'avg_memory',     ROUND(AVG(ar."MemoryUsage")::NUMERIC, 2),
        'total_events',   (
            SELECT COUNT(*) FROM "EventLogs" el
            WHERE el."AgentId" = ANY(
                SELECT "AgentId" FROM "Agents" WHERE "TenantId" = p_tenant_id
            )
            AND el."Timestamp" >= v_start_ts
        ),
        'critical_events', (
            SELECT COUNT(*) FROM "EventLogs" el2
            WHERE el2."AgentId" = ANY(
                SELECT "AgentId" FROM "Agents" WHERE "TenantId" = p_tenant_id
            )
            AND el2."Timestamp" >= v_start_ts
            AND el2."Severity" = 'Critical'
        ),
        'high_risk_agents', COUNT(DISTINCT a."Id") FILTER (WHERE a."RiskLevel" IN ('High', 'Critical'))
    )
    INTO v_result
    FROM "Agents" a
    LEFT JOIN "AgentReports" ar
           ON ar."AgentId" = a."AgentId"
          AND ar."Timestamp" >= v_start_ts
    WHERE a."TenantId" = p_tenant_id
      AND (a."IsPendingUninstall" IS NULL OR a."IsPendingUninstall" = FALSE);

    RETURN v_result;
END;
$$;

COMMENT ON FUNCTION get_tenant_dashboard_kpis(INT, INT) IS
    'Returns all dashboard KPIs for a tenant in one DB round-trip.';


-- ---------------------------------------------------------------------------
-- 2. get_activity_stats(agent_id, hours)
--    Returns productivity, risk and category breakdown for one agent.
--    Replaces: N+1 queries in productivity.py / dashboard stats.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION get_activity_stats(
    p_agent_id  TEXT,
    p_hours     INT DEFAULT 24
)
RETURNS JSON
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_start_ts  TIMESTAMP := NOW() - (p_hours || ' hours')::INTERVAL;
    v_result    JSON;
BEGIN
    SELECT json_build_object(
        'total_duration_seconds',      COALESCE(SUM(al."DurationSeconds"), 0),
        'total_idle_seconds',          COALESCE(SUM(al."IdleSeconds"), 0),
        'avg_productivity_score',      ROUND(AVG(al."ProductivityScore")::NUMERIC, 2),
        'avg_risk_score',              ROUND(AVG(al."RiskScore")::NUMERIC, 2),
        'high_risk_count',             COUNT(*) FILTER (WHERE al."RiskLevel" IN ('High', 'Critical')),
        'activity_by_type', (
            SELECT json_agg(row_to_json(t)) FROM (
                SELECT "ActivityType", COUNT(*) AS cnt,
                       ROUND(SUM("DurationSeconds")::NUMERIC, 1) AS total_secs
                FROM   "ActivityLogs"
                WHERE  "AgentId" = p_agent_id
                  AND  "Timestamp" >= v_start_ts
                GROUP  BY "ActivityType"
                ORDER  BY total_secs DESC
                LIMIT  10
            ) t
        ),
        'activity_by_category', (
            SELECT json_agg(row_to_json(c)) FROM (
                SELECT "Category", COUNT(*) AS cnt,
                       ROUND(SUM("DurationSeconds")::NUMERIC, 1) AS total_secs
                FROM   "ActivityLogs"
                WHERE  "AgentId" = p_agent_id
                  AND  "Timestamp" >= v_start_ts
                GROUP  BY "Category"
            ) c
        )
    )
    INTO v_result
    FROM "ActivityLogs" al
    WHERE al."AgentId" = p_agent_id
      AND al."Timestamp" >= v_start_ts;

    RETURN COALESCE(v_result, '{}'::JSON);
END;
$$;

COMMENT ON FUNCTION get_activity_stats(TEXT, INT) IS
    'Returns productivity + risk activity breakdown for a single agent over N hours.';


-- ---------------------------------------------------------------------------
-- 3. get_vulnerability_summary(agent_id)
--    Cross-joins AgentSoftware with Vulnerabilities to produce a per-agent
--    CVE exposure report broken down by severity.
--    Replaces: Python-level vuln matching loop in vulnerabilities.py
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION get_vulnerability_summary(
    p_agent_id  TEXT
)
RETURNS JSON
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_result JSON;
BEGIN
    SELECT json_build_object(
        'total_vulnerable_packages',  COUNT(DISTINCT sw."Id"),
        'total_cve_matches',          COUNT(*),
        'by_severity', (
            SELECT json_agg(row_to_json(s)) FROM (
                SELECT v."Severity", COUNT(*) AS cve_count
                FROM   "AgentSoftware" sw2
                JOIN   "Vulnerabilities" v
                    ON LOWER(sw2."Name") = LOWER(v."AffectedProduct")
                WHERE  sw2."AgentId" = p_agent_id
                  AND  sw2."HasPatchAvailable" = TRUE
                GROUP  BY v."Severity"
                ORDER  BY CASE v."Severity"
                    WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                    WHEN 'Medium'   THEN 3 ELSE 4 END
            ) s
        ),
        'top_cves', (
            SELECT json_agg(row_to_json(c)) FROM (
                SELECT v2."CVE", v2."AffectedProduct", v2."Severity",
                       sw3."Version" AS installed_version,
                       v2."Description"
                FROM   "AgentSoftware" sw3
                JOIN   "Vulnerabilities" v2
                    ON LOWER(sw3."Name") = LOWER(v2."AffectedProduct")
                WHERE  sw3."AgentId" = p_agent_id
                  AND  sw3."HasPatchAvailable" = TRUE
                ORDER  BY CASE v2."Severity"
                    WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                    WHEN 'Medium'   THEN 3 ELSE 4 END,
                    v2."CVE"
                LIMIT  20
            ) c
        )
    )
    INTO v_result
    FROM "AgentSoftware" sw
    JOIN "Vulnerabilities" v ON LOWER(sw."Name") = LOWER(v."AffectedProduct")
    WHERE sw."AgentId" = p_agent_id
      AND sw."HasPatchAvailable" = TRUE;

    RETURN COALESCE(v_result, '{"total_vulnerable_packages":0,"total_cve_matches":0,"by_severity":[],"top_cves":[]}'::JSON);
END;
$$;

COMMENT ON FUNCTION get_vulnerability_summary(TEXT) IS
    'Returns CVE exposure summary for a single agent by joining AgentSoftware × Vulnerabilities.';


-- ---------------------------------------------------------------------------
-- 4. get_agent_threat_summary(tenant_id)
--    Returns per-agent ThreatScore + RiskLevel for the threat hunting leaderboard.
--    Used by: ThreatHunting.tsx → threat summary endpoint
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION get_agent_threat_summary(
    p_tenant_id  INT
)
RETURNS TABLE (
    agent_id     TEXT,
    hostname     TEXT,
    risk_level   TEXT,
    threat_score INT,
    last_seen    TIMESTAMP
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT
        a."AgentId"::TEXT,
        a."Hostname"::TEXT,
        a."RiskLevel"::TEXT,
        a."ThreatScore",
        a."LastSeen"
    FROM "Agents" a
    WHERE a."TenantId" = p_tenant_id
      AND (a."IsPendingUninstall" IS NULL OR a."IsPendingUninstall" = FALSE)
    ORDER BY a."ThreatScore" DESC, a."LastSeen" DESC;
END;
$$;

COMMENT ON FUNCTION get_agent_threat_summary(INT) IS
    'Returns threat score leaderboard for all agents in a tenant.';


-- ---------------------------------------------------------------------------
-- 5. get_event_type_histogram(tenant_id, hours)
--    Returns event type distribution for the dashboard chart.
--    Replaces: Python-level grouping in dashboard.py /dashboard/stats
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION get_event_type_histogram(
    p_tenant_id  INT,
    p_hours      INT DEFAULT 24
)
RETURNS JSON
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_start_ts  TIMESTAMP := NOW() - (p_hours || ' hours')::INTERVAL;
    v_result    JSON;
BEGIN
    SELECT json_agg(row_to_json(t))
    INTO   v_result
    FROM (
        SELECT el."Type", COUNT(*) AS count
        FROM   "EventLogs" el
        WHERE  el."AgentId" IN (
            SELECT "AgentId" FROM "Agents" WHERE "TenantId" = p_tenant_id
        )
        AND el."Timestamp" >= v_start_ts
        GROUP  BY el."Type"
        ORDER  BY count DESC
        LIMIT  20
    ) t;

    RETURN COALESCE(v_result, '[]'::JSON);
END;
$$;

COMMENT ON FUNCTION get_event_type_histogram(INT, INT) IS
    'Returns event type frequency distribution for a tenant dashboard chart.';
