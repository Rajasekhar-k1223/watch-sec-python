-- =============================================================================
-- MONITORIX — PostgreSQL Reusable Views
-- Purpose  : Named, reusable complex queries — no precomputed storage.
--            Refreshed on every SELECT (unlike materialized views).
-- Run      : psql -d <db> -f pg_views.sql   (OR via init-db.sql)
-- Safe     : All use CREATE OR REPLACE VIEW — idempotent.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. v_agent_latest_report
--    The most-recent AgentReports row per agent.
--    Replaces the repeated subquery pattern inside dashboard.py:
--      SELECT AgentId, MAX(Id) ... GROUP BY AgentId
--    Usage: SELECT * FROM v_agent_latest_report WHERE "TenantId" = 1
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_agent_latest_report AS
SELECT ar.*
FROM   "AgentReports" ar
JOIN (
    SELECT "AgentId", MAX("Id") AS max_id
    FROM   "AgentReports"
    GROUP  BY "AgentId"
) latest ON ar."Id" = latest.max_id;

COMMENT ON VIEW v_agent_latest_report IS
    'Latest AgentReports row per agent. Drop-in replacement for the MAX(Id) subquery in dashboard.py.';


-- ---------------------------------------------------------------------------
-- 2. v_active_vulnerabilities
--    Joins AgentSoftware × Vulnerabilities for every agent.
--    Pre-filtered to only patchable/vulnerable entries.
--    Usage: SELECT * FROM v_active_vulnerabilities WHERE "AgentId" = 'abc'
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_active_vulnerabilities AS
SELECT
    sw."AgentId",
    sw."Name"                  AS software_name,
    sw."Version"               AS installed_version,
    sw."Severity"              AS software_severity,
    sw."HasPatchAvailable",
    v."CVE",
    v."Severity"               AS cve_severity,
    v."Description"            AS cve_description,
    v."MinVersion",
    v."MaxVersion"
FROM   "AgentSoftware" sw
JOIN   "Vulnerabilities" v
    ON (LOWER(sw."Name") LIKE '%' || LOWER(v."AffectedProduct") || '%' OR LOWER(v."AffectedProduct") LIKE '%' || LOWER(sw."Name") || '%');

COMMENT ON VIEW v_active_vulnerabilities IS
    'Cross-join of AgentSoftware with Vulnerabilities — only patchable CVE exposures.';


-- ---------------------------------------------------------------------------
-- 3. v_open_incidents
--    Open + In-Progress Incidents enriched with agent hostname.
--    Usage: SELECT * FROM v_open_incidents WHERE "TenantId" = 1
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_open_incidents AS
SELECT
    i."Id",
    i."TenantId",
    i."AgentId",
    a."Hostname",
    i."Title",
    i."Severity",
    i."Status",
    i."CreatedDate",
    i."UpdateDate",
    i."Description"
FROM   "Incidents" i
LEFT   JOIN "Agents" a ON a."AgentId" = i."AgentId"
WHERE  i."Status" IN ('Open', 'In-Progress');

COMMENT ON VIEW v_open_incidents IS
    'Incidents that are Open or In-Progress, enriched with agent hostname.';


-- ---------------------------------------------------------------------------
-- 4. v_unread_notifications
--    Per-tenant unread notification count + latest message preview.
--    Usage: SELECT * FROM v_unread_notifications WHERE "TenantId" = 1
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_unread_notifications AS
SELECT
    n."TenantId",
    COUNT(*)                    AS unread_count,
    MAX(n."CreatedAt")          AS latest_at,
    json_agg(json_build_object(
        'id',      n."Id",
        'title',   n."Title",
        'type',    n."Type",
        'created', n."CreatedAt"
    ) ORDER BY n."CreatedAt" DESC)
    FILTER (WHERE rn <= 5)     AS preview_items
FROM (
    SELECT *,
           ROW_NUMBER() OVER (PARTITION BY "TenantId" ORDER BY "CreatedAt" DESC) AS rn
    FROM "Notifications"
    WHERE "IsRead" = FALSE
) n
GROUP BY n."TenantId";

COMMENT ON VIEW v_unread_notifications IS
    'Per-tenant unread notification count and 5-item preview.';


-- ---------------------------------------------------------------------------
-- 5. v_agent_online_status
--    Current online/offline status for every agent.
--    Usage: SELECT * FROM v_agent_online_status WHERE "TenantId" = 1
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_agent_online_status AS
SELECT
    a."Id",
    a."AgentId",
    a."TenantId",
    a."Hostname",
    a."LastSeen",
    a."ThreatScore",
    a."RiskLevel",
    a."Version",
    CASE
        WHEN a."LastSeen" >= NOW() - INTERVAL '2 minutes' THEN 'Online'
        ELSE 'Offline'
    END AS online_status
FROM   "Agents" a
WHERE  (a."IsPendingUninstall" IS NULL OR a."IsPendingUninstall" = FALSE);

COMMENT ON VIEW v_agent_online_status IS
    'Real-time online/offline status for all active agents.';


-- ---------------------------------------------------------------------------
-- 6. v_software_patch_queue
--    All agents that have software with patches available, sorted by severity.
--    Usage: SELECT * FROM v_software_patch_queue WHERE "AgentId" = 'abc'
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_software_patch_queue AS
SELECT
    sw."AgentId",
    a."Hostname",
    a."TenantId",
    sw."Name"           AS software_name,
    sw."Version"        AS current_version,
    sw."LatestVersion",
    sw."Severity",
    sw."VulnerabilityCount",
    sw."LastSeen"
FROM   "AgentSoftware" sw
JOIN   "Agents" a ON a."AgentId" = sw."AgentId"
WHERE  sw."HasPatchAvailable" = TRUE
ORDER  BY
    CASE sw."Severity"
        WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
        WHEN 'Medium'   THEN 3 ELSE 4
    END,
    sw."AgentId";

COMMENT ON VIEW v_software_patch_queue IS
    'All patchable software items across all agents, sorted by severity.';


-- ---------------------------------------------------------------------------
-- 7. v_detection_alert_summary
--    DetectionAlerts enriched with rule name and agent hostname.
--    Usage: SELECT * FROM v_detection_alert_summary WHERE "TenantId" = 1
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_detection_alert_summary AS
SELECT
    da."Id",
    da."AgentId",
    a."Hostname",
    a."TenantId",
    dr."Name"           AS rule_name,
    dr."MitreTactic",
    dr."MitreTechnique",
    dr."Severity",
    da."Status",
    da."MatchedContent",
    da."Timestamp"
FROM   "DetectionAlerts" da
JOIN   "Agents" a           ON a."AgentId" = da."AgentId"
LEFT   JOIN "DetectionRules" dr ON dr."Id"  = da."RuleId";

COMMENT ON VIEW v_detection_alert_summary IS
    'DetectionAlerts enriched with rule name, MITRE details, and agent hostname.';
