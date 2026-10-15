-- =============================================================================
-- MONITORIX — PostgreSQL Composite Indexes
-- Purpose : Eliminate sequential scans on hot tables.
-- Run     : psql -d <db> -f pg_indexes.sql
--           OR sourced by init-db.sql on first boot.
-- Safe    : All indexes use CREATE INDEX IF NOT EXISTS — idempotent.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- ActivityLogs  (highest insert rate: every agent event)
-- ---------------------------------------------------------------------------

-- Dashboard stats: tenant time-range aggregates
CREATE INDEX IF NOT EXISTS idx_activity_logs_tenant_ts
    ON "ActivityLogs" ("TenantId", "Timestamp" DESC);

-- Per-agent productivity / risk breakdowns
CREATE INDEX IF NOT EXISTS idx_activity_logs_agent_type_ts
    ON "ActivityLogs" ("AgentId", "ActivityType", "Timestamp" DESC);

-- Risk-level filtering for threat hunting
CREATE INDEX IF NOT EXISTS idx_activity_logs_tenant_risk
    ON "ActivityLogs" ("TenantId", "RiskLevel", "Timestamp" DESC);

-- Keyset pagination cursor (replaces slow OFFSET)
CREATE INDEX IF NOT EXISTS idx_activity_logs_id_desc
    ON "ActivityLogs" ("Id" DESC);

-- ---------------------------------------------------------------------------
-- AgentReports  (second-highest insert rate: agent heartbeat ~60s)
-- ---------------------------------------------------------------------------

-- Already has (AgentId, Timestamp) and (TenantId, Timestamp) composite indexes
-- defined in models.py via __table_args__. Below adds the missing ones.

-- CPU/Memory trend query covers both directions
CREATE INDEX IF NOT EXISTS idx_agent_reports_tenant_ts_cpu
    ON "AgentReports" ("TenantId", "Timestamp" DESC, "CpuUsage");

-- Keyset pagination cursor
CREATE INDEX IF NOT EXISTS idx_agent_reports_id_desc
    ON "AgentReports" ("Id" DESC);

-- ---------------------------------------------------------------------------
-- EventLogs  (security event stream)
-- ---------------------------------------------------------------------------

-- Per-agent event fetch (events.py main query)
CREATE INDEX IF NOT EXISTS idx_event_logs_agent_ts
    ON "EventLogs" ("AgentId", "Timestamp" DESC);

-- Type-filtered event queries (e.g. threat hunting by event type)
CREATE INDEX IF NOT EXISTS idx_event_logs_agent_type_ts
    ON "EventLogs" ("AgentId", "Type", "Timestamp" DESC);

-- Tenant-scoped event stream via agent list
CREATE INDEX IF NOT EXISTS idx_event_logs_id_desc
    ON "EventLogs" ("Id" DESC);

-- ---------------------------------------------------------------------------
-- Agents  (core entity — joined on almost every query)
-- ---------------------------------------------------------------------------

-- Online-agent count (LastSeen threshold check)
CREATE INDEX IF NOT EXISTS idx_agents_tenant_lastseen
    ON "Agents" ("TenantId", "LastSeen" DESC);

-- Risk ranking / threat score leaderboard
CREATE INDEX IF NOT EXISTS idx_agents_tenant_threatscore
    ON "Agents" ("TenantId", "ThreatScore" DESC);

-- AgentId is already unique-indexed; add lowercase-compatible index for
-- case-insensitive lookups used in events.py (func.lower(Agent.AgentId))
CREATE INDEX IF NOT EXISTS idx_agents_agentid_lower
    ON "Agents" (LOWER("AgentId"));

-- ---------------------------------------------------------------------------
-- AgentSoftware  (vulnerability / patch queries)
-- ---------------------------------------------------------------------------

-- Patch-required filter (agents.py vuln scan)
CREATE INDEX IF NOT EXISTS idx_agent_software_agent_patch
    ON "AgentSoftware" ("AgentId", "HasPatchAvailable");

-- Severity dashboard: count vulns by severity across tenant
CREATE INDEX IF NOT EXISTS idx_agent_software_severity_patch
    ON "AgentSoftware" ("Severity", "HasPatchAvailable");

-- ---------------------------------------------------------------------------
-- Screenshots  (time-series image metadata — large table)
-- ---------------------------------------------------------------------------

-- Per-agent screenshot listing with timestamp order
CREATE INDEX IF NOT EXISTS idx_screenshots_agent_ts
    ON "Screenshots" ("AgentId", "Timestamp" DESC);

-- Tenant-scoped screenshot gallery
CREATE INDEX IF NOT EXISTS idx_screenshots_tenant_ts
    ON "Screenshots" ("TenantId", "Timestamp" DESC);

-- Alert screenshots filter
CREATE INDEX IF NOT EXISTS idx_screenshots_agent_alert
    ON "Screenshots" ("AgentId", "IsAlert", "Timestamp" DESC);

-- ---------------------------------------------------------------------------
-- DetectionAlerts  (SOAR / threat hunting)
-- ---------------------------------------------------------------------------

-- Alert status filter (New, Investigating, False Positive, Confirmed)
CREATE INDEX IF NOT EXISTS idx_detection_alerts_agent_status_ts
    ON "DetectionAlerts" ("AgentId", "Status", "Timestamp" DESC);

-- ---------------------------------------------------------------------------
-- Notifications  (badge count — runs on every page load)
-- ---------------------------------------------------------------------------

-- Unread badge count per tenant
CREATE INDEX IF NOT EXISTS idx_notifications_tenant_read_ts
    ON "Notifications" ("TenantId", "IsRead", "CreatedAt" DESC);

-- ---------------------------------------------------------------------------
-- OCRLogs  (DLP / OCR risk filtering)
-- ---------------------------------------------------------------------------

-- Risk-level filter for OCR threat analysis
CREATE INDEX IF NOT EXISTS idx_ocr_logs_agent_risk
    ON "OCRLogs" ("AgentId", "RiskLevel");

-- ---------------------------------------------------------------------------
-- Incidents  (SOAR incident tracking)
-- ---------------------------------------------------------------------------

-- Open incident count per tenant
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_status
    ON "Incidents" ("TenantId", "Status");

-- ---------------------------------------------------------------------------
-- AuditLogs  (compliance / export queries)
-- ---------------------------------------------------------------------------

-- Tenant-scoped audit trail with time ordering
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_ts
    ON "AuditLogs" ("TenantId", "Timestamp" DESC);

-- ---------------------------------------------------------------------------
-- IndicatorsOfCompromise  (threat feed lookups — value + type)
-- ---------------------------------------------------------------------------

-- IOC lookup by value and type (used in threat hunting)
CREATE INDEX IF NOT EXISTS idx_ioc_value_type
    ON "IndicatorsOfCompromise" ("IndicatorValue", "IndicatorType");
