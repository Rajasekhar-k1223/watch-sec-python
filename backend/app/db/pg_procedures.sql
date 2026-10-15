-- =============================================================================
-- MONITORIX — PostgreSQL Stored Procedures
-- Purpose  : Transactional, multi-step DB operations that must succeed or fail
--            together — cannot be done safely with single SELECT/UPDATE calls.
-- Run      : psql -d <db> -f pg_procedures.sql  (OR via init-db.sql)
-- Safe     : All use CREATE OR REPLACE PROCEDURE — idempotent.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1. purge_old_activity_logs(tenant_id, retention_days)
--    Deletes ActivityLogs older than retention_days for a specific tenant.
--    Honors the DataRetentionDays GDPR field on the Tenant table.
--    Writes an AuditLog entry for the purge action.
--
--    Usage: CALL purge_old_activity_logs(1, 90);
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE purge_old_activity_logs(
    p_tenant_id       INT,
    p_retention_days  INT DEFAULT 90
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_cutoff      TIMESTAMP := NOW() - (p_retention_days || ' days')::INTERVAL;
    v_deleted_cnt BIGINT;
BEGIN
    -- Delete in batches to avoid locking the table for too long
    WITH deleted AS (
        DELETE FROM "ActivityLogs"
        WHERE  "TenantId" = p_tenant_id
          AND  "Timestamp" < v_cutoff
        RETURNING "Id"
    )
    SELECT COUNT(*) INTO v_deleted_cnt FROM deleted;

    -- Audit trail: write a record of what was purged
    INSERT INTO "AuditLogs" (
        "TenantId", "Actor", "Action", "Target", "Details", "Timestamp"
    ) VALUES (
        p_tenant_id,
        'System',
        'DataRetentionPurge',
        'ActivityLogs',
        'Purged ' || v_deleted_cnt || ' rows older than ' || p_retention_days
            || ' days (cutoff: ' || v_cutoff::TEXT || ')',
        NOW()
    );

    RAISE NOTICE 'purge_old_activity_logs: deleted % rows for tenant % (cutoff %)',
        v_deleted_cnt, p_tenant_id, v_cutoff;
END;
$$;

COMMENT ON PROCEDURE purge_old_activity_logs(INT, INT) IS
    'GDPR-compliant deletion of ActivityLogs older than retention_days for a tenant.';


-- ---------------------------------------------------------------------------
-- 2. purge_old_agent_reports(tenant_id, retention_days)
--    Same pattern as above but for AgentReports (heartbeat telemetry).
--
--    Usage: CALL purge_old_agent_reports(1, 90);
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE purge_old_agent_reports(
    p_tenant_id       INT,
    p_retention_days  INT DEFAULT 90
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_cutoff      TIMESTAMP := NOW() - (p_retention_days || ' days')::INTERVAL;
    v_deleted_cnt BIGINT;
BEGIN
    WITH deleted AS (
        DELETE FROM "AgentReports"
        WHERE  "TenantId" = p_tenant_id
          AND  "Timestamp" < v_cutoff
        RETURNING "Id"
    )
    SELECT COUNT(*) INTO v_deleted_cnt FROM deleted;

    INSERT INTO "AuditLogs" (
        "TenantId", "Actor", "Action", "Target", "Details", "Timestamp"
    ) VALUES (
        p_tenant_id,
        'System',
        'DataRetentionPurge',
        'AgentReports',
        'Purged ' || v_deleted_cnt || ' rows older than ' || p_retention_days
            || ' days (cutoff: ' || v_cutoff::TEXT || ')',
        NOW()
    );

    RAISE NOTICE 'purge_old_agent_reports: deleted % rows for tenant % (cutoff %)',
        v_deleted_cnt, p_tenant_id, v_cutoff;
END;
$$;

COMMENT ON PROCEDURE purge_old_agent_reports(INT, INT) IS
    'GDPR-compliant deletion of AgentReports older than retention_days for a tenant.';


-- ---------------------------------------------------------------------------
-- 3. purge_old_event_logs(tenant_id, retention_days)
--    Purges EventLogs — uses AgentId subquery since EventLogs has no TenantId.
--
--    Usage: CALL purge_old_event_logs(1, 90);
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE purge_old_event_logs(
    p_tenant_id       INT,
    p_retention_days  INT DEFAULT 90
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_cutoff      TIMESTAMP := NOW() - (p_retention_days || ' days')::INTERVAL;
    v_deleted_cnt BIGINT;
BEGIN
    WITH deleted AS (
        DELETE FROM "EventLogs"
        WHERE  "AgentId" IN (
            SELECT "AgentId" FROM "Agents" WHERE "TenantId" = p_tenant_id
        )
          AND  "Timestamp" < v_cutoff
        RETURNING "Id"
    )
    SELECT COUNT(*) INTO v_deleted_cnt FROM deleted;

    INSERT INTO "AuditLogs" (
        "TenantId", "Actor", "Action", "Target", "Details", "Timestamp"
    ) VALUES (
        p_tenant_id,
        'System',
        'DataRetentionPurge',
        'EventLogs',
        'Purged ' || v_deleted_cnt || ' rows older than ' || p_retention_days
            || ' days (cutoff: ' || v_cutoff::TEXT || ')',
        NOW()
    );

    RAISE NOTICE 'purge_old_event_logs: deleted % rows for tenant % (cutoff %)',
        v_deleted_cnt, p_tenant_id, v_cutoff;
END;
$$;

COMMENT ON PROCEDURE purge_old_event_logs(INT, INT) IS
    'GDPR-compliant deletion of EventLogs (via AgentId subquery) older than retention_days.';


-- ---------------------------------------------------------------------------
-- 4. purge_tenant_data(tenant_id)
--    Master retention procedure: reads DataRetentionDays from Tenant table,
--    then calls the three individual purge procedures.
--    Called nightly by the background worker.
--
--    Usage: CALL purge_tenant_data(1);
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE purge_tenant_data(
    p_tenant_id INT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_retention_days INT;
BEGIN
    SELECT COALESCE("DataRetentionDays", 90)
    INTO   v_retention_days
    FROM   "Tenants"
    WHERE  "Id" = p_tenant_id;

    IF NOT FOUND THEN
        RAISE WARNING 'purge_tenant_data: Tenant % not found — skipping', p_tenant_id;
        RETURN;
    END IF;

    CALL purge_old_activity_logs(p_tenant_id, v_retention_days);
    CALL purge_old_agent_reports(p_tenant_id, v_retention_days);
    CALL purge_old_event_logs(p_tenant_id, v_retention_days);

    RAISE NOTICE 'purge_tenant_data: completed for tenant % (retention=% days)',
        p_tenant_id, v_retention_days;
END;
$$;

COMMENT ON PROCEDURE purge_tenant_data(INT) IS
    'Master GDPR retention procedure. Reads DataRetentionDays from Tenant and purges all log tables.';


-- ---------------------------------------------------------------------------
-- 5. resolve_incident_with_audit(incident_id, notes, actor)
--    Atomically:
--      a) Updates Incident.Status = 'Resolved', sets ResolutionNotes
--      b) Writes an AuditLog entry for the resolution
--    This is a multi-table write that must be atomic.
--
--    Usage: CALL resolve_incident_with_audit(42, 'False positive - whitelisted', 'admin@co.in');
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE resolve_incident_with_audit(
    p_incident_id  INT,
    p_notes        TEXT,
    p_actor        TEXT DEFAULT 'System'
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_tenant_id  INT;
    v_title      TEXT;
BEGIN
    -- 1. Fetch incident info
    SELECT "TenantId", "Title"
    INTO   v_tenant_id, v_title
    FROM   "Incidents"
    WHERE  "Id" = p_incident_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Incident % not found', p_incident_id;
    END IF;

    -- 2. Update incident status
    UPDATE "Incidents"
    SET    "Status"          = 'Resolved',
           "ResolutionNotes" = p_notes,
           "UpdateDate"      = NOW()
    WHERE  "Id" = p_incident_id;

    -- 3. Write audit log entry
    INSERT INTO "AuditLogs" (
        "TenantId", "Actor", "Action", "Target", "Details", "Timestamp"
    ) VALUES (
        v_tenant_id,
        p_actor,
        'IncidentResolved',
        'Incident#' || p_incident_id,
        'Incident "' || v_title || '" resolved. Notes: ' || p_notes,
        NOW()
    );

    RAISE NOTICE 'resolve_incident_with_audit: Incident % resolved by %', p_incident_id, p_actor;
END;
$$;

COMMENT ON PROCEDURE resolve_incident_with_audit(INT, TEXT, TEXT) IS
    'Atomically resolves an Incident and writes an AuditLog entry in one transaction.';


-- ---------------------------------------------------------------------------
-- 6. decommission_agent(agent_id, actor)
--    Atomically:
--      a) Sets Agent.IsPendingUninstall = TRUE and Status = 'Decommissioned'
--      b) Marks all open Incidents for this agent as Resolved
--      c) Writes AuditLog
--    Useful for: remote agent removal from admin dashboard
--
--    Usage: CALL decommission_agent('agent-abc-123', 'admin@co.in');
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE decommission_agent(
    p_agent_id  TEXT,
    p_actor     TEXT DEFAULT 'System'
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_tenant_id  INT;
BEGIN
    SELECT "TenantId"
    INTO   v_tenant_id
    FROM   "Agents"
    WHERE  "AgentId" = p_agent_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Agent % not found', p_agent_id;
    END IF;

    -- Mark agent for uninstall
    UPDATE "Agents"
    SET    "IsPendingUninstall" = TRUE,
           "Status"             = 'Decommissioned',
           "UpdateDate"         = NOW()
    WHERE  "AgentId" = p_agent_id;

    -- Auto-resolve open incidents for this agent
    UPDATE "Incidents"
    SET    "Status"          = 'Resolved',
           "ResolutionNotes" = 'Auto-resolved: agent decommissioned by ' || p_actor,
           "UpdateDate"      = NOW()
    WHERE  "AgentId" = p_agent_id
      AND  "Status" IN ('Open', 'In-Progress');

    -- Audit trail
    INSERT INTO "AuditLogs" (
        "TenantId", "Actor", "Action", "Target", "Details", "Timestamp"
    ) VALUES (
        v_tenant_id,
        p_actor,
        'AgentDecommissioned',
        p_agent_id,
        'Agent decommissioned and open incidents auto-resolved.',
        NOW()
    );

    RAISE NOTICE 'decommission_agent: Agent % decommissioned by %', p_agent_id, p_actor;
END;
$$;

COMMENT ON PROCEDURE decommission_agent(TEXT, TEXT) IS
    'Atomically marks agent as decommissioned and resolves all open incidents in one transaction.';
