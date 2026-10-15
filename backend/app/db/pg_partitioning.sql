-- =============================================================================
-- MONITORIX — PostgreSQL Table Partitioning Migration Script
-- Purpose  : Convert ActivityLogs and AgentReports to range-partitioned tables
--            partitioned by month on the Timestamp column.
-- 
-- ⚠️  WARNING: This is a ONE-TIME DATA MIGRATION.
--    - Run during a MAINTENANCE WINDOW (write traffic should be paused).
--    - Creates new partitioned parent tables and migrates existing data.
--    - Then renames tables atomically using a transaction.
--    - Uses pg_partman-compatible naming convention (optional).
--
-- Run      : psql -d <db> -f pg_partitioning.sql
-- Estimated time: Depends on table size. For 50M rows expect 5-20 minutes.
-- =============================================================================

-- =============================================================================
-- SECTION 1: ActivityLogs Partitioning
-- =============================================================================

BEGIN;

-- Step 1a: Create the new partitioned parent table
CREATE TABLE IF NOT EXISTS "ActivityLogs_partitioned" (
    "Id"                SERIAL,
    "CreatedDate"       TIMESTAMP,
    "UpdateDate"        TIMESTAMP,
    "AgentId"           VARCHAR(50),
    "TenantId"          INTEGER,
    "ActivityType"      VARCHAR(50),
    "ProcessName"       VARCHAR(255),
    "WindowTitle"       TEXT,
    "Url"               TEXT,
    "DurationSeconds"   FLOAT   DEFAULT 0.0,
    "IdleSeconds"       FLOAT   DEFAULT 0.0,
    "Category"          VARCHAR(50) DEFAULT 'Neutral',
    "ProductivityScore" FLOAT   DEFAULT 0.0,
    "RiskScore"         FLOAT   DEFAULT 0.0,
    "RiskLevel"         VARCHAR(50) DEFAULT 'Normal',
    "Timestamp"         TIMESTAMP NOT NULL,
    PRIMARY KEY ("Id", "Timestamp")  -- Partition key must be in PK
) PARTITION BY RANGE ("Timestamp");

-- Step 1b: Create monthly child partitions (last 12 months + next 3 months)
-- Extend this list as needed or use pg_partman for auto-creation.

CREATE TABLE IF NOT EXISTS "ActivityLogs_y2025m10"
    PARTITION OF "ActivityLogs_partitioned"
    FOR VALUES FROM ('2025-10-01') TO ('2025-11-01');

CREATE TABLE IF NOT EXISTS "ActivityLogs_y2025m11"
    PARTITION OF "ActivityLogs_partitioned"
    FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');

CREATE TABLE IF NOT EXISTS "ActivityLogs_y2025m12"
    PARTITION OF "ActivityLogs_partitioned"
    FOR VALUES FROM ('2025-12-01') TO ('2026-01-01');

CREATE TABLE IF NOT EXISTS "ActivityLogs_y2026m01"
    PARTITION OF "ActivityLogs_partitioned"
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');

CREATE TABLE IF NOT EXISTS "ActivityLogs_y2026m02"
    PARTITION OF "ActivityLogs_partitioned"
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');

CREATE TABLE IF NOT EXISTS "ActivityLogs_y2026m03"
    PARTITION OF "ActivityLogs_partitioned"
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

CREATE TABLE IF NOT EXISTS "ActivityLogs_y2026m04"
    PARTITION OF "ActivityLogs_partitioned"
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');

CREATE TABLE IF NOT EXISTS "ActivityLogs_y2026m05"
    PARTITION OF "ActivityLogs_partitioned"
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

CREATE TABLE IF NOT EXISTS "ActivityLogs_y2026m06"
    PARTITION OF "ActivityLogs_partitioned"
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

CREATE TABLE IF NOT EXISTS "ActivityLogs_y2026m07"
    PARTITION OF "ActivityLogs_partitioned"
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');

CREATE TABLE IF NOT EXISTS "ActivityLogs_y2026m08"
    PARTITION OF "ActivityLogs_partitioned"
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');

CREATE TABLE IF NOT EXISTS "ActivityLogs_y2026m09"
    PARTITION OF "ActivityLogs_partitioned"
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');

-- Forward partitions (future months)
CREATE TABLE IF NOT EXISTS "ActivityLogs_y2026m10"
    PARTITION OF "ActivityLogs_partitioned"
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');

CREATE TABLE IF NOT EXISTS "ActivityLogs_y2026m11"
    PARTITION OF "ActivityLogs_partitioned"
    FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');

CREATE TABLE IF NOT EXISTS "ActivityLogs_y2026m12"
    PARTITION OF "ActivityLogs_partitioned"
    FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');

CREATE TABLE IF NOT EXISTS "ActivityLogs_y2027m01"
    PARTITION OF "ActivityLogs_partitioned"
    FOR VALUES FROM ('2027-01-01') TO ('2027-02-01');

-- Catch-all for very old data
CREATE TABLE IF NOT EXISTS "ActivityLogs_default"
    PARTITION OF "ActivityLogs_partitioned" DEFAULT;

-- Step 1c: Add per-partition indexes (PostgreSQL auto-propagates from parent)
CREATE INDEX IF NOT EXISTS idx_al_part_agentid_ts
    ON "ActivityLogs_partitioned" ("AgentId", "Timestamp" DESC);

CREATE INDEX IF NOT EXISTS idx_al_part_tenantid_ts
    ON "ActivityLogs_partitioned" ("TenantId", "Timestamp" DESC);

CREATE INDEX IF NOT EXISTS idx_al_part_type_ts
    ON "ActivityLogs_partitioned" ("AgentId", "ActivityType", "Timestamp" DESC);

COMMIT;

-- Step 1d: Migrate existing data (run OUTSIDE transaction for large tables)
-- This may take time — progress visible via pg_stat_progress_copy.
INSERT INTO "ActivityLogs_partitioned" (
    "Id", "CreatedDate", "UpdateDate", "AgentId", "TenantId",
    "ActivityType", "ProcessName", "WindowTitle", "Url",
    "DurationSeconds", "IdleSeconds", "Category", "ProductivityScore",
    "RiskScore", "RiskLevel", "Timestamp"
)
SELECT
    "Id", "CreatedDate", "UpdateDate", "AgentId", "TenantId",
    "ActivityType", "ProcessName", "WindowTitle", "Url",
    "DurationSeconds", "IdleSeconds", "Category", "ProductivityScore",
    "RiskScore", "RiskLevel", "Timestamp"
FROM "ActivityLogs"
ON CONFLICT DO NOTHING;

-- Step 1e: Atomic rename (swap old table with new partitioned table)
-- Run this in one transaction to minimize downtime.
BEGIN;
ALTER TABLE "ActivityLogs"             RENAME TO "ActivityLogs_old";
ALTER TABLE "ActivityLogs_partitioned" RENAME TO "ActivityLogs";
COMMIT;

-- Step 1f: Drop old table after verifying row counts match.
-- Uncomment ONLY after verification:
-- DROP TABLE "ActivityLogs_old";


-- =============================================================================
-- SECTION 2: AgentReports Partitioning  (same pattern)
-- =============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS "AgentReports_partitioned" (
    "Id"             SERIAL,
    "CreatedDate"    TIMESTAMP,
    "UpdateDate"     TIMESTAMP,
    "AgentId"        VARCHAR(255),
    "TenantId"       INTEGER,
    "Status"         VARCHAR(50),
    "CpuUsage"       FLOAT,
    "MemoryUsage"    FLOAT,
    "DiskUsage"      FLOAT   DEFAULT 0.0,
    "SoftwareCount"  INTEGER DEFAULT 0,
    "NetworkInMbps"  FLOAT   DEFAULT 0.0,
    "NetworkOutMbps" FLOAT   DEFAULT 0.0,
    "TopProcessesJson" TEXT,
    "Timestamp"      TIMESTAMP NOT NULL,
    PRIMARY KEY ("Id", "Timestamp")
) PARTITION BY RANGE ("Timestamp");

-- Monthly partitions — same date range as ActivityLogs
CREATE TABLE IF NOT EXISTS "AgentReports_y2025m10"
    PARTITION OF "AgentReports_partitioned"
    FOR VALUES FROM ('2025-10-01') TO ('2025-11-01');

CREATE TABLE IF NOT EXISTS "AgentReports_y2025m11"
    PARTITION OF "AgentReports_partitioned"
    FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');

CREATE TABLE IF NOT EXISTS "AgentReports_y2025m12"
    PARTITION OF "AgentReports_partitioned"
    FOR VALUES FROM ('2025-12-01') TO ('2026-01-01');

CREATE TABLE IF NOT EXISTS "AgentReports_y2026m01"
    PARTITION OF "AgentReports_partitioned"
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');

CREATE TABLE IF NOT EXISTS "AgentReports_y2026m02"
    PARTITION OF "AgentReports_partitioned"
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');

CREATE TABLE IF NOT EXISTS "AgentReports_y2026m03"
    PARTITION OF "AgentReports_partitioned"
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

CREATE TABLE IF NOT EXISTS "AgentReports_y2026m04"
    PARTITION OF "AgentReports_partitioned"
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');

CREATE TABLE IF NOT EXISTS "AgentReports_y2026m05"
    PARTITION OF "AgentReports_partitioned"
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

CREATE TABLE IF NOT EXISTS "AgentReports_y2026m06"
    PARTITION OF "AgentReports_partitioned"
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

CREATE TABLE IF NOT EXISTS "AgentReports_y2026m07"
    PARTITION OF "AgentReports_partitioned"
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');

CREATE TABLE IF NOT EXISTS "AgentReports_y2026m08"
    PARTITION OF "AgentReports_partitioned"
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');

CREATE TABLE IF NOT EXISTS "AgentReports_y2026m09"
    PARTITION OF "AgentReports_partitioned"
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');

CREATE TABLE IF NOT EXISTS "AgentReports_y2026m10"
    PARTITION OF "AgentReports_partitioned"
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');

CREATE TABLE IF NOT EXISTS "AgentReports_y2026m11"
    PARTITION OF "AgentReports_partitioned"
    FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');

CREATE TABLE IF NOT EXISTS "AgentReports_y2026m12"
    PARTITION OF "AgentReports_partitioned"
    FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');

CREATE TABLE IF NOT EXISTS "AgentReports_y2027m01"
    PARTITION OF "AgentReports_partitioned"
    FOR VALUES FROM ('2027-01-01') TO ('2027-02-01');

CREATE TABLE IF NOT EXISTS "AgentReports_default"
    PARTITION OF "AgentReports_partitioned" DEFAULT;

-- Per-partition indexes
CREATE INDEX IF NOT EXISTS idx_ar_part_agentid_ts
    ON "AgentReports_partitioned" ("AgentId", "Timestamp" DESC);

CREATE INDEX IF NOT EXISTS idx_ar_part_tenantid_ts
    ON "AgentReports_partitioned" ("TenantId", "Timestamp" DESC);

COMMIT;

-- Migrate existing data
INSERT INTO "AgentReports_partitioned" (
    "Id", "CreatedDate", "UpdateDate", "AgentId", "TenantId",
    "Status", "CpuUsage", "MemoryUsage", "DiskUsage", "SoftwareCount",
    "NetworkInMbps", "NetworkOutMbps", "TopProcessesJson", "Timestamp"
)
SELECT
    "Id", "CreatedDate", "UpdateDate", "AgentId", "TenantId",
    "Status", "CpuUsage", "MemoryUsage", "DiskUsage", "SoftwareCount",
    "NetworkInMbps", "NetworkOutMbps", "TopProcessesJson", "Timestamp"
FROM "AgentReports"
ON CONFLICT DO NOTHING;

-- Atomic rename
BEGIN;
ALTER TABLE "AgentReports"             RENAME TO "AgentReports_old";
ALTER TABLE "AgentReports_partitioned" RENAME TO "AgentReports";
COMMIT;

-- DROP TABLE "AgentReports_old";  -- Uncomment after verification


-- =============================================================================
-- SECTION 3: Verification Queries (run after migration)
-- =============================================================================

-- Verify row counts match:
-- SELECT COUNT(*) FROM "ActivityLogs_old";
-- SELECT COUNT(*) FROM "ActivityLogs";

-- Verify partition pruning is working (should show Bitmap Index Scan on child):
-- EXPLAIN SELECT * FROM "ActivityLogs"
-- WHERE "Timestamp" >= '2026-09-01' AND "Timestamp" < '2026-10-01';

-- List all partitions and their sizes:
-- SELECT
--     child.relname AS partition_name,
--     pg_size_pretty(pg_total_relation_size(child.oid)) AS size
-- FROM pg_inherits
-- JOIN pg_class parent ON pg_inherits.inhparent = parent.oid
-- JOIN pg_class child  ON pg_inherits.inhrelid  = child.oid
-- WHERE parent.relname IN ('ActivityLogs', 'AgentReports')
-- ORDER BY partition_name;
