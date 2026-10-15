-- =============================================================================
-- MONITORIX — init-db.sql
-- Master database initialization / optimization script.
-- Run this once after the schema is created (after SQLAlchemy create_all).
--
-- Order matters:
--   1. Indexes      — no dependencies
--   2. Functions    — no dependencies
--   3. Views        — depend on tables and may reference functions
--   4. Materialized Views — depend on tables and views
--   5. Procedures   — depend on tables only
--
-- NOTE: Partitioning (pg_partitioning.sql) is NOT included here.
--       It is a one-time migration run manually during a maintenance window.
--
-- Usage:
--   psql -d $DATABASE_URL -f init-db.sql
--   OR from Python on startup:
--   async with engine.begin() as conn:
--       await conn.execute(text(open("app/db/init-db.sql").read()))
-- =============================================================================

-- 1. Indexes (safe to re-run — all use IF NOT EXISTS)
\i pg_indexes.sql

-- 2. SQL Functions (safe to re-run — all use CREATE OR REPLACE)
\i pg_functions.sql

-- 3. Views (safe to re-run — all use CREATE OR REPLACE VIEW)
\i pg_views.sql

-- 4. Materialized Views (destructive: uses DROP IF EXISTS + CREATE)
--    On first run these will be empty (WITH NO DATA).
--    The background task will populate them within 5 minutes.
\i pg_materialized_views.sql

-- 5. Stored Procedures (safe to re-run — all use CREATE OR REPLACE)
\i pg_procedures.sql

-- Initial populate of materialized views (runs immediately on first apply)
-- Comment this out if you have very large tables and prefer background refresh.
SELECT refresh_all_materialized_views();
