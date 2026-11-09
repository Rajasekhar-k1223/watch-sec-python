-- ==============================================================================
-- MONITORIX ENTERPRISE — PHASE 5.4.3B
-- Rollback Migration: Revert TenantId on DetectionAlerts
-- ==============================================================================

BEGIN;

-- Step 1: Drop Foreign Key constraint
ALTER TABLE "DetectionAlerts"
DROP CONSTRAINT IF EXISTS "fk_DetectionAlerts_TenantId";

-- Step 2: Drop index
DROP INDEX IF EXISTS "ix_DetectionAlerts_TenantId";

-- Step 3: Drop column
ALTER TABLE "DetectionAlerts"
DROP COLUMN IF EXISTS "TenantId";

COMMIT;

