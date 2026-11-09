-- ==============================================================================
-- MONITORIX ENTERPRISE — PHASE 5.4.3B
-- Migration: Add TenantId to DetectionAlerts with Authoritative Agent Backfill
-- ==============================================================================
-- Guarantees:
-- 1. Never invents tenant ownership.
-- 2. Never deletes existing historical alerts.
-- 3. Never assigns historical alerts to an arbitrary default tenant.
-- 4. Reversible with full rollback script.
-- 5. Safe, non-blocking transactional execution.
-- ==============================================================================

BEGIN;

-- Step 1: Add nullable TenantId column
ALTER TABLE "DetectionAlerts" 
ADD COLUMN IF NOT EXISTS "TenantId" INTEGER;

-- Step 2: Backfill TenantId from Agents table using authoritative AgentId mapping
UPDATE "DetectionAlerts" da
SET "TenantId" = a."TenantId"
FROM "Agents" a
WHERE da."AgentId" = a."AgentId"
  AND da."TenantId" IS NULL;

-- Step 3: Create performance index for tenant-filtered queries
CREATE INDEX IF NOT EXISTS "ix_DetectionAlerts_TenantId" 
ON "DetectionAlerts" ("TenantId");

-- Step 4: Add Foreign Key constraint to Tenants table (ON DELETE SET NULL)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_DetectionAlerts_TenantId'
    ) THEN
        ALTER TABLE "DetectionAlerts"
        ADD CONSTRAINT "fk_DetectionAlerts_TenantId"
        FOREIGN KEY ("TenantId") REFERENCES "Tenants"("Id")
        ON DELETE SET NULL;
    END IF;
END $$;

COMMIT;

