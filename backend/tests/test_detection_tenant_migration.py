#!/usr/bin/env python3
"""
MONITORIX ENTERPRISE — PHASE 5.4.3C TEST SUITE (PART 1)
Detection Alerts TenantId Migration & Rehearsal Validation
==========================================================
Validates:
 1. Pre-migration schema audit & readiness metrics
 2. Forward migration execution on isolated rehearsal table
 3. Successful authoritative historical backfill (AgentId -> Agents.TenantId)
 4. Missing agent ownership handling (safe NULL retention, zero invented data)
 5. Ambiguous agent/tenant state resolution
 6. Orphaned alert preservation (non-existent agent preserves alert with NULL tenant)
 7. Foreign-key constraint integrity (ON DELETE SET NULL verification)
 8. Composite performance indexing (ix_DetectionAlerts_Tenant_Status_Time)
 9. Reversible rollback execution & zero data loss verification
10. Query plan optimization & execution speedup measurement
"""

import os
import sys
import time
import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List

# Ensure backend path is in sys.path
for candidate in ["/app", "/opt/projects/monitorix/watch-sec-python/backend"]:
    if os.path.exists(candidate) and candidate not in sys.path:
        sys.path.insert(0, candidate)

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import text

PASSED = 0
FAILED = 0
TEST_RESULTS = []


def record_result(test_num: int, name: str, passed: bool, duration_ms: float, detail: str = ""):
    global PASSED, FAILED
    status = "PASS" if passed else "FAIL"
    if passed:
        PASSED += 1
    else:
        FAILED += 1
    TEST_RESULTS.append({
        "test_num": test_num,
        "name": name,
        "status": status,
        "duration_ms": duration_ms,
        "detail": detail
    })
    print(f"  [{status}] #{test_num:02d}: {name} ({duration_ms:.2f}ms) {detail}")


async def run_suite():
    global PASSED, FAILED
    print("=" * 80)
    print("MONITORIX ENTERPRISE — PHASE 5.4.3C TEST SUITE (PART 1)")
    print("DetectionAlerts Tenant Migration Rehearsal & Historical Audit")
    print("=" * 80)

    # Use AsyncSessionLocal to run rehearsal in an isolated schema
    from app.db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        # Create isolated rehearsal schema
        await session.execute(text("CREATE SCHEMA IF NOT EXISTS rehearsal_migration_suite;"))
        
        # Setup rehearsal tables mirroring production
        await session.execute(text("""
            CREATE TABLE IF NOT EXISTS rehearsal_migration_suite."Tenants" (
                "Id" INTEGER PRIMARY KEY,
                "Name" VARCHAR(255)
            )
        """))
        await session.execute(text("""
            CREATE TABLE IF NOT EXISTS rehearsal_migration_suite."Agents" (
                "Id" SERIAL PRIMARY KEY,
                "AgentId" VARCHAR(50) UNIQUE,
                "TenantId" INTEGER,
                "Hostname" VARCHAR(255)
            )
        """))
        await session.execute(text("""
            CREATE TABLE IF NOT EXISTS rehearsal_migration_suite."DetectionAlerts" (
                "Id" SERIAL PRIMARY KEY,
                "AgentId" VARCHAR(50),
                "RuleId" INTEGER,
                "TelemetryId" INTEGER,
                "MatchedContent" TEXT,
                "Status" VARCHAR(50) DEFAULT 'New',
                "Timestamp" TIMESTAMP DEFAULT NOW(),
                "HitCount" INTEGER DEFAULT 1,
                "LastSeenAt" TIMESTAMP DEFAULT NOW()
            )
        """))

        # Seed mock tenants
        await session.execute(text('DELETE FROM rehearsal_migration_suite."DetectionAlerts";'))
        await session.execute(text('DELETE FROM rehearsal_migration_suite."Agents";'))
        await session.execute(text('DELETE FROM rehearsal_migration_suite."Tenants";'))
        await session.execute(text("""
            INSERT INTO rehearsal_migration_suite."Tenants" ("Id", "Name") VALUES 
                (1, 'Tenant Alpha'),
                (2, 'Tenant Beta'),
                (3, 'Tenant Gamma')
        """))

        # Seed mock agents
        await session.execute(text("""
            INSERT INTO rehearsal_migration_suite."Agents" ("AgentId", "TenantId", "Hostname") VALUES 
                ('AGENT-ALPHA-01', 1, 'alpha-srv-01'),
                ('AGENT-ALPHA-02', 1, 'alpha-srv-02'),
                ('AGENT-BETA-01',  2, 'beta-srv-01'),
                ('AGENT-GAMMA-01', 3, 'gamma-srv-01'),
                ('AGENT-NO-TENANT', NULL, 'unassigned-host')
        """))

        # Seed alerts
        await session.execute(text("""
            INSERT INTO rehearsal_migration_suite."DetectionAlerts" ("Id", "AgentId", "RuleId", "MatchedContent", "Status", "Timestamp") VALUES 
                (101, 'AGENT-ALPHA-01', 2, 'Mimikatz Execution 1', 'New', NOW() - INTERVAL '10 minutes'),
                (102, 'AGENT-ALPHA-01', 2, 'Mimikatz Execution 2', 'Investigating', NOW() - INTERVAL '5 minutes'),
                (103, 'AGENT-ALPHA-02', 3, 'PowerShell Bypass', 'New', NOW() - INTERVAL '3 minutes'),
                (104, 'AGENT-BETA-01',  4, 'Firewall Disabled', 'New', NOW() - INTERVAL '2 minutes'),
                (105, 'AGENT-GAMMA-01', 5, 'Pass-the-Hash', 'Closed', NOW() - INTERVAL '1 minute'),
                (106, '',               2, 'Empty Agent Alert', 'New', NOW()),
                (107, NULL,             2, 'NULL Agent Alert', 'New', NOW()),
                (108, 'AGENT-DELETED-999', 2, 'Orphan Alert (Agent purged)', 'New', NOW()),
                (109, 'AGENT-NO-TENANT', 2, 'Agent with no tenant in DB', 'New', NOW())
        """))
        await session.commit()

        # ----------------------------------------------------------------------
        # TEST 01: Pre-migration schema audit & readiness inspection
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        col_res = await session.execute(text("""
            SELECT column_name FROM information_schema.columns 
            WHERE table_schema = 'rehearsal_migration_suite' 
              AND table_name = 'DetectionAlerts' 
              AND column_name = 'TenantId';
        """))
        has_col = bool(col_res.scalar())
        tot_alerts = (await session.execute(text('SELECT count(*) FROM rehearsal_migration_suite."DetectionAlerts";'))).scalar()
        d1 = (time.perf_counter() - t0) * 1000
        p1 = (not has_col and tot_alerts == 9)
        record_result(1, "Pre-Migration Schema Audit & Readiness Verification", p1, d1, f"(TotalAlerts={tot_alerts}, HasTenantId={has_col})")

        # ----------------------------------------------------------------------
        # TEST 02: Forward migration execution on rehearsal table
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        await session.execute(text("""
            ALTER TABLE rehearsal_migration_suite."DetectionAlerts" 
            ADD COLUMN IF NOT EXISTS "TenantId" INTEGER;
        """))
        await session.commit()
        d2 = (time.perf_counter() - t0) * 1000
        col_check = await session.execute(text("""
            SELECT column_name FROM information_schema.columns 
            WHERE table_schema = 'rehearsal_migration_suite' 
              AND table_name = 'DetectionAlerts' 
              AND column_name = 'TenantId';
        """))
        p2 = bool(col_check.scalar())
        record_result(2, "Forward Migration DDL (ADD COLUMN TenantId)", p2, d2)

        # ----------------------------------------------------------------------
        # TEST 03: Authoritative historical backfill execution
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        bf_res = await session.execute(text("""
            UPDATE rehearsal_migration_suite."DetectionAlerts" da
            SET "TenantId" = a."TenantId"
            FROM rehearsal_migration_suite."Agents" a
            WHERE da."AgentId" = a."AgentId"
              AND da."TenantId" IS NULL
              AND a."TenantId" IS NOT NULL;
        """))
        rows_updated = bf_res.rowcount
        await session.commit()
        d3 = (time.perf_counter() - t0) * 1000

        # Verify exact backfilled rows
        t1_count = (await session.execute(text('SELECT count(*) FROM rehearsal_migration_suite."DetectionAlerts" WHERE "TenantId" = 1;'))).scalar()
        t2_count = (await session.execute(text('SELECT count(*) FROM rehearsal_migration_suite."DetectionAlerts" WHERE "TenantId" = 2;'))).scalar()
        t3_count = (await session.execute(text('SELECT count(*) FROM rehearsal_migration_suite."DetectionAlerts" WHERE "TenantId" = 3;'))).scalar()
        p3 = (rows_updated == 5 and t1_count == 3 and t2_count == 1 and t3_count == 1)
        record_result(3, "Authoritative Historical Backfill Verification", p3, d3, f"(Backfilled={rows_updated}, T1={t1_count}, T2={t2_count}, T3={t3_count})")

        # ----------------------------------------------------------------------
        # TEST 04: Missing agent ownership handling (safe NULL retention)
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        empty_agent_alert = (await session.execute(text('SELECT "TenantId" FROM rehearsal_migration_suite."DetectionAlerts" WHERE "Id" = 106;'))).scalar()
        null_agent_alert = (await session.execute(text('SELECT "TenantId" FROM rehearsal_migration_suite."DetectionAlerts" WHERE "Id" = 107;'))).scalar()
        d4 = (time.perf_counter() - t0) * 1000
        # Invariant: Never invent tenant ownership or assign default! Must remain NULL.
        p4 = (empty_agent_alert is None and null_agent_alert is None)
        record_result(4, "Missing Agent Ownership (Safe NULL Preservation)", p4, d4, "(Empty and NULL AgentId preserve NULL TenantId)")

        # ----------------------------------------------------------------------
        # TEST 05: Ambiguous agent/tenant state resolution
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        no_tenant_agent_alert = (await session.execute(text('SELECT "TenantId" FROM rehearsal_migration_suite."DetectionAlerts" WHERE "Id" = 109;'))).scalar()
        d5 = (time.perf_counter() - t0) * 1000
        p5 = (no_tenant_agent_alert is None)
        record_result(5, "Ambiguous Agent State (Agent without Tenant retains NULL)", p5, d5)

        # ----------------------------------------------------------------------
        # TEST 06: Orphaned alert preservation (purged agent preserves alert)
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        orphan_alert = (await session.execute(text('SELECT "Id", "TenantId", "MatchedContent" FROM rehearsal_migration_suite."DetectionAlerts" WHERE "Id" = 108;'))).first()
        tot_alerts_after = (await session.execute(text('SELECT count(*) FROM rehearsal_migration_suite."DetectionAlerts";'))).scalar()
        d6 = (time.perf_counter() - t0) * 1000
        p6 = (orphan_alert is not None and orphan_alert[1] is None and tot_alerts_after == 9)
        record_result(6, "Orphaned Alert Preservation (Zero Data Loss Invariant)", p6, d6, "(Orphan alert preserved with TenantId=NULL)")

        # ----------------------------------------------------------------------
        # TEST 07: Foreign-key constraint integrity (ON DELETE SET NULL)
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        await session.execute(text("""
            ALTER TABLE rehearsal_migration_suite."DetectionAlerts"
            ADD CONSTRAINT "fk_reh_DetectionAlerts_TenantId"
            FOREIGN KEY ("TenantId") REFERENCES rehearsal_migration_suite."Tenants"("Id")
            ON DELETE SET NULL;
        """))
        await session.commit()
        
        # Test ON DELETE SET NULL behavior
        await session.execute(text('DELETE FROM rehearsal_migration_suite."Tenants" WHERE "Id" = 2;'))
        await session.commit()
        t2_alert_tenant = (await session.execute(text('SELECT "TenantId" FROM rehearsal_migration_suite."DetectionAlerts" WHERE "Id" = 104;'))).scalar()
        t2_alert_exists = (await session.execute(text('SELECT count(*) FROM rehearsal_migration_suite."DetectionAlerts" WHERE "Id" = 104;'))).scalar()
        d7 = (time.perf_counter() - t0) * 1000
        p7 = (t2_alert_exists == 1 and t2_alert_tenant is None)
        record_result(7, "Foreign-Key Constraint Integrity & ON DELETE SET NULL", p7, d7, "(Alert preserved when tenant deleted)")

        # ----------------------------------------------------------------------
        # TEST 08: Composite performance indexing
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        await session.execute(text("""
            CREATE INDEX IF NOT EXISTS "ix_reh_alerts_tenant" 
            ON rehearsal_migration_suite."DetectionAlerts" ("TenantId");
        """))
        await session.execute(text("""
            CREATE INDEX IF NOT EXISTS "ix_reh_alerts_tenant_status_time" 
            ON rehearsal_migration_suite."DetectionAlerts" ("TenantId", "Status", "Timestamp" DESC);
        """))
        await session.commit()
        d8 = (time.perf_counter() - t0) * 1000
        idx_count = (await session.execute(text("""
            SELECT count(*) FROM pg_indexes 
            WHERE schemaname = 'rehearsal_migration_suite' 
              AND indexname IN ('ix_reh_alerts_tenant', 'ix_reh_alerts_tenant_status_time');
        """))).scalar()
        p8 = (idx_count == 2)
        record_result(8, "Composite Performance Index Creation", p8, d8)

        # ----------------------------------------------------------------------
        # TEST 09: Reversible rollback execution & zero record loss
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        await session.execute(text("""
            ALTER TABLE rehearsal_migration_suite."DetectionAlerts"
            DROP CONSTRAINT IF EXISTS "fk_reh_DetectionAlerts_TenantId";
        """))
        await session.execute(text("""
            DROP INDEX IF EXISTS rehearsal_migration_suite."ix_reh_alerts_tenant_status_time";
        """))
        await session.execute(text("""
            DROP INDEX IF EXISTS rehearsal_migration_suite."ix_reh_alerts_tenant";
        """))
        await session.execute(text("""
            ALTER TABLE rehearsal_migration_suite."DetectionAlerts"
            DROP COLUMN IF EXISTS "TenantId";
        """))
        await session.commit()
        d9 = (time.perf_counter() - t0) * 1000
        
        # Verify post-rollback state
        col_after_rb = (await session.execute(text("""
            SELECT column_name FROM information_schema.columns 
            WHERE table_schema = 'rehearsal_migration_suite' 
              AND table_name = 'DetectionAlerts' 
              AND column_name = 'TenantId';
        """))).scalar()
        count_after_rb = (await session.execute(text('SELECT count(*) FROM rehearsal_migration_suite."DetectionAlerts";'))).scalar()
        p9 = (col_after_rb is None and count_after_rb == 9)
        record_result(9, "Reversible Rollback DDL & Zero Record Loss", p9, d9, f"(ColumnDropped={col_after_rb is None}, RowsPreserved={count_after_rb}/9)")

        # ----------------------------------------------------------------------
        # TEST 10: Query plan optimization & execution speedup measurement
        # ----------------------------------------------------------------------
        t0 = time.perf_counter()
        # Re-apply migration with 1000 rows to benchmark EXPLAIN ANALYZE
        await session.execute(text("""
            ALTER TABLE rehearsal_migration_suite."DetectionAlerts" ADD COLUMN "TenantId" INTEGER;
        """))
        await session.execute(text("""
            INSERT INTO rehearsal_migration_suite."DetectionAlerts" ("Id", "AgentId", "RuleId", "Status", "Timestamp", "TenantId")
            SELECT 1000 + g, 'AGENT-ALPHA-01', 2, 'New', NOW() - (g || ' minutes')::interval, 1
            FROM generate_series(1, 1000) g;
        """))
        await session.execute(text("""
            CREATE INDEX "ix_bench_tenant_status_time" 
            ON rehearsal_migration_suite."DetectionAlerts" ("TenantId", "Status", "Timestamp" DESC);
        """))
        await session.commit()

        exp_res = await session.execute(text("""
            EXPLAIN (ANALYZE, BUFFERS)
            SELECT * FROM rehearsal_migration_suite."DetectionAlerts"
            WHERE "TenantId" = 1 AND "Status" = 'New'
            ORDER BY "Timestamp" DESC
            LIMIT 50;
        """))
        plan_lines = [r[0] for r in exp_res.fetchall()]
        plan_text = "\n".join(plan_lines)
        d10 = (time.perf_counter() - t0) * 1000
        uses_index_scan = "Index Scan" in plan_text and "ix_bench_tenant_status_time" in plan_text
        record_result(10, "Query Plan Optimization (Verified Index Scan on Composite Key)", uses_index_scan, d10)

        # Cleanup isolated rehearsal schema completely
        await session.execute(text("DROP SCHEMA rehearsal_migration_suite CASCADE;"))
        await session.commit()

    print("\n" + "=" * 80)
    print(f"PART 1 TOTAL: 10 | PASSED: {PASSED} | FAILED: {FAILED}")
    print("=" * 80)
    return FAILED == 0


if __name__ == "__main__":
    success = asyncio.run(run_suite())
    sys.exit(0 if success else 1)
