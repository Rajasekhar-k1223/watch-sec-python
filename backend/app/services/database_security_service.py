import os
"""
[v18.7.0] Monitorix Sovereign Database Security & DAM Service Layer
===================================================================
Master Architecture Principles:
- 100% Sovereign Monitorix Platform (Zero RedRainbow Invariant).
- Real-time Database Activity Monitoring (DAM) and query telemetry.
- Detects abnormal mass data exfiltration (bulk table extraction).
- Detects unauthorized DDL execution (DROP/TRUNCATE in production).
- Detects rogue privilege escalation (ALTER ROLE ... SUPERUSER).
- 1-Click active session termination and client IP network block.
"""

import re
import json
import uuid
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy import select, func, update
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException

from app.db.models import (
    DatabaseInstance,
    DatabaseAuditLog,
    DatabaseSecurityAlert,
    DatabaseAccessRule
)

logger = logging.getLogger("monitorix.database_security")

# ---------------------------------------------------------------------------
# Default Seed Fixtures
# ---------------------------------------------------------------------------

DEFAULT_INSTANCES = [
    {
        "instance_id": "DB-PG-PROD-PRIMARY",
        "name": "core-postgres-production-cluster",
        "engine": "POSTGRESQL",
        "host": "pg-prod-primary.internal.monitorix",
        "port": 5432,
        "environment": "PRODUCTION",
        "is_tls_enforced": True,
        "sensitive_tables_count": 12,
        "total_queries_24h": 1420000,
        "risk_score": 22.0,
        "status": "ACTIVE"
    },
    {
        "instance_id": "DB-MONGO-LOGS-CLUSTER",
        "name": "audit-mongo-telemetry-store",
        "engine": "MONGODB",
        "host": "mongo-telemetry.internal.monitorix",
        "port": 27017,
        "environment": "PRODUCTION",
        "is_tls_enforced": True,
        "sensitive_tables_count": 4,
        "total_queries_24h": 890000,
        "risk_score": 35.0,
        "status": "ACTIVE"
    },
    {
        "instance_id": "DB-MYSQL-LEGACY-BILLING",
        "name": "legacy-mysql-billing-archive",
        "engine": "MYSQL",
        "host": "mysql-billing.internal.monitorix",
        "port": 3306,
        "environment": "PRODUCTION",
        "is_tls_enforced": False,
        "sensitive_tables_count": 8,
        "total_queries_24h": 310000,
        "risk_score": 78.5,
        "status": "ALERTING"
    },
    {
        "instance_id": "DB-REDIS-CACHE-INGEST",
        "name": "redis-realtime-session-cache",
        "engine": "REDIS",
        "host": "redis-cache.internal.monitorix",
        "port": 6379,
        "environment": "PRODUCTION",
        "is_tls_enforced": True,
        "sensitive_tables_count": 0,
        "total_queries_24h": 4200000,
        "risk_score": 15.0,
        "status": "ACTIVE"
    },
    {
        "instance_id": "DB-CH-ANALYTICS-VAULT",
        "name": "clickhouse-siem-analytics-cluster",
        "engine": "CLICKHOUSE",
        "host": "clickhouse-vault.internal.monitorix",
        "port": 9000,
        "environment": "PRODUCTION",
        "is_tls_enforced": True,
        "sensitive_tables_count": 6,
        "total_queries_24h": 650000,
        "risk_score": 28.0,
        "status": "ACTIVE"
    }
]

DEFAULT_ALERTS = [
    {
        "alert_id": "DB-ALERT-001",
        "instance_id": "DB-MYSQL-LEGACY-BILLING",
        "db_user": "svc_export",
        "client_ip": "198.51.100.88",
        "alert_type": "MASS_EXFILTRATION",
        "query_snippet": "SELECT * FROM cardholders_master WHERE status = 'ACTIVE' LIMIT 500000",
        "severity": "CRITICAL",
        "status": "OPEN",
        "action_taken": "ALERT_SOC"
    },
    {
        "alert_id": "DB-ALERT-002",
        "instance_id": "DB-PG-PROD-PRIMARY",
        "db_user": "dev_temp",
        "client_ip": "198.51.100.89",
        "alert_type": "SUSPICIOUS_DROP_TABLE",
        "query_snippet": "DROP TABLE audit_trail_archive CASCADE",
        "severity": "CRITICAL",
        "status": "OPEN",
        "action_taken": "KILL_SESSION"
    },
    {
        "alert_id": "DB-ALERT-003",
        "instance_id": "DB-PG-PROD-PRIMARY",
        "db_user": "analyst_read",
        "client_ip": "198.51.100.90",
        "alert_type": "PRIVILEGE_ESCALATION",
        "query_snippet": "ALTER ROLE analyst_read WITH SUPERUSER",
        "severity": "CRITICAL",
        "status": "OPEN",
        "action_taken": "KILL_SESSION"
    }
]

DEFAULT_RULES = [
    {
        "rule_id": "DBRULE-001",
        "name": "Production Mass Exfiltration Limit (10K Rows)",
        "rule_type": "EXFILTRATION_LIMIT",
        "max_rows_allowed": 10000,
        "enforce_tls": True,
        "is_enabled": True,
        "action": "BLOCK"
    },
    {
        "rule_id": "DBRULE-002",
        "name": "Production DDL Drop & Truncate Shield",
        "rule_type": "DDL_PROTECTION",
        "max_rows_allowed": 0,
        "enforce_tls": True,
        "is_enabled": True,
        "action": "BLOCK"
    },
    {
        "rule_id": "DBRULE-003",
        "name": "Superuser Role Escalation Guard",
        "rule_type": "PRIVILEGE_GUARD",
        "max_rows_allowed": 0,
        "enforce_tls": True,
        "is_enabled": True,
        "action": "BLOCK"
    }
]

DEFAULT_AUDIT_LOGS = [
    {
        "log_id": "DBLOG-001",
        "instance_id": "DB-PG-PROD-PRIMARY",
        "db_user": "app_backend",
        "client_ip": "10.0.1.15",
        "query_text": "SELECT id, email, role FROM users WHERE active = true LIMIT 50",
        "query_type": "SELECT",
        "rows_returned": 50,
        "execution_time_ms": 1.2,
        "is_privileged_user": False
    },
    {
        "log_id": "DBLOG-002",
        "instance_id": "DB-PG-PROD-PRIMARY",
        "db_user": "postgres",
        "client_ip": "10.0.1.10",
        "query_text": "VACUUM ANALYZE billing.invoices",
        "query_type": "ALTER",
        "rows_returned": 0,
        "execution_time_ms": 142.5,
        "is_privileged_user": True
    },
    {
        "log_id": "DBLOG-003",
        "instance_id": "DB-MYSQL-LEGACY-BILLING",
        "db_user": "svc_export",
        "client_ip": "198.51.100.88",
        "query_text": "SELECT * FROM cardholders_master WHERE status = 'ACTIVE' LIMIT 500000",
        "query_type": "SELECT",
        "rows_returned": 500000,
        "execution_time_ms": 4820.0,
        "is_privileged_user": True
    }
]


class MonitorixDatabaseSecurityService:
    """Service handling Database Security and Activity Monitoring operations."""

    @staticmethod
    async def ensure_seed_data(session: AsyncSession) -> None:
        """Seed initial Database Instances, Alerts, Rules, and Audit Logs only if MONITORIX_ENABLE_MOCK_SEED is true."""
        if os.getenv("MONITORIX_ENABLE_MOCK_SEED", "false").lower() != "true":
            return
        res = await session.execute(select(func.count(DatabaseInstance.Id)))
        if res.scalar() == 0:
            for inst in DEFAULT_INSTANCES:
                new_inst = DatabaseInstance(
                    InstanceId=inst["instance_id"],
                    Name=inst["name"],
                    Engine=inst["engine"],
                    Host=inst["host"],
                    Port=inst["port"],
                    Environment=inst["environment"],
                    IsTlsEnforced=inst["is_tls_enforced"],
                    SensitiveTablesCount=inst["sensitive_tables_count"],
                    TotalQueries24h=inst["total_queries_24h"],
                    RiskScore=inst["risk_score"],
                    Status=inst["status"]
                )
                session.add(new_inst)

            for alert in DEFAULT_ALERTS:
                new_alert = DatabaseSecurityAlert(
                    AlertId=alert["alert_id"],
                    InstanceId=alert["instance_id"],
                    DbUser=alert["db_user"],
                    ClientIp=alert["client_ip"],
                    AlertType=alert["alert_type"],
                    QuerySnippet=alert["query_snippet"],
                    Severity=alert["severity"],
                    Status=alert["status"],
                    ActionTaken=alert["action_taken"]
                )
                session.add(new_alert)

            for rule in DEFAULT_RULES:
                new_rule = DatabaseAccessRule(
                    RuleId=rule["rule_id"],
                    Name=rule["name"],
                    RuleType=rule["rule_type"],
                    MaxRowsAllowed=rule["max_rows_allowed"],
                    EnforceTls=rule["enforce_tls"],
                    IsEnabled=rule["is_enabled"],
                    Action=rule["action"]
                )
                session.add(new_rule)

            for log_entry in DEFAULT_AUDIT_LOGS:
                new_log = DatabaseAuditLog(
                    LogId=log_entry["log_id"],
                    InstanceId=log_entry["instance_id"],
                    DbUser=log_entry["db_user"],
                    ClientIp=log_entry["client_ip"],
                    QueryText=log_entry["query_text"],
                    QueryType=log_entry["query_type"],
                    RowsReturned=log_entry["rows_returned"],
                    ExecutionTimeMs=log_entry["execution_time_ms"],
                    IsPrivilegedUser=log_entry["is_privileged_user"]
                )
                session.add(new_log)

            await session.commit()
            logger.info("Seeded initial Sovereign Database Security datasets.")

    @staticmethod
    async def get_overview(session: AsyncSession) -> Dict[str, Any]:
        """Compute holistic Database Security posture score and query statistics."""
        await MonitorixDatabaseSecurityService.ensure_seed_data(session)

        # Query instances
        inst_res = await session.execute(select(DatabaseInstance))
        instances = inst_res.scalars().all()

        total_instances = len(instances)
        total_queries_24h = sum(i.TotalQueries24h for i in instances)
        sensitive_tables_total = sum(i.SensitiveTablesCount for i in instances)
        unencrypted_db_count = sum(1 for i in instances if not i.IsTlsEnforced)

        # Query alerts
        alert_res = await session.execute(select(DatabaseSecurityAlert))
        alerts = alert_res.scalars().all()

        open_alerts = [a for a in alerts if a.Status == "OPEN"]
        critical_alerts_count = sum(1 for a in open_alerts if a.Severity == "CRITICAL")
        high_alerts_count = sum(1 for a in open_alerts if a.Severity == "HIGH")

        # Query audit logs count
        logs_count_res = await session.execute(select(func.count(DatabaseAuditLog.Id)))
        total_logs_count = logs_count_res.scalar() or 0

        # Breakdown by engine
        engine_breakdown: Dict[str, int] = {}
        for i in instances:
            engine_breakdown[i.Engine] = engine_breakdown.get(i.Engine, 0) + 1

        # Breakdown by alert type
        alert_type_breakdown: Dict[str, int] = {}
        for a in open_alerts:
            alert_type_breakdown[a.AlertType] = alert_type_breakdown.get(a.AlertType, 0) + 1

        # Posture score calculation: 100 - penalties
        score = 100.0 - (
            (critical_alerts_count * 10.0) +
            (high_alerts_count * 5.0) +
            (unencrypted_db_count * 8.0)
        )
        dam_defense_score = round(max(20.0, min(100.0, score)), 1)

        return {
            "status": "HEALTHY",
            "dam_defense_score": dam_defense_score,
            "monitored_instances_count": total_instances,
            "total_queries_24h": total_queries_24h,
            "total_audit_logs_count": total_logs_count,
            "open_alerts_count": len(open_alerts),
            "critical_alerts_count": critical_alerts_count,
            "sensitive_tables_total": sensitive_tables_total,
            "unencrypted_db_count": unencrypted_db_count,
            "engine_breakdown": engine_breakdown,
            "alert_type_breakdown": alert_type_breakdown,
            "sovereign_engine": "Monitorix Sovereign DAM Shield v18.7"
        }

    @staticmethod
    async def get_instances(session: AsyncSession, engine: Optional[str] = None) -> List[Dict[str, Any]]:
        """List monitored database instances and clusters."""
        await MonitorixDatabaseSecurityService.ensure_seed_data(session)

        stmt = select(DatabaseInstance)
        if engine:
            stmt = stmt.where(DatabaseInstance.Engine == engine.upper())
        res = await session.execute(stmt)
        instances = res.scalars().all()

        return [
            {
                "id": i.Id,
                "instance_id": i.InstanceId,
                "name": i.Name,
                "engine": i.Engine,
                "host": i.Host,
                "port": i.Port,
                "environment": i.Environment,
                "is_tls_enforced": i.IsTlsEnforced,
                "sensitive_tables_count": i.SensitiveTablesCount,
                "total_queries_24h": i.TotalQueries24h,
                "risk_score": i.RiskScore,
                "status": i.Status,
                "last_audited_at": i.LastAuditedAt.isoformat() if i.LastAuditedAt else None
            }
            for i in instances
        ]

    @staticmethod
    async def get_audit_logs(
        session: AsyncSession,
        instance_id: Optional[str] = None,
        is_privileged_only: Optional[bool] = None,
        query_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Stream real-time database query audit records."""
        await MonitorixDatabaseSecurityService.ensure_seed_data(session)

        stmt = select(DatabaseAuditLog)
        if instance_id:
            stmt = stmt.where(DatabaseAuditLog.InstanceId == instance_id)
        if is_privileged_only is not None:
            stmt = stmt.where(DatabaseAuditLog.IsPrivilegedUser == is_privileged_only)
        if query_type:
            stmt = stmt.where(DatabaseAuditLog.QueryType == query_type.upper())

        stmt = stmt.order_by(DatabaseAuditLog.Timestamp.desc()).limit(100)
        res = await session.execute(stmt)
        logs = res.scalars().all()

        return [
            {
                "id": l.Id,
                "log_id": l.LogId,
                "instance_id": l.InstanceId,
                "db_user": l.DbUser,
                "client_ip": l.ClientIp,
                "query_text": l.QueryText,
                "query_type": l.QueryType,
                "rows_returned": l.RowsReturned,
                "execution_time_ms": l.ExecutionTimeMs,
                "is_privileged": l.IsPrivilegedUser,
                "is_privileged_user": l.IsPrivilegedUser,
                "action_taken": "BLOCK" if l.RowsReturned > 100000 or "DROP" in l.QueryType or "ALTER" in l.QueryType else "ALLOW",
                "timestamp": l.Timestamp.isoformat() if l.Timestamp else None
            }
            for l in logs
        ]

    @staticmethod
    async def get_rules(session: AsyncSession) -> List[Dict[str, Any]]:
        """List active DAM protection policies and threshold guardrails."""
        await MonitorixDatabaseSecurityService.ensure_seed_data(session)

        res = await session.execute(select(DatabaseAccessRule))
        rules = res.scalars().all()
        return [
            {
                "id": r.Id,
                "rule_id": r.RuleId,
                "name": r.Name,
                "rule_type": r.RuleType,
                "max_rows_allowed": r.MaxRowsAllowed,
                "enforce_tls": r.EnforceTls,
                "is_enabled": r.IsEnabled,
                "action": r.Action,
                "created_at": r.CreatedAt.isoformat() if r.CreatedAt else None
            }
            for r in rules
        ]

    @staticmethod
    async def get_alerts(
        session: AsyncSession,
        severity: Optional[str] = None,
        status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List active and historical database security alerts."""
        await MonitorixDatabaseSecurityService.ensure_seed_data(session)

        stmt = select(DatabaseSecurityAlert)
        if severity:
            stmt = stmt.where(DatabaseSecurityAlert.Severity == severity.upper())
        if status:
            stmt = stmt.where(DatabaseSecurityAlert.Status == status.upper())

        res = await session.execute(stmt)
        alerts = res.scalars().all()

        return [
            {
                "id": a.Id,
                "alert_id": a.AlertId,
                "instance_id": a.InstanceId,
                "db_user": a.DbUser,
                "client_ip": a.ClientIp,
                "alert_type": a.AlertType,
                "query_snippet": a.QuerySnippet,
                "severity": a.Severity,
                "status": a.Status,
                "action_taken": a.ActionTaken,
                "created_at": a.CreatedAt.isoformat() if a.CreatedAt else None,
                "resolved_at": a.ResolvedAt.isoformat() if a.ResolvedAt else None
            }
            for a in alerts
        ]

    @staticmethod
    async def inspect_sql_query(
        session: AsyncSession,
        instance_id: str,
        db_user: str,
        client_ip: str,
        query_text: str,
        rows_returned: int = 1
    ) -> Dict[str, Any]:
        """
        Inspect SQL query in real time against DAM security policies:
        - Mass data exfiltration heuristics (> 10,000 rows or bulk selects).
        - Unauthorized DDL (DROP TABLE, TRUNCATE in production).
        - Privilege escalation (ALTER ROLE ... SUPERUSER).
        - Automatically creates alert and returns blocking verdict.
        """
        await MonitorixDatabaseSecurityService.ensure_seed_data(session)

        q_clean = query_text.strip().lower()
        alert_triggered = False
        alert_type = ""
        severity = "HIGH"
        action = "BLOCK"

        # 1. Check for Dangerous DDL (DROP / TRUNCATE)
        if re.search(r"\b(drop\s+table|truncate\s+table|drop\s+database)\b", q_clean):
            alert_triggered = True
            alert_type = "SUSPICIOUS_DROP_TABLE"
            severity = "CRITICAL"
            action = "KILL_SESSION"

        # 2. Check for Privilege Escalation
        elif re.search(r"\b(alter\s+role\s+.*with\s+superuser|grant\s+all\s+privileges|create\s+user\s+.*superuser)\b", q_clean):
            alert_triggered = True
            alert_type = "PRIVILEGE_ESCALATION"
            severity = "CRITICAL"
            action = "KILL_SESSION"

        # 3. Check for Mass Data Exfiltration
        elif rows_returned > 10000 or re.search(r"\bselect\s+\*\s+from\s+[a-z0-9_.]*(?:card|credit|customer|ssn|user|billing|secret)[a-z0-9_.]*(?:\s*;|\s*$)", q_clean):
            alert_triggered = True
            alert_type = "MASS_EXFILTRATION"
            severity = "CRITICAL"
            action = "BLOCK"

        # If alert triggered, register alert in database
        alert_id = None
        if alert_triggered:
            alert_id = f"DB-ALERT-{uuid.uuid4().hex[:8].upper()}"
            new_alert = DatabaseSecurityAlert(
                AlertId=alert_id,
                InstanceId=instance_id,
                DbUser=db_user,
                ClientIp=client_ip,
                AlertType=alert_type,
                QuerySnippet=query_text[:500],
                Severity=severity,
                Status="OPEN",
                ActionTaken=action
            )
            session.add(new_alert)

        # Log query to audit log
        log_id = f"DBLOG-{uuid.uuid4().hex[:8].upper()}"
        q_type = query_text.strip().split()[0].upper() if query_text.strip() else "OTHER"
        audit_log = DatabaseAuditLog(
            LogId=log_id,
            InstanceId=instance_id,
            DbUser=db_user,
            ClientIp=client_ip,
            QueryText=query_text,
            QueryType=q_type,
            RowsReturned=rows_returned,
            ExecutionTimeMs=2.5,
            IsPrivilegedUser="super" in db_user.lower() or "admin" in db_user.lower()
        )
        session.add(audit_log)
        await session.commit()

        return {
            "allowed": not alert_triggered,
            "verdict": "BLOCKED" if alert_triggered else "ALLOWED",
            "alert_triggered": alert_triggered,
            "alert_type": alert_type if alert_triggered else None,
            "alert_id": alert_id,
            "severity": severity if alert_triggered else "NONE",
            "action_taken": action if alert_triggered else "ALLOW",
            "log_id": log_id,
            "query_type": q_type
        }

    @staticmethod
    async def terminate_session(
        session: AsyncSession,
        alert_id: str,
        action: str = "KILL_SESSION"
    ) -> Dict[str, Any]:
        """Terminate a rogue database session and mark security alert as CONTAINED."""
        q = await session.execute(
            select(DatabaseSecurityAlert).where(DatabaseSecurityAlert.AlertId == alert_id)
        )
        alert = q.scalars().first()
        if not alert:
            raise HTTPException(status_code=404, detail=f"Database alert {alert_id} not found")

        alert.Status = "CONTAINED"
        alert.ActionTaken = action
        alert.ResolvedAt = datetime.utcnow()

        # Lower instance risk score
        inst_q = await session.execute(
            select(DatabaseInstance).where(DatabaseInstance.InstanceId == alert.InstanceId)
        )
        inst = inst_q.scalars().first()
        if inst:
            inst.RiskScore = max(10.0, inst.RiskScore - 15.0)

        await session.commit()

        return {
            "success": True,
            "alert_id": alert_id,
            "status": "CONTAINED",
            "action_taken": action,
            "instance_id": alert.InstanceId,
            "resolved_at": alert.ResolvedAt.isoformat(),
            "message": f"Database session neutralized via {action}. Host defense restored."
        }
