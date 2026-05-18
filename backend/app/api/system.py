from fastapi import APIRouter, Depends, HTTPException # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from sqlalchemy import update # type: ignore
from typing import List, Dict, Any # type: ignore
from pydantic import BaseModel # type: ignore
import time # type: ignore
from datetime import datetime # type: ignore
from app.db.session import get_db # type: ignore
from app.db.models import SystemSetting, User # type: ignore
from app.api.deps import get_current_user # type: ignore

router = APIRouter()

class SettingDto(BaseModel):
    Key: str
    Value: str
    Category: str = "General"
    Description: str = None

@router.get("/system/settings")
async def get_settings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.Role != 'SuperAdmin':
        raise HTTPException(status_code=403, detail="SuperAdmin restricted endpoint")

    result = await db.execute(select(SystemSetting))
    settings = result.scalars().all()
    
    # If empty, seed defaults
    defaults = {
        "DataRetentionDays": ("90", "General", "Days to keep activity logs"),
        "LogLevel": ("INFO", "General", "System logging level"),
        "EnableGlobalLockdown": ("false", "Auth", "Lock all agents"),
        "TrustedIps": ("", "Auth", "Comma-separated whitelist IPs")
    }
    
    if not settings:
        for k, v in defaults.items():
            new_setting = SystemSetting(Key=k, Value=v[0], Category=v[1], Description=v[2])
            db.add(new_setting)
        await db.commit()
        # Re-fetch
        result = await db.execute(select(SystemSetting))
        settings = result.scalars().all()

    # Group by category
    grouped = {}
    for s in settings:
        if s.Category not in grouped: grouped[s.Category] = []
        grouped[s.Category].append({"Key": s.Key, "Value": s.Value, "Description": s.Description})
        
    return grouped

@router.post("/system/settings")
async def update_settings(
    settings: List[SettingDto],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.Role != 'SuperAdmin':
        raise HTTPException(status_code=403, detail="SuperAdmin restricted endpoint")

    for s in settings:
        stmt = select(SystemSetting).where(SystemSetting.Key == s.Key)
        res = await db.execute(stmt)
        existing = res.scalar_one_or_none()
        
        if existing:
            existing.Value = s.Value
        else:
            new_s = SystemSetting(Key=s.Key, Value=s.Value, Category=s.Category, Description=s.Description)
            db.add(new_s)
            
    # [AUDIT]
    from app.db.models import AuditLog # type: ignore
    from datetime import datetime # type: ignore
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action="Update System Settings",
        Target="System Config",
        Details=f"Updated {len(settings)} system settings",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    
@router.get("/system/health")
async def get_system_health(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Diagnostic endpoint to check connectivity of all core services.
    Accessible by SuperAdmin and TenantAdmin roles.
    """
    if current_user.Role not in ['SuperAdmin', 'TenantAdmin']:
        raise HTTPException(status_code=403, detail="Admin restricted endpoint")

    import os # type: ignore
    import shutil # type: ignore
    from sqlalchemy import text, func # type: ignore

    now = datetime.utcnow()

    status: Dict[str, Any] = {
        "overall": "Healthy",
        "timestamp": now.isoformat() + "Z",
        "uptime_check": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "services": {
            "mysql":   {"status": "Checking...", "latency_ms": 0},
            "mongodb": {"status": "Checking...", "latency_ms": 0},
            "redis":   {"status": "Checking...", "latency_ms": 0},
        },
        "database": {},
        "disk": {},
    }

    # ── 1. MySQL ──────────────────────────────────────────────────────────────
    try:
        t0 = time.time()
        await db.execute(select(1))
        status["services"]["mysql"]["latency_ms"] = round((time.time() - t0) * 1000, 2)
        status["services"]["mysql"]["status"] = "Connected"

        # Row counts for key tables
        from app.db.models import Agent, Tenant, EventLog, ActivityLog, User as UserModel # type: ignore
        counts: Dict[str, int] = {}
        for label, Model in [
            ("agents",     Agent),
            ("tenants",    Tenant),
            ("users",      UserModel),
            ("event_logs", EventLog),
            ("activity_logs", ActivityLog),
        ]:
            try:
                res = await db.execute(select(func.count()).select_from(Model))
                counts[label] = res.scalar() or 0
            except Exception:
                counts[label] = -1

        # Online agents
        try:
            online_res = await db.execute(
                select(func.count()).select_from(Agent).where(Agent.Status == "Online")
            )
            counts["agents_online"] = online_res.scalar() or 0
        except Exception:
            counts["agents_online"] = -1

        # DB size (MySQL information_schema)
        try:
            size_q = await db.execute(text(
                "SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) "
                "FROM information_schema.tables WHERE table_schema = DATABASE()"
            ))
            db_size_mb = size_q.scalar()
            status["database"] = {
                "row_counts": counts,
                "size_mb": float(db_size_mb) if db_size_mb else 0,
            }
        except Exception:
            status["database"] = {"row_counts": counts}

    except Exception as e:
        status["services"]["mysql"]["status"] = f"Error: {str(e)}"
        status["overall"] = "Degraded"

    # ── 2. MongoDB ────────────────────────────────────────────────────────────
    try:
        from app.db.session import mongo_client # type: ignore
        t0 = time.time()
        await mongo_client.admin.command('ping')
        latency = round((time.time() - t0) * 1000, 2)
        status["services"]["mongodb"]["latency_ms"] = latency
        status["services"]["mongodb"]["status"] = "Connected"

        # Collection stats
        try:
            mongo_db = mongo_client["appdb"]
            col_names = await mongo_db.list_collection_names()
            col_stats = {}
            for col in col_names:
                col_stats[col] = await mongo_db[col].estimated_document_count()
            status["services"]["mongodb"]["collections"] = col_stats
        except Exception:
            pass
    except Exception as e:
        status["services"]["mongodb"]["status"] = f"Error: {str(e)}"
        status["overall"] = "Degraded"

    # ── 3. Redis ──────────────────────────────────────────────────────────────
    try:
        import redis as redis_lib # type: ignore
        from urllib.parse import urlparse, urlunparse # type: ignore
        from app.db.session import settings as app_settings # type: ignore

        raw_url = (
            getattr(app_settings, 'CELERY_BROKER_URL', None)
            or os.getenv("CELERY_BROKER_URL")
            or os.getenv("REDIS_URL")
            or "redis://watch-sec-redis:6379/0"
        )

        def _try_redis_connect(url: str):
            """Attempt a Redis PING and return (client, latency_ms) or raise."""
            t0 = time.time()
            c = redis_lib.from_url(url, socket_timeout=3, decode_responses=True)
            c.ping()
            return c, round((time.time() - t0) * 1000, 2)

        def _strip_auth(url: str) -> str:
            """Return the same URL with username+password removed."""
            p = urlparse(url)
            no_auth = p._replace(netloc=p.hostname + (f":{p.port}" if p.port else ""))
            return urlunparse(no_auth)

        r = None
        latency = 0.0
        try:
            # Attempt 1: URL exactly as configured
            r, latency = _try_redis_connect(raw_url)
        except redis_lib.exceptions.AuthenticationError:
            # Redis has NO password set — retry without credentials
            try:
                r, latency = _try_redis_connect(_strip_auth(raw_url))
            except Exception as inner:
                raise inner
        except redis_lib.exceptions.ResponseError as e:
            if "AUTH" in str(e):
                # Same "no password configured" error but as ResponseError
                r, latency = _try_redis_connect(_strip_auth(raw_url))
            else:
                raise

        if r:
            status["services"]["redis"]["latency_ms"] = latency
            status["services"]["redis"]["status"] = "Connected"
            try:
                info_server = r.info("server")
                info_mem    = r.info("memory")
                info_cli    = r.info("clients")
                status["services"]["redis"]["version"]           = info_server.get("redis_version", "?")
                status["services"]["redis"]["used_memory_human"] = info_mem.get("used_memory_human", "?")
                status["services"]["redis"]["connected_clients"] = info_cli.get("connected_clients", "?")
            except Exception:
                pass
        else:
            status["services"]["redis"]["status"] = "Ping Failed"

    except Exception as e:
        status["services"]["redis"]["status"] = f"Error: {str(e)}"
        status["overall"] = "Degraded"


    # ── 4. Disk Space ─────────────────────────────────────────────────────────
    try:
        storage_path = os.getenv("STORAGE_PATH", "/app/storage")
        if not os.path.exists(storage_path):
            storage_path = "/"
        total, used, free = shutil.disk_usage(storage_path)
        status["disk"] = {
            "path": storage_path,
            "total_gb": round(total / (1024 ** 3), 2),
            "used_gb":  round(used  / (1024 ** 3), 2),
            "free_gb":  round(free  / (1024 ** 3), 2),
            "used_pct": round(used / total * 100, 1),
        }
    except Exception as e:
        status["disk"] = {"error": str(e)}

    # ── Overall Status ────────────────────────────────────────────────────────
    svc_statuses = [s["status"] for s in status["services"].values()]
    if all(s.startswith("Error") or s == "Ping Failed" for s in svc_statuses):
        status["overall"] = "Down"
    elif any(s.startswith("Error") or s == "Ping Failed" for s in svc_statuses):
        status["overall"] = "Degraded"
    else:
        status["overall"] = "Healthy"

    return status
