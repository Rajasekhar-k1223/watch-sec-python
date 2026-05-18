from fastapi import APIRouter, Depends, HTTPException # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from typing import Dict, Any
import time
import os

from ..db.session import get_db, engine # type: ignore
from ..core.celery_app import celery_app # type: ignore

router = APIRouter()

@router.get("/health")
async def deep_health_check(db: AsyncSession = Depends(get_db)):
    """
    [v2.4.0] Deep Health Analytics: Evaluates the status of all backend dependencies.
    Used by Kubernetes Liveness/Readiness probes and SOC monitoring dashboards.
    """
    health_status = {
        "status": "healthy",
        "timestamp": time.time(),
        "components": {}
    }

    # 1. Database Health
    try:
        start_time = time.time()
        await db.execute(select(1))
        db_latency = (time.time() - start_time) * 1000
        health_status["components"]["database"] = {
            "status": "connected",
            "latency_ms": round(db_latency, 2)
        }
    except Exception as e:
        health_status["status"] = "unhealthy"
        health_status["components"]["database"] = {"status": "error", "message": str(e)}

    # 2. Redis / Celery Health
    try:
        inspector = celery_app.control.inspect()
        ping = inspector.ping()
        health_status["components"]["celery_workers"] = {
            "status": "active" if ping else "idle",
            "worker_count": len(ping) if ping else 0
        }
    except Exception as e:
        health_status["components"]["celery_workers"] = {"status": "error", "message": str(e)}

    # 3. Storage Health
    try:
        storage_path = "/app/storage"
        if os.path.exists(storage_path):
            stat = os.statvfs(storage_path)
            free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
            health_status["components"]["storage"] = {
                "status": "available",
                "free_gb": round(free_gb, 2)
            }
    except: pass

    if health_status["status"] == "unhealthy":
        raise HTTPException(status_code=503, detail=health_status)

    return health_status
