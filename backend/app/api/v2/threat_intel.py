"""
[v2.3.0] Threat Intelligence API — V2
Provides endpoints for feed management, sync, IOC lookup, feed health stats,
and YARA rule management. Uses async pipeline with Redis-backed IOC cache.
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore
from sqlalchemy.future import select  # type: ignore
from pydantic import BaseModel, field_validator  # type: ignore
from typing import Optional
import logging

from ...db.session import get_db  # type: ignore
from ...db.models import ThreatFeed, IndicatorOfCompromise, YaraRule, User  # type: ignore
from ...services.threat_intel_pipeline import ti_pipeline  # type: ignore
from ..deps import get_current_user  # type: ignore

router = APIRouter()
logger = logging.getLogger("ThreatIntelAPI")


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class YaraRuleRequest(BaseModel):
    name: str
    content: str

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 100:
            raise ValueError("Rule name must be 1-100 characters")
        return v


class FeedCreateRequest(BaseModel):
    name: str
    source_url: str
    feed_format: str = "auto"

    @field_validator("source_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith("https://"):
            raise ValueError("Feed URL must use HTTPS")
        return v

    @field_validator("feed_format")
    @classmethod
    def validate_format(cls, v: str) -> str:
        if v not in ("auto", "plain", "csv", "stix"):
            raise ValueError("Format must be one of: auto, plain, csv, stix")
        return v


# ---------------------------------------------------------------------------
# GET /api/v2/threat-intel/feeds  — List all feeds
# ---------------------------------------------------------------------------

@router.get("/feeds")
async def list_feeds(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Returns all configured threat feed sources."""
    result = await db.execute(select(ThreatFeed))
    feeds = result.scalars().all()
    return {"feeds": [{"id": f.Id, "name": getattr(f, "Name", ""), "source_url": getattr(f, "SourceUrl", ""), "is_enabled": getattr(f, "IsEnabled", True)} for f in feeds]}


# ---------------------------------------------------------------------------
# POST /api/v2/threat-intel/feeds  — Create a new feed
# ---------------------------------------------------------------------------

@router.post("/feeds")
async def create_feed(
    request: FeedCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Creates a new threat intelligence feed source. TenantAdmin or SuperAdmin only."""
    if current_user.Role not in ("TenantAdmin", "SuperAdmin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    feed = ThreatFeed(
        Name=request.name,
        SourceUrl=request.source_url,
        FeedType=request.feed_format,
        IsEnabled=True
    )
    db.add(feed)
    await db.commit()
    await db.refresh(feed)
    return {"status": "created", "feed_id": feed.Id}


# ---------------------------------------------------------------------------
# POST /api/v2/threat-intel/feeds/sync  — Bulk sync all active feeds
# ---------------------------------------------------------------------------

@router.post("/feeds/sync")
async def sync_all_feeds(
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Triggers a background sync of all enabled threat feeds."""
    if current_user.Role not in ("TenantAdmin", "SuperAdmin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    result = await db.execute(select(ThreatFeed))
    feeds = result.scalars().all()
    enabled = [f for f in feeds if getattr(f, "IsEnabled", True)]

    if not enabled:
        return {"status": "no_feeds", "message": "No enabled feeds to sync"}

    background_tasks.add_task(ti_pipeline.sync_all_active_feeds, db)
    return {"status": "sync_initiated", "feed_count": len(enabled)}


# ---------------------------------------------------------------------------
# POST /api/v2/threat-intel/feeds/sync/{feed_id}  — Sync single feed
# ---------------------------------------------------------------------------

@router.post("/feeds/sync/{feed_id}")
async def sync_single_feed(
    feed_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Triggers a background sync for a specific threat feed."""
    if current_user.Role not in ("TenantAdmin", "SuperAdmin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    background_tasks.add_task(ti_pipeline.sync_feed, db, feed_id)
    return {"status": "sync_initiated", "feed_id": feed_id}


# ---------------------------------------------------------------------------
# GET /api/v2/threat-intel/feeds/stats  — Feed health statistics
# ---------------------------------------------------------------------------

@router.get("/feeds/stats")
async def get_feed_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Returns sync status, IOC counts, and last-sync timestamps per feed."""
    stats = await ti_pipeline.get_feed_stats(db)
    return {"feeds": stats, "total_feeds": len(stats)}


# ---------------------------------------------------------------------------
# GET /api/v2/threat-intel/ioc/lookup  — Ad-hoc IOC lookup
# ---------------------------------------------------------------------------

@router.get("/ioc/lookup")
async def lookup_indicator(
    value: str = Query(..., min_length=1, max_length=500),
    type: str = Query(..., pattern="^(IPv4|IPv6|Domain|SHA256|URL|Email)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Ad-hoc IOC lookup. Checks the Redis cache (O(1)) and also queries
    the DB for the full indicator record with feed attribution.
    Security: input is validated against an allowlist of types.
    """
    is_bad = await ti_pipeline.is_malicious(type, value)

    ioc_result = await db.execute(
        select(IndicatorOfCompromise).where(
            IndicatorOfCompromise.IndicatorValue == value,
            IndicatorOfCompromise.IndicatorType == type
        )
    )
    ioc = ioc_result.scalars().first()

    return {
        "value": value,
        "type": type,
        "is_malicious": is_bad,
        "in_db": ioc is not None,
        "feed_id": ioc.FeedId if ioc else None,
        "valid_until": ioc.ValidUntil.isoformat() if ioc and ioc.ValidUntil else None,
    }


# ---------------------------------------------------------------------------
# POST /api/v2/threat-intel/yara  — Add YARA rule
# ---------------------------------------------------------------------------

@router.post("/yara")
async def add_yara_rule(
    request: YaraRuleRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Adds a new YARA detection rule scoped to the current tenant."""
    rule = YaraRule(
        TenantId=current_user.TenantId,
        Name=request.name,
        RuleContent=request.content
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return {"status": "success", "rule_id": rule.Id}
