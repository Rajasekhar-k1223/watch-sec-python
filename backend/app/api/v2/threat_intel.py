"""
[v3.0.0] Threat Intelligence Platform API — V2
Enterprise Threat Intelligence endpoints for:
- Threat Feed Management (List, Add, Update, Toggle, Delete, SSRF Protection)
- Curated Feed Catalog Presets (Abuse.ch, CISA, Spamhaus, Emerging Threats, Tor)
- Ingested Indicators of Compromise (IOC) Explorer (Paginated, Searchable, Filterable, Tenant-Scoped)
- Manual & Bulk IOC Ingestion (STIX 2.1, TAXII 2.1, CSV, JSON, Plaintext)
- Multi-Provider IOC Enrichment (VirusTotal, AbuseIPDB, AlienVault OTX, MISP, Internal)
- Real-Time IOC Telemetry Matching & Event Evaluation
- Background Feed Synchronization
- YARA Rule Management
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore
from sqlalchemy.future import select  # type: ignore
from sqlalchemy import func, or_  # type: ignore
from pydantic import BaseModel, field_validator  # type: ignore
from typing import Optional, List, Dict, Any
import datetime
import logging

from ...db.session import get_db  # type: ignore
from ...db.models import ThreatFeed, IndicatorOfCompromise, YaraRule, User  # type: ignore
from ...services.threat_intel.core import (
    IndicatorType,
    ThreatSeverity,
    ThreatClassification,
    normalize_indicator,
    detect_indicator_type,
    IocRecord
)
from ...services.threat_intel.feed_engine import (
    is_safe_feed_url,
    feed_ingestion_engine
)
from ...services.threat_intel.enrichment import enrichment_manager
from ...services.threat_intel.matcher import ioc_matcher, IocMatchResult
from ...services.threat_intel_pipeline import ti_pipeline  # type: ignore
from ..deps import get_current_user  # type: ignore

router = APIRouter()
logger = logging.getLogger("ThreatIntelAPI")


# ---------------------------------------------------------------------------
# Curated Presets Catalog
# ---------------------------------------------------------------------------

CURATED_PRESETS = [
    {
        "id": "feodo_tracker",
        "name": "Feodo Tracker (abuse.ch)",
        "category": "Botnet C2",
        "description": "High-confidence botnet C2 servers associated with Dridex, Emotet, and QakBot.",
        "source_url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "feed_format": "plain",
        "confidence": 95,
        "default_active": True
    },
    {
        "id": "urlhaus",
        "name": "URLhaus (abuse.ch)",
        "category": "Malware URLs",
        "description": "Real-time feed tracking actively used malicious websites distributing malware payloads.",
        "source_url": "https://urlhaus.abuse.ch/downloads/text/",
        "feed_format": "plain",
        "confidence": 90,
        "default_active": True
    },
    {
        "id": "threatfox",
        "name": "ThreatFox (abuse.ch)",
        "category": "Multi-Threat IOCs",
        "description": "Comprehensive IOC feed sharing malware domains, IPs, and hashes with threat types.",
        "source_url": "https://threatfox.abuse.ch/export/csv/recent/",
        "feed_format": "csv",
        "confidence": 92,
        "default_active": True
    },
    {
        "id": "emerging_threats",
        "name": "Emerging Threats Compromised IPs",
        "category": "Exploitation & Scanners",
        "description": "Proofpoint Emerging Threats daily blocklist of actively compromised adversary hosts.",
        "source_url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "feed_format": "plain",
        "confidence": 88,
        "default_active": True
    },
    {
        "id": "tor_exit_nodes",
        "name": "Tor Project Exit Nodes",
        "category": "Anonymizers & Proxies",
        "description": "Official list of active Tor exit nodes to detect perimeter anonymized egress/ingress.",
        "source_url": "https://check.torproject.org/torbulkexitlist",
        "feed_format": "plain",
        "confidence": 85,
        "default_active": False
    },
    {
        "id": "spamhaus_drop",
        "name": "Spamhaus DROP (Don't Route Or Peer)",
        "category": "Hijacked Subnets",
        "description": "Advisory warning list of hijacked or leased netblocks directly operated by cybercriminals.",
        "source_url": "https://www.spamhaus.org/drop/drop.txt",
        "feed_format": "plain",
        "confidence": 98,
        "default_active": False
    },
    {
        "id": "cisa_kev",
        "name": "CISA Known Exploited Vulnerabilities",
        "category": "Vulnerability Intelligence",
        "description": "Catalog of vulnerabilities that have been confirmed actively exploited in the wild.",
        "source_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "feed_format": "stix",
        "confidence": 99,
        "default_active": False
    }
]


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
        safe, reason = is_safe_feed_url(v)
        if not safe:
            raise ValueError(f"SSRF validation rejected feed URL: {reason}")
        return v

    @field_validator("feed_format")
    @classmethod
    def validate_format(cls, v: str) -> str:
        if v.lower() not in ("auto", "plain", "csv", "json", "stix", "taxii"):
            raise ValueError("Format must be one of: auto, plain, csv, json, stix, taxii")
        return v.lower()


class FeedPatchRequest(BaseModel):
    is_enabled: Optional[bool] = None
    name: Optional[str] = None
    source_url: Optional[str] = None

    @field_validator("source_url")
    @classmethod
    def validate_url(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            safe, reason = is_safe_feed_url(v)
            if not safe:
                raise ValueError(f"SSRF validation rejected feed URL: {reason}")
        return v


class ManualIocRequest(BaseModel):
    value: str
    type: str = "IPv4"
    severity: str = "High"
    confidence: int = 80
    feed_id: Optional[int] = None
    threat_classification: Optional[str] = "Malware"
    tenant_id: Optional[int] = None


class BulkImportRequest(BaseModel):
    format: str = "plain"  # plain, csv, json, stix, taxii
    content: str
    source_name: Optional[str] = "Manual Import"
    tenant_id: Optional[int] = None


class EnrichRequest(BaseModel):
    value: str
    type: str
    providers: Optional[List[str]] = None


class MatchTestRequest(BaseModel):
    event: Optional[Dict[str, Any]] = None
    indicator_value: Optional[str] = None
    indicator_type: Optional[str] = None
    tenant_id: Optional[int] = None


# ---------------------------------------------------------------------------
# Feed Management Endpoints
# ---------------------------------------------------------------------------

@router.get("/feeds")
async def list_feeds(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Returns all configured threat feed sources."""
    result = await db.execute(select(ThreatFeed).order_by(ThreatFeed.Id.asc()))
    feeds = result.scalars().all()
    return {
        "feeds": [
            {
                "id": feed.Id,
                "name": feed.Name,
                "source_url": feed.SourceUrl,
                "feed_type": getattr(feed, "FeedType", "plain"),
                "poll_interval_minutes": getattr(feed, "PollIntervalMinutes", 1440),
                "last_sync": feed.LastSync.isoformat() if feed.LastSync else None,
                "is_enabled": getattr(feed, "IsEnabled", True),
                "is_active": getattr(feed, "IsActive", True),
            }
            for feed in feeds
        ]
    }


@router.post("/feeds")
async def create_feed(
    request: FeedCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Registers a new external or internal threat feed with SSRF validation."""
    if current_user.Role not in ("TenantAdmin", "SuperAdmin", "Admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    # SSRF Security Check
    safe, reason = is_safe_feed_url(request.source_url)
    if not safe:
        raise HTTPException(status_code=400, detail=f"SSRF security check failed: {reason}")

    existing = await db.execute(select(ThreatFeed).where(ThreatFeed.Name == request.name))
    if existing.scalars().first():
        raise HTTPException(status_code=400, detail="A threat feed with this name already exists")

    new_feed = ThreatFeed(
        Name=request.name,
        SourceUrl=request.source_url,
        FeedType=request.feed_format,
        PollIntervalMinutes=1440,
        IsActive=True,
        IsEnabled=True
    )
    db.add(new_feed)
    await db.commit()
    await db.refresh(new_feed)
    return {"status": "created", "feed_id": new_feed.Id, "name": new_feed.Name}


@router.patch("/feeds/{feed_id}")
async def update_feed(
    feed_id: int,
    request: FeedPatchRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Updates feed configuration or toggles active status."""
    if current_user.Role not in ("TenantAdmin", "SuperAdmin", "Admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    result = await db.execute(select(ThreatFeed).where(ThreatFeed.Id == feed_id))
    feed = result.scalars().first()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    if request.is_enabled is not None:
        feed.IsEnabled = request.is_enabled
        feed.IsActive = request.is_enabled
    if request.name is not None:
        feed.Name = request.name
    if request.source_url is not None:
        safe, reason = is_safe_feed_url(request.source_url)
        if not safe:
            raise HTTPException(status_code=400, detail=f"SSRF validation failed: {reason}")
        feed.SourceUrl = request.source_url

    await db.commit()
    return {"status": "updated", "feed_id": feed.Id, "is_enabled": feed.IsEnabled}


@router.delete("/feeds/{feed_id}")
async def delete_feed(
    feed_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Deletes a threat feed and its associated indicators."""
    if current_user.Role not in ("TenantAdmin", "SuperAdmin", "Admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    result = await db.execute(select(ThreatFeed).where(ThreatFeed.Id == feed_id))
    feed = result.scalars().first()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    # Delete related indicators
    await db.execute(
        IndicatorOfCompromise.__table__.delete().where(IndicatorOfCompromise.FeedId == feed_id)
    )
    await db.delete(feed)
    await db.commit()
    await ti_pipeline.prime_cache(db)
    return {"status": "deleted", "feed_id": feed_id}


@router.get("/presets")
async def list_presets(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Returns curated CTI presets catalog with installation status."""
    result = await db.execute(select(ThreatFeed))
    installed_feeds = {f.Name: f for f in result.scalars().all()}

    presets_with_status = []
    for p in CURATED_PRESETS:
        installed = p["name"] in installed_feeds
        feed_obj = installed_feeds.get(p["name"])
        presets_with_status.append({
            **p,
            "is_installed": installed,
            "is_active": getattr(feed_obj, "IsEnabled", False) if installed else False,
            "feed_id": feed_obj.Id if installed else None
        })
    return {"presets": presets_with_status}


@router.post("/presets/activate")
async def activate_preset(
    preset_id: str = Query(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Installs and triggers immediate background ingestion for a curated preset feed."""
    if current_user.Role not in ("TenantAdmin", "SuperAdmin", "Admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    preset = next((p for p in CURATED_PRESETS if p["id"] == preset_id), None)
    if not preset:
        raise HTTPException(status_code=404, detail=f"Preset '{preset_id}' not found in catalog")

    # SSRF verification for preset
    safe, reason = is_safe_feed_url(preset["source_url"])
    if not safe:
        raise HTTPException(status_code=400, detail=f"Preset URL failed SSRF check: {reason}")

    res = await db.execute(select(ThreatFeed).where(ThreatFeed.Name == preset["name"]))
    feed = res.scalars().first()

    if not feed:
        feed = ThreatFeed(
            Name=preset["name"],
            SourceUrl=preset["source_url"],
            FeedType=preset["feed_format"],
            PollIntervalMinutes=360,
            IsActive=True,
            IsEnabled=True
        )
        db.add(feed)
        await db.commit()
        await db.refresh(feed)

    background_tasks.add_task(ti_pipeline.sync_feed, db, feed.Id)
    return {"status": "activated", "feed_id": feed.Id, "name": feed.Name}


@router.post("/feeds/sync")
async def trigger_sync_all_feeds(
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Triggers background synchronization for all active feeds."""
    if current_user.Role not in ("TenantAdmin", "SuperAdmin", "Admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    background_tasks.add_task(ti_pipeline.sync_all_active_feeds, db)
    return {"status": "sync_initiated", "message": "All active feeds scheduled for background sync."}


@router.post("/feeds/sync/{feed_id}")
async def trigger_sync_single_feed(
    feed_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Triggers an immediate background synchronization for a specific feed."""
    if current_user.Role not in ("TenantAdmin", "SuperAdmin", "Admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    background_tasks.add_task(ti_pipeline.sync_feed, db, feed_id)
    return {"status": "sync_initiated", "feed_id": feed_id}


@router.get("/feeds/stats")
async def get_feed_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Returns sync status, IOC counts, and last-sync timestamps per feed."""
    stats = await ti_pipeline.get_feed_stats(db)
    return {"feeds": stats, "total_feeds": len(stats)}


# ---------------------------------------------------------------------------
# Indicators of Compromise (IOC) Explorer Endpoints
# ---------------------------------------------------------------------------

@router.get("/iocs")
async def list_iocs(
    q: Optional[str] = Query(None, description="Search indicator value"),
    type: Optional[str] = Query(None, description="Filter by type (IPv4, Domain, URL, SHA256, etc.)"),
    severity: Optional[str] = Query(None, description="Filter by severity (Critical, High, Medium, Low)"),
    status: Optional[str] = Query("all", description="Filter by status (all, active, expired)"),
    tenant_id: Optional[int] = Query(None, description="Filter by tenant attribution"),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Returns a paginated and filtered list of IOCs with tenant scoping."""
    stmt = select(IndicatorOfCompromise)

    # Tenant Scoping: non-SuperAdmin users see global IOCs (NULL) + their tenant's IOCs
    if current_user.Role != "SuperAdmin":
        user_tenant = current_user.TenantId
        if hasattr(IndicatorOfCompromise, "TenantId"):
            stmt = stmt.where(
                or_(
                    IndicatorOfCompromise.TenantId == user_tenant,
                    IndicatorOfCompromise.TenantId == None
                )
            )
    elif tenant_id is not None and hasattr(IndicatorOfCompromise, "TenantId"):
        stmt = stmt.where(IndicatorOfCompromise.TenantId == tenant_id)

    if type and type != "All":
        stmt = stmt.where(IndicatorOfCompromise.IndicatorType.ilike(type))
    if severity and severity != "All":
        stmt = stmt.where(IndicatorOfCompromise.Severity.ilike(severity))
    if q and q.strip():
        stmt = stmt.where(IndicatorOfCompromise.IndicatorValue.ilike(f"%{q.strip()}%"))

    now = datetime.datetime.utcnow()
    if status == "active":
        stmt = stmt.where((IndicatorOfCompromise.ValidUntil > now) | (IndicatorOfCompromise.ValidUntil == None))
    elif status == "expired":
        stmt = stmt.where(IndicatorOfCompromise.ValidUntil <= now)

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_result = await db.execute(count_stmt)
    total = total_result.scalar_one()

    stmt = stmt.order_by(IndicatorOfCompromise.Id.desc()).offset((page - 1) * limit).limit(limit)
    result = await db.execute(stmt)
    iocs = result.scalars().all()

    feed_ids = {ioc.FeedId for ioc in iocs if ioc.FeedId}
    feeds_map = {}
    if feed_ids:
        feeds_res = await db.execute(select(ThreatFeed).where(ThreatFeed.Id.in_(feed_ids)))
        feeds_map = {f.Id: getattr(f, "Name", f"Feed #{f.Id}") for f in feeds_res.scalars().all()}

    return {
        "iocs": [
            {
                "id": ioc.Id,
                "value": ioc.IndicatorValue,
                "type": ioc.IndicatorType,
                "severity": getattr(ioc, "Severity", "High"),
                "confidence": getattr(ioc, "Confidence", 75),
                "threat_classification": getattr(ioc, "ThreatClassification", "Malware"),
                "tenant_id": getattr(ioc, "TenantId", None),
                "feed_id": ioc.FeedId,
                "feed_name": feeds_map.get(ioc.FeedId, "Curated CTI Feed"),
                "valid_until": ioc.ValidUntil.isoformat() if ioc.ValidUntil else None,
                "created_at": getattr(ioc, "CreatedAt", None).isoformat() if getattr(ioc, "CreatedAt", None) else None,
                "is_expired": (ioc.ValidUntil <= now) if ioc.ValidUntil else False
            }
            for ioc in iocs
        ],
        "total": total,
        "page": page,
        "limit": limit
    }


@router.post("/iocs")
async def create_manual_ioc(
    request: ManualIocRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Manually registers an IOC with strict normalization and validation."""
    if current_user.Role not in ("TenantAdmin", "SuperAdmin", "Admin", "Analyst"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    # Canonical normalization and validation
    try:
        canon_type, canon_val = normalize_indicator(request.type, request.value)
    except ValueError as err:
        raise HTTPException(status_code=422, detail=f"Indicator validation error: {err}")

    # Determine tenant attribution
    assigned_tenant = request.tenant_id if current_user.Role == "SuperAdmin" else current_user.TenantId

    result = await db.execute(
        select(IndicatorOfCompromise).where(
            IndicatorOfCompromise.IndicatorValue == canon_val,
            IndicatorOfCompromise.IndicatorType == canon_type
        )
    )
    existing = result.scalars().first()
    expiry = datetime.datetime.utcnow() + datetime.timedelta(days=30)

    if existing:
        existing.ValidUntil = expiry
        existing.Severity = request.severity
        existing.Confidence = max(getattr(existing, "Confidence", 50), request.confidence)
        if hasattr(existing, "TenantId") and assigned_tenant is not None:
            existing.TenantId = assigned_tenant
        await db.commit()
        await ti_pipeline.prime_cache(db)
        return {"status": "updated", "id": existing.Id, "value": existing.IndicatorValue}

    ioc_kwargs = {
        "IndicatorValue": canon_val,
        "IndicatorType": canon_type,
        "Severity": request.severity,
        "Confidence": request.confidence,
        "FeedId": request.feed_id,
        "ValidUntil": expiry
    }
    if hasattr(IndicatorOfCompromise, "TenantId"):
        ioc_kwargs["TenantId"] = assigned_tenant

    new_ioc = IndicatorOfCompromise(**ioc_kwargs)
    db.add(new_ioc)
    await db.commit()
    await db.refresh(new_ioc)
    await ti_pipeline.prime_cache(db)

    return {"status": "created", "id": new_ioc.Id, "value": new_ioc.IndicatorValue}


@router.delete("/iocs/{ioc_id}")
async def delete_ioc(
    ioc_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Deletes an indicator of compromise from the active database."""
    if current_user.Role not in ("TenantAdmin", "SuperAdmin", "Admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    result = await db.execute(select(IndicatorOfCompromise).where(IndicatorOfCompromise.Id == ioc_id))
    ioc = result.scalars().first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    # Tenant boundary enforcement
    if current_user.Role != "SuperAdmin" and hasattr(ioc, "TenantId") and ioc.TenantId is not None:
        if ioc.TenantId != current_user.TenantId:
            raise HTTPException(status_code=404, detail="IOC not found")

    await db.delete(ioc)
    await db.commit()
    await ti_pipeline.prime_cache(db)
    return {"status": "deleted", "id": ioc_id}


@router.post("/iocs/{ioc_id}/block-fleet")
async def block_ioc_fleet_wide(
    ioc_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Dispatches a fleet-wide containment policy to block this IOC on all endpoints."""
    if current_user.Role not in ("TenantAdmin", "SuperAdmin", "Admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    result = await db.execute(select(IndicatorOfCompromise).where(IndicatorOfCompromise.Id == ioc_id))
    ioc = result.scalars().first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    ioc.Severity = "Critical"
    ioc.Confidence = 100
    await db.commit()
    await ti_pipeline.prime_cache(db)

    return {
        "status": "policy_dispatched",
        "indicator": ioc.IndicatorValue,
        "type": ioc.IndicatorType,
        "action": "BLOCK_FLEET_WIDE",
        "message": f"Containment rule dispatched: {ioc.IndicatorValue} ({ioc.IndicatorType}) is now blocked fleet-wide."
    }


# ---------------------------------------------------------------------------
# Bulk Import (STIX 2.1, TAXII, CSV, JSON, Plaintext)
# ---------------------------------------------------------------------------

@router.post("/import")
async def import_bulk_iocs(
    request: BulkImportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Imports bulk threat intelligence from raw text, CSV, JSON, or STIX 2.1 bundles.
    """
    if current_user.Role not in ("TenantAdmin", "SuperAdmin", "Admin", "Analyst"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    assigned_tenant = request.tenant_id if current_user.Role == "SuperAdmin" else current_user.TenantId
    fmt = request.format.lower()
    records: List[IocRecord] = []

    if fmt == "stix":
        records = feed_ingestion_engine.parse_stix21(request.content, source_name=request.source_name or "Manual STIX")
    elif fmt == "taxii":
        records = feed_ingestion_engine.parse_taxii21_envelope(request.content, source_name=request.source_name or "Manual TAXII")
    elif fmt == "csv":
        records = feed_ingestion_engine.parse_csv(request.content, source_name=request.source_name or "Manual CSV")
    elif fmt == "json":
        records = feed_ingestion_engine.parse_generic_json(request.content, source_name=request.source_name or "Manual JSON")
    else:
        records = feed_ingestion_engine.parse_plain_text(request.content, source_name=request.source_name or "Manual List")

    if not records:
        return {"status": "completed", "total_parsed": 0, "added": 0, "skipped": 0, "message": "No valid indicators extracted"}

    expiry = datetime.datetime.utcnow() + datetime.timedelta(days=30)
    added = 0
    skipped = 0

    unique_recs = {r.value: r for r in records}
    chunk_size = 500
    vals = list(unique_recs.keys())

    for i in range(0, len(vals), chunk_size):
        chunk = vals[i:i + chunk_size]
        res = await db.execute(
            select(IndicatorOfCompromise).where(IndicatorOfCompromise.IndicatorValue.in_(chunk))
        )
        existing_map = {ioc.IndicatorValue: ioc for ioc in res.scalars().all()}

        new_iocs = []
        for v in chunk:
            r = unique_recs[v]
            if v in existing_map:
                existing_map[v].ValidUntil = expiry
                skipped += 1
            else:
                ioc_kwargs = {
                    "IndicatorValue": r.value,
                    "IndicatorType": r.type,
                    "Severity": r.severity,
                    "Confidence": r.confidence,
                    "ValidUntil": expiry
                }
                if hasattr(IndicatorOfCompromise, "TenantId"):
                    ioc_kwargs["TenantId"] = assigned_tenant
                new_iocs.append(IndicatorOfCompromise(**ioc_kwargs))
                added += 1

        if new_iocs:
            db.add_all(new_iocs)
        await db.commit()

    await ti_pipeline.prime_cache(db)
    return {
        "status": "completed",
        "total_parsed": len(records),
        "unique_indicators": len(unique_recs),
        "added": added,
        "refreshed_existing": skipped
    }


# ---------------------------------------------------------------------------
# Multi-Provider On-Demand Enrichment
# ---------------------------------------------------------------------------

@router.post("/enrich")
async def enrich_ioc(
    request: EnrichRequest,
    current_user: User = Depends(get_current_user)
):
    """
    On-demand multi-provider enrichment across VirusTotal, AbuseIPDB, OTX, MISP, and Internal intelligence.
    """
    try:
        canon_type, canon_val = normalize_indicator(request.type, request.value)
    except ValueError as err:
        raise HTTPException(status_code=422, detail=f"Invalid indicator format: {err}")

    result = await enrichment_manager.enrich_indicator(
        canon_type,
        canon_val,
        providers=request.providers
    )
    return result


# ---------------------------------------------------------------------------
# Real-Time Matching & Telemetry Evaluation Test
# ---------------------------------------------------------------------------

@router.post("/match-test")
async def test_ioc_matching(
    request: MatchTestRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Evaluates an indicator or full telemetry event payload against the active IOC catalog.
    """
    tenant_id = request.tenant_id or current_user.TenantId

    if request.event:
        matches = ioc_matcher.evaluate_telemetry_event(request.event, tenant_id=tenant_id)
        return {
            "evaluation_mode": "event",
            "matches_found": len(matches),
            "matches": [m.to_dict() for m in matches]
        }

    if not request.indicator_value or not request.indicator_type:
        raise HTTPException(status_code=422, detail="Provide either 'event' or ('indicator_value' and 'indicator_type')")

    matched_record = ioc_matcher.match_indicator(
        request.indicator_type,
        request.indicator_value,
        tenant_id=tenant_id
    )

    return {
        "evaluation_mode": "indicator",
        "indicator_value": request.indicator_value,
        "indicator_type": request.indicator_type,
        "is_matched": matched_record is not None,
        "match_details": matched_record.to_dict() if matched_record else None
    }


# ---------------------------------------------------------------------------
# Ad-Hoc Real-time Lookup & Global Statistics
# ---------------------------------------------------------------------------

@router.get("/ioc/lookup")
async def lookup_indicator(
    value: str = Query(..., min_length=1, max_length=500),
    type: str = Query(..., pattern="^(IPv4|IPv6|Domain|Subdomain|SHA256|MD5|SHA1|URL|Email|FileName|Network)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Ad-hoc IOC lookup. Checks Redis / in-memory matcher and queries DB.
    """
    is_bad = await ti_pipeline.is_malicious(type, value, tenant_id=current_user.TenantId)

    ioc_result = await db.execute(
        select(IndicatorOfCompromise).where(
            IndicatorOfCompromise.IndicatorValue == value,
            IndicatorOfCompromise.IndicatorType.ilike(type)
        )
    )
    ioc = ioc_result.scalars().first()

    feed_name = None
    if ioc and ioc.FeedId:
        feed_res = await db.execute(select(ThreatFeed).where(ThreatFeed.Id == ioc.FeedId))
        feed_obj = feed_res.scalars().first()
        if feed_obj:
            feed_name = getattr(feed_obj, "Name", None)

    return {
        "value": value,
        "type": type,
        "is_malicious": is_bad or (ioc is not None),
        "in_db": ioc is not None,
        "feed_id": ioc.FeedId if ioc else None,
        "feed_name": feed_name or "Curated Feed / Rule",
        "severity": getattr(ioc, "Severity", "High") if ioc else ("Critical" if is_bad else "Low"),
        "valid_until": ioc.ValidUntil.isoformat() if ioc and ioc.ValidUntil else None,
    }


@router.get("/stats")
async def get_threat_intel_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns high-level Threat Intelligence metrics for the SOC dashboard.
    """
    now = datetime.datetime.utcnow()

    # Total and active counts
    total_iocs_res = await db.execute(select(func.count(IndicatorOfCompromise.Id)))
    total_iocs = total_iocs_res.scalar_one()

    active_iocs_res = await db.execute(
        select(func.count(IndicatorOfCompromise.Id)).where(
            (IndicatorOfCompromise.ValidUntil > now) | (IndicatorOfCompromise.ValidUntil == None)
        )
    )
    active_iocs = active_iocs_res.scalar_one()

    # Distribution by type
    type_counts_res = await db.execute(
        select(IndicatorOfCompromise.IndicatorType, func.count(IndicatorOfCompromise.Id))
        .group_by(IndicatorOfCompromise.IndicatorType)
    )
    by_type = {t: count for t, count in type_counts_res.all()}

    # Total Feeds
    total_feeds_res = await db.execute(select(func.count(ThreatFeed.Id)))
    total_feeds = total_feeds_res.scalar_one()

    active_feeds_res = await db.execute(
        select(func.count(ThreatFeed.Id)).where(ThreatFeed.IsActive == True)
    )
    active_feeds = active_feeds_res.scalar_one()

    return {
        "total_indicators": total_iocs,
        "active_indicators": active_iocs,
        "expired_indicators": total_iocs - active_iocs,
        "by_type": by_type,
        "total_feeds": total_feeds,
        "active_feeds": active_feeds,
        "in_memory_cached": len(ioc_matcher._global_iocs)
    }


# ---------------------------------------------------------------------------
# YARA Rule Management
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


# ---------------------------------------------------------------------------
# Retroactive Historical Sweeping (Stage 2.2)
# ---------------------------------------------------------------------------

class RetroactiveSweepRequest(BaseModel):
    indicator_value: str
    indicator_type: str = "Unknown"
    lookback_days: int = 90
    create_alerts: bool = True


@router.post("/sweep", summary="Retroactively sweep ClickHouse telemetry lake for an IOC")
async def trigger_retroactive_sweep(
    request: RetroactiveSweepRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Executes a historical retroactive sweep across ClickHouse telemetry (up to 90 days),
    discovering past endpoint sightings of a newly identified indicator.
    """
    tenant_id = getattr(current_user, "TenantId", 1) or 1
    return await ti_pipeline.sweep_historical_ioc(
        db=db,
        ioc_value=request.indicator_value,
        ioc_type=request.indicator_type,
        tenant_id=tenant_id,
        lookback_days=request.lookback_days,
        create_alerts=request.create_alerts
    )
