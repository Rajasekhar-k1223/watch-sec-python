"""
[v3.0.0] Threat Intelligence Pipeline
Ingests IOC feeds (STIX 2.1, TAXII 2.1, CSV, JSON, plaintext) via HTTP,
normalises them into the IndicatorOfCompromise table, and
primes Redis and in-memory indexes for sub-millisecond real-time matching.
"""
import asyncio
import datetime
import logging
import csv
import io
import json
from typing import Optional, List, Dict, Any, Tuple

import httpx  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore
from sqlalchemy.future import select  # type: ignore

from ..db.models import IndicatorOfCompromise, ThreatFeed, DetectionAlert  # type: ignore
from ..db.clickhouse import clickhouse_db
from .threat_intel.core import (
    IndicatorType,
    ThreatSeverity,
    ThreatClassification,
    IocRecord,
    normalize_indicator,
    detect_indicator_type
)
from .threat_intel.feed_engine import (
    is_safe_feed_url,
    feed_ingestion_engine
)
from .threat_intel.matcher import (
    IocMatchResult,
    ioc_matcher
)

logger = logging.getLogger("ThreatIntelPipeline")

# ---------------------------------------------------------------------------
# Redis client (async) — lazy-initialised singleton
# Falls back to an in-memory set if Redis is unavailable.
# ---------------------------------------------------------------------------

_redis_client = None
_redis_fallback: set = set()

async def _get_redis():
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    try:
        import redis.asyncio as aioredis  # type: ignore
        import os
        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/1")
        _redis_client = aioredis.from_url(redis_url, decode_responses=True)
        await _redis_client.ping()
        logger.info("[ThreatIntel] Redis connected for IOC cache.")
        return _redis_client
    except Exception as e:
        logger.warning(f"[ThreatIntel] Redis unavailable ({e}). Using in-memory fallback.")
        return None


# ---------------------------------------------------------------------------
# Main Pipeline Class
# ---------------------------------------------------------------------------

class ThreatIntelPipeline:
    """
    Enterprise Threat Intelligence Ingestion & Real-Time Correlation Pipeline.
    """

    async def sync_feed(self, db: AsyncSession, feed_id: int) -> Dict[str, Any]:
        """
        Syncs a single threat feed by ID with SSRF defense, auto-parsing, and cache priming.
        """
        result = await db.execute(select(ThreatFeed).where(ThreatFeed.Id == feed_id))
        feed = result.scalars().first()
        if not feed:
            return {"success": False, "error": "Feed not found"}

        feed_url = getattr(feed, "SourceUrl", "")
        # SSRF Protection Check
        safe, reason = is_safe_feed_url(feed_url)
        if not safe:
            err_msg = f"SSRF Check Failed: {reason}"
            logger.warning(f"[ThreatIntel] Blocked insecure feed URL {feed_url!r}: {reason}")
            await self._update_feed_sync_status(db, feed, success=False, error=err_msg)
            return {"success": False, "feed_id": feed_id, "error": err_msg}

        content, fetch_err = await feed_ingestion_engine.fetch_feed_data(feed_url)
        if fetch_err or not content:
            err_msg = fetch_err or "Empty response payload"
            await self._update_feed_sync_status(db, feed, success=False, error=err_msg)
            return {"success": False, "feed_id": feed_id, "error": err_msg}

        # Parse based on FeedType or content sniffing
        feed_type = getattr(feed, "FeedType", "auto") or "auto"
        ft_lower = feed_type.lower()
        records: List[IocRecord] = []

        if "stix" in ft_lower:
            records = feed_ingestion_engine.parse_stix21(content, source_name=feed.Name)
        elif "taxii" in ft_lower:
            records = feed_ingestion_engine.parse_taxii21_envelope(content, source_name=feed.Name)
        elif "csv" in ft_lower:
            records = feed_ingestion_engine.parse_csv(content, source_name=feed.Name)
        elif "json" in ft_lower:
            records = feed_ingestion_engine.parse_generic_json(content, source_name=feed.Name)
        else:
            # Auto-detection
            c_strip = content.strip()
            if c_strip.startswith("{"):
                if '"objects"' in c_strip or '"spec_version"' in c_strip:
                    records = feed_ingestion_engine.parse_stix21(content, source_name=feed.Name)
                else:
                    records = feed_ingestion_engine.parse_generic_json(content, source_name=feed.Name)
            elif "," in content[:300] and "\n" in content[:300]:
                records = feed_ingestion_engine.parse_csv(content, source_name=feed.Name)
            else:
                records = feed_ingestion_engine.parse_plain_text(content, source_name=feed.Name)

        # Convert IocRecords to indicator dicts for database persistence
        indicators = [{"value": r.value, "type": r.type, "severity": r.severity, "confidence": r.confidence} for r in records]

        added, skipped = await self._upsert_indicators(db, feed, indicators)
        await self._update_feed_sync_status(db, feed, success=True)
        await self.prime_cache(db)

        logger.info(f"[ThreatIntel] Feed {feed_id} ({feed.Name}) synced: +{added} added, {skipped} refreshed/skipped")
        return {
            "success": True,
            "feed_id": feed_id,
            "name": feed.Name,
            "indicators_fetched": len(indicators),
            "added": added,
            "skipped": skipped,
            "synced_at": datetime.datetime.utcnow().isoformat()
        }

    async def sync_all_active_feeds(self, db: AsyncSession) -> List[Dict[str, Any]]:
        """Syncs all enabled threat feeds in parallel."""
        result = await db.execute(select(ThreatFeed).where(ThreatFeed.IsActive == True))
        feeds = result.scalars().all()
        tasks = [self.sync_feed(db, feed.Id) for feed in feeds]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r if isinstance(r, dict) else {"success": False, "error": str(r)} for r in results]

    async def _upsert_indicators(
        self, db: AsyncSession, feed: ThreatFeed, indicators: List[Dict[str, Any]]
    ) -> Tuple[int, int]:
        """High-performance batch upsert of parsed indicators into the IndicatorOfCompromise table."""
        added = 0
        skipped = 0
        expiry = datetime.datetime.utcnow() + datetime.timedelta(days=30)

        # Canonical normalization & deduplication in memory
        unique_indicators: Dict[str, Dict[str, Any]] = {}
        for ind in indicators:
            raw_val = ind.get("value", "").strip()
            raw_type = ind.get("type", "Unknown").strip()
            if not raw_val:
                continue
            try:
                canon_type, canon_val = normalize_indicator(raw_type, raw_val)
                if canon_val not in unique_indicators:
                    unique_indicators[canon_val] = {
                        "type": canon_type,
                        "severity": ind.get("severity", ThreatSeverity.HIGH.value),
                        "confidence": ind.get("confidence", 80)
                    }
            except ValueError:
                continue

        vals = list(unique_indicators.keys())
        chunk_size = 500
        for i in range(0, len(vals), chunk_size):
            chunk_vals = vals[i:i + chunk_size]
            
            existing_result = await db.execute(
                select(IndicatorOfCompromise).where(
                    IndicatorOfCompromise.IndicatorValue.in_(chunk_vals)
                )
            )
            existing_records = {ioc.IndicatorValue: ioc for ioc in existing_result.scalars().all()}
            
            new_iocs = []
            for v in chunk_vals:
                if v in existing_records:
                    rec = existing_records[v]
                    rec.ValidUntil = expiry
                    skipped += 1
                else:
                    new_iocs.append(IndicatorOfCompromise(
                        IndicatorValue=v,
                        IndicatorType=unique_indicators[v]["type"],
                        FeedId=feed.Id,
                        Severity=unique_indicators[v]["severity"],
                        Confidence=unique_indicators[v]["confidence"],
                        ValidUntil=expiry
                    ))
                    added += 1

            if new_iocs:
                db.add_all(new_iocs)
            await db.commit()

        return added, skipped

    async def _update_feed_sync_status(
        self, db: AsyncSession, feed: ThreatFeed,
        success: bool, error: Optional[str] = None
    ):
        feed.LastSync = datetime.datetime.utcnow()
        if hasattr(feed, "LastSyncStatus"):
            feed.LastSyncStatus = "success" if success else f"error: {error}"
        await db.commit()

    async def prime_cache(self, db: AsyncSession):
        """Loads all active IOCs into Redis and ioc_matcher for sub-millisecond matching."""
        now = datetime.datetime.utcnow()
        result = await db.execute(
            select(IndicatorOfCompromise).where(
                (IndicatorOfCompromise.ValidUntil > now) | (IndicatorOfCompromise.ValidUntil == None)
            )
        )
        iocs = result.scalars().all()

        # Prime in-memory matcher
        ioc_matcher.clear()
        for ioc in iocs:
            try:
                rec = IocRecord(
                    value=ioc.IndicatorValue,
                    indicator_type=ioc.IndicatorType,
                    severity=ioc.Severity or ThreatSeverity.HIGH.value,
                    confidence=ioc.Confidence or 75,
                    source=f"Feed-{ioc.FeedId}" if ioc.FeedId else "Database",
                    tenant_id=getattr(ioc, "TenantId", None)
                )
                ioc_matcher.register_ioc(rec)
            except Exception:
                continue

        # Prime Redis set
        redis = await _get_redis()
        if redis:
            try:
                pipe = redis.pipeline()
                pipe.delete("ioc_cache")
                for ioc in iocs:
                    key = f"ioc:{ioc.IndicatorType.lower()}:{ioc.IndicatorValue.lower()}"
                    pipe.sadd("ioc_cache", key)
                await pipe.execute()
                logger.info(f"[ThreatIntel] Redis cache primed with {len(iocs)} IOCs")
            except Exception as re_err:
                logger.warning(f"[ThreatIntel] Redis priming error: {re_err}")
        else:
            _redis_fallback.clear()
            for ioc in iocs:
                _redis_fallback.add(f"ioc:{ioc.IndicatorType.lower()}:{ioc.IndicatorValue.lower()}")

    async def is_malicious(self, indicator_type: str, value: str, tenant_id: Optional[int] = None) -> bool:
        """
        O(1) real-time IOC matching.
        Checks ioc_matcher (with tenant-scoping & expiry) first, then Redis/memory fallback.
        """
        # 1. High-speed in-memory matcher with tenant isolation
        match = ioc_matcher.match_indicator(indicator_type, value, tenant_id=tenant_id)
        if match is not None:
            return True

        # 2. Redis cache fallback
        try:
            canon_type, canon_val = normalize_indicator(indicator_type, value)
            key = f"ioc:{canon_type.lower()}:{canon_val.lower()}"
        except ValueError:
            key = f"ioc:{indicator_type.lower()}:{value.lower()}"

        redis = await _get_redis()
        if redis:
            try:
                if await redis.sismember("ioc_cache", key):
                    return True
            except Exception:
                pass

        return key in _redis_fallback

    def match_event(self, event: Dict[str, Any], tenant_id: Optional[int] = None) -> List[IocMatchResult]:
        """
        Evaluates a complete Kafka telemetry event for any IOC matches.
        """
        return ioc_matcher.evaluate_telemetry_event(event, tenant_id=tenant_id)

    async def get_feed_stats(self, db: AsyncSession) -> List[Dict[str, Any]]:
        """Returns sync health statistics per feed."""
        result = await db.execute(select(ThreatFeed))
        feeds = result.scalars().all()

        stats = []
        for feed in feeds:
            ioc_count_result = await db.execute(
                select(IndicatorOfCompromise).where(IndicatorOfCompromise.FeedId == feed.Id)
            )
            count = len(ioc_count_result.scalars().all())
            stats.append({
                "feed_id": feed.Id,
                "name": getattr(feed, "Name", f"Feed-{feed.Id}"),
                "source_url": getattr(feed, "SourceUrl", ""),
                "feed_type": getattr(feed, "FeedType", "plain"),
                "is_enabled": getattr(feed, "IsEnabled", True),
                "last_sync": getattr(feed, "LastSync", None),
                "last_sync_status": getattr(feed, "LastSyncStatus", "never"),
                "ioc_count": count
            })
        return stats

    async def sweep_historical_ioc(
        self,
        db: AsyncSession,
        ioc_value: str,
        ioc_type: str = "Unknown",
        tenant_id: Optional[int] = None,
        lookback_days: int = 90,
        create_alerts: bool = True
    ) -> Dict[str, Any]:
        """
        Retroactively sweeps the 90-day ClickHouse telemetry lake for past sightings of an IOC.
        If past compromised hosts are identified, automatically logs a DetectionAlert.
        """
        now = datetime.datetime.utcnow()
        clean_val = ioc_value.strip()
        if not clean_val:
            return {"status": "error", "message": "Empty indicator value", "hits": 0, "affected_agents": []}

        # Bounded between 1 and 90 days
        bounded_days = min(max(1, lookback_days), 90)

        # Ensure ClickHouse connection is active
        if not clickhouse_db.client:
            clickhouse_db.connect()

        if not clickhouse_db.client:
            return {"status": "error", "message": "ClickHouse telemetry lake offline", "hits": 0, "affected_agents": []}

        try:
            where_clauses = [
                "positionCaseInsensitive(payload, %(ioc_val)s) > 0",
                f"timestamp >= now() - INTERVAL %(days)s DAY"
            ]
            params = {
                "ioc_val": clean_val,
                "days": bounded_days,
                "limit": 100
            }
            if tenant_id:
                where_clauses.append("tenant_id = %(tenant_id)s")
                params["tenant_id"] = str(tenant_id)

            where_str = " AND ".join(where_clauses)
            query = f"""
                SELECT event_id, agent_id, tenant_id, event_type, timestamp, payload
                FROM monitorix.monitorix_telemetry_raw
                WHERE {where_str}
                ORDER BY timestamp DESC
                LIMIT %(limit)s
            """
            rows = clickhouse_db.client.execute(query, params)

            affected_agents = set()
            hits = []
            for r in rows:
                ev_id, ag_id, t_id, ev_type, ts, pl_raw = r
                affected_agents.add(ag_id)
                hits.append({
                    "event_id": str(ev_id),
                    "agent_id": ag_id,
                    "tenant_id": t_id,
                    "event_type": ev_type,
                    "timestamp": ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
                    "snippet": pl_raw[:120] if isinstance(pl_raw, str) else str(pl_raw)[:120]
                })

            created_alert_ids = []
            if create_alerts and hits:
                for ag in affected_agents:
                    alert = DetectionAlert(
                        AgentId=ag,
                        TenantId=int(tenant_id or 1),
                        RuleId=9008,
                        RuleTitle="Retroactive Threat Intel Sighting",
                        Title=f"Retroactive IOC Sighting: {clean_val}",
                        Description=f"Indicator '{clean_val}' ({ioc_type}) detected in past {bounded_days}-day telemetry on host {ag}.",
                        Severity="High",
                        Status="New",
                        MitreTactic="Command and Control",
                        MitreTechnique="T1071.001",
                        Timestamp=now
                    )
                    db.add(alert)
                await db.commit()

            return {
                "status": "success",
                "indicator_value": clean_val,
                "indicator_type": ioc_type,
                "lookback_days": bounded_days,
                "total_hits": len(hits),
                "affected_agents_count": len(affected_agents),
                "affected_agents": sorted(list(affected_agents)),
                "earliest_sighting": hits[-1]["timestamp"] if hits else None,
                "latest_sighting": hits[0]["timestamp"] if hits else None,
                "hits_preview": hits[:10]
            }

        except Exception as e:
            logger.error(f"Error executing historical IOC sweep for '{clean_val}': {e}")
            return {"status": "error", "message": str(e), "hits": 0, "affected_agents": []}


# Singleton for dependency injection
ti_pipeline = ThreatIntelPipeline()
