"""
[v2.3.0] Threat Intelligence Pipeline
Ingests IOC feeds (plain IP lists, CSV, STIX JSON) via HTTP,
normalises them into the IndicatorOfCompromise table, and
primes a Redis set for O(1) real-time matching.
"""
import asyncio
import datetime
import logging
import csv
import io
import json
from typing import Optional, List, Dict, Any

import httpx  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore
from sqlalchemy.future import select  # type: ignore

from ..db.models import IndicatorOfCompromise, ThreatFeed  # type: ignore

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
# Feed Format Parsers
# ---------------------------------------------------------------------------

def _parse_plain_ip_list(content: str) -> List[Dict[str, str]]:
    """Parses a newline-delimited list of IPs/domains, ignoring # comments."""
    results = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Heuristic: IPv4 or IPv6
        import re
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", line):
            results.append({"value": line, "type": "IPv4"})
        elif re.match(r"^[0-9a-fA-F:]+$", line) and ":" in line:
            results.append({"value": line, "type": "IPv6"})
        elif re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", line):
            results.append({"value": line, "type": "Domain"})
    return results


def _parse_csv_feed(content: str, ioc_column: str = "indicator", type_column: str = "type") -> List[Dict[str, str]]:
    """Parses a CSV feed with configurable column names."""
    results = []
    reader = csv.DictReader(io.StringIO(content))
    for row in reader:
        value = row.get(ioc_column, "").strip()
        ioc_type = row.get(type_column, "Unknown").strip()
        if value:
            results.append({"value": value, "type": ioc_type})
    return results


def _parse_stix_json(content: str) -> List[Dict[str, str]]:
    """
    Parses basic STIX 2.x JSON bundles.
    Extracts indicator pattern values from `indicator` STIX objects.
    """
    results = []
    try:
        bundle = json.loads(content)
        objects = bundle.get("objects", [])
        for obj in objects:
            if obj.get("type") != "indicator":
                continue
            pattern = obj.get("pattern", "")
            import re
            # Extract IPv4: [ipv4-addr:value = '1.2.3.4']
            for match in re.findall(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern):
                results.append({"value": match, "type": "IPv4"})
            # Extract domain: [domain-name:value = 'evil.com']
            for match in re.findall(r"domain-name:value\s*=\s*'([^']+)'", pattern):
                results.append({"value": match, "type": "Domain"})
            # Extract SHA256: [file:hashes.'SHA-256' = 'abc...']
            for match in re.findall(r"SHA-256'\s*=\s*'([a-fA-F0-9]{64})'", pattern):
                results.append({"value": match, "type": "SHA256"})
            # Extract URL
            for match in re.findall(r"url:value\s*=\s*'([^']+)'", pattern):
                results.append({"value": match, "type": "URL"})
    except Exception as e:
        logger.warning(f"[ThreatIntel] STIX parse error: {e}")
    return results


# ---------------------------------------------------------------------------
# Main Pipeline Class
# ---------------------------------------------------------------------------

class ThreatIntelPipeline:

    async def sync_feed(self, db: AsyncSession, feed_id: int) -> Dict[str, Any]:
        """
        Syncs a single threat feed by ID.
        Fetches from feed.SourceUrl, parses based on detected format,
        upserts IOCs into DB, and primes Redis cache.
        Returns a result summary dict.
        """
        result = await db.execute(select(ThreatFeed).where(ThreatFeed.Id == feed_id))
        feed = result.scalars().first()
        if not feed:
            return {"success": False, "error": "Feed not found"}

        indicators = await self._fetch_and_parse(feed.SourceUrl, getattr(feed, "FeedFormat", "auto"))
        if indicators is None:
            await self._update_feed_sync_status(db, feed, success=False, error="Fetch failed")
            return {"success": False, "feed_id": feed_id, "error": "HTTP fetch failed"}

        added, skipped = await self._upsert_indicators(db, feed, indicators)
        await self._update_feed_sync_status(db, feed, success=True)
        await self.prime_cache(db)

        logger.info(f"[ThreatIntel] Feed {feed_id} synced: +{added} added, {skipped} skipped")
        return {
            "success": True,
            "feed_id": feed_id,
            "indicators_fetched": len(indicators),
            "added": added,
            "skipped": skipped,
            "synced_at": datetime.datetime.utcnow().isoformat()
        }

    async def sync_all_active_feeds(self, db: AsyncSession) -> List[Dict[str, Any]]:
        """Syncs all enabled threat feeds in parallel. Used by the Celery beat scheduler."""
        result = await db.execute(select(ThreatFeed).where(ThreatFeed.IsEnabled == True))
        feeds = result.scalars().all()
        tasks = [self.sync_feed(db, feed.Id) for feed in feeds]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r if isinstance(r, dict) else {"success": False, "error": str(r)} for r in results]

    async def _fetch_and_parse(self, url: str, fmt: str = "auto") -> Optional[List[Dict[str, str]]]:
        """Fetches content from a threat feed URL and parses it by format."""
        if not url or not url.startswith("https://"):
            logger.warning(f"[ThreatIntel] Skipping insecure/invalid feed URL: {url!r}")
            return None
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                content = resp.text

            if fmt == "stix" or (fmt == "auto" and content.strip().startswith("{")):
                return _parse_stix_json(content)
            elif fmt == "csv" or (fmt == "auto" and "," in content[:200]):
                return _parse_csv_feed(content)
            else:
                return _parse_plain_ip_list(content)
        except Exception as e:
            logger.error(f"[ThreatIntel] Failed to fetch feed {url!r}: {e}")
            return None

    async def _upsert_indicators(
        self, db: AsyncSession, feed: ThreatFeed, indicators: List[Dict[str, str]]
    ):
        """Upserts parsed indicators into the IndicatorOfCompromise table."""
        added = 0
        skipped = 0
        expiry = datetime.datetime.utcnow() + datetime.timedelta(days=7)

        for ind in indicators:
            value = ind.get("value", "").strip()
            ioc_type = ind.get("type", "Unknown").strip()
            if not value:
                continue

            existing_result = await db.execute(
                select(IndicatorOfCompromise).where(
                    IndicatorOfCompromise.IndicatorValue == value
                )
            )
            existing = existing_result.scalars().first()

            if existing:
                # Refresh expiry on existing IOC
                existing.ValidUntil = expiry
                skipped += 1
            else:
                new_ioc = IndicatorOfCompromise(
                    IndicatorValue=value,
                    IndicatorType=ioc_type,
                    FeedId=feed.Id,
                    ValidUntil=expiry
                )
                db.add(new_ioc)
                added += 1

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
        """Loads all active IOCs into Redis for O(1) real-time matching."""
        now = datetime.datetime.utcnow()
        result = await db.execute(
            select(IndicatorOfCompromise).where(
                (IndicatorOfCompromise.ValidUntil > now) | (IndicatorOfCompromise.ValidUntil == None)
            )
        )
        iocs = result.scalars().all()

        redis = await _get_redis()
        if redis:
            pipe = redis.pipeline()
            pipe.delete("ioc_cache")
            for ioc in iocs:
                key = f"ioc:{ioc.IndicatorType.lower()}:{ioc.IndicatorValue}"
                pipe.sadd("ioc_cache", key)
            await pipe.execute()
            logger.info(f"[ThreatIntel] Redis cache primed with {len(iocs)} IOCs")
        else:
            _redis_fallback.clear()
            for ioc in iocs:
                _redis_fallback.add(f"ioc:{ioc.IndicatorType.lower()}:{ioc.IndicatorValue}")

    async def is_malicious(self, indicator_type: str, value: str) -> bool:
        """O(1) real-time IOC matching. Checks Redis first, falls back to in-memory."""
        key = f"ioc:{indicator_type.lower()}:{value}"
        redis = await _get_redis()
        if redis:
            try:
                return bool(await redis.sismember("ioc_cache", key))
            except Exception:
                pass
        return key in _redis_fallback

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
                "is_enabled": getattr(feed, "IsEnabled", True),
                "last_sync": getattr(feed, "LastSync", None),
                "last_sync_status": getattr(feed, "LastSyncStatus", "never"),
                "ioc_count": count
            })
        return stats


# Singleton for dependency injection
ti_pipeline = ThreatIntelPipeline()
