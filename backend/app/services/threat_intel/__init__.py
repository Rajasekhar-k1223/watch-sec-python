"""
Monitorix Enterprise Threat Intelligence Platform Module
========================================================
Exports Core, Feed Ingestion, Enrichment, and Real-Time Matching services.
"""

from .core import (
    IndicatorType,
    ThreatSeverity,
    ThreatClassification,
    ADMIRALTY_RELIABILITY,
    ADMIRALTY_CREDIBILITY,
    IocRecord,
    normalize_indicator,
    detect_indicator_type
)
from .feed_engine import (
    is_safe_feed_url,
    FeedIngestionEngine,
    feed_ingestion_engine
)
from .enrichment import (
    ThreatEnrichmentAdapter,
    VirusTotalAdapter,
    AbuseIPDBAdapter,
    AlienVaultOTXAdapter,
    MISPAdapter,
    InternalIntelligenceAdapter,
    EnrichmentManager,
    enrichment_manager
)
from .matcher import (
    IocMatchResult,
    RealTimeIocMatcher,
    ioc_matcher
)

__all__ = [
    "IndicatorType",
    "ThreatSeverity",
    "ThreatClassification",
    "ADMIRALTY_RELIABILITY",
    "ADMIRALTY_CREDIBILITY",
    "IocRecord",
    "normalize_indicator",
    "detect_indicator_type",
    "is_safe_feed_url",
    "FeedIngestionEngine",
    "feed_ingestion_engine",
    "ThreatEnrichmentAdapter",
    "VirusTotalAdapter",
    "AbuseIPDBAdapter",
    "AlienVaultOTXAdapter",
    "MISPAdapter",
    "InternalIntelligenceAdapter",
    "EnrichmentManager",
    "enrichment_manager",
    "IocMatchResult",
    "RealTimeIocMatcher",
    "ioc_matcher"
]

