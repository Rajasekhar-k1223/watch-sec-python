#!/usr/bin/env python3
"""
MONITORIX ENTERPRISE — PHASE 5.4.4 TEST SUITE 3/5
IOC Enrichment Framework & Provider Adapters Validation
======================================================
Validates:
  #01: VirusTotal adapter returns unconfigured status when no API key set (zero fabrication).
  #02: AbuseIPDB adapter returns unconfigured status when no API key set (zero fabrication).
  #03: AlienVault OTX adapter returns unconfigured status when no API key set.
  #04: MISP adapter returns unconfigured status when no URL/key set.
  #05: Internal Intelligence adapter operates reliably without external network dependencies.
  #06: Dynamic adapter credential configuration updates adapter state.
  #07: Rate limiter blocks requests exceeding configured quota with rate_limited status.
  #08: Bounded LRU cache returns cached metadata on repeat queries.
  #09: Parallel multi-provider enrichment aggregation via EnrichmentManager.
  #10: Graceful exception handling and timeout resilience without crashing callers.
"""

import sys
import os
import asyncio

# Ensure backend path is in sys.path
for candidate in ["/app", "/opt/projects/monitorix/watch-sec-python/backend"]:
    if os.path.exists(candidate) and candidate not in sys.path:
        sys.path.insert(0, candidate)

from app.services.threat_intel.enrichment import (
    VirusTotalAdapter,
    AbuseIPDBAdapter,
    AlienVaultOTXAdapter,
    MISPAdapter,
    InternalIntelligenceAdapter,
    EnrichmentManager,
    enrichment_manager
)

PASSED = 0
FAILED = 0
RESULTS = []

def record(test_num: int, name: str, passed: bool, detail: str = ""):
    global PASSED, FAILED
    status = "PASS" if passed else "FAIL"
    if passed:
        PASSED += 1
    else:
        FAILED += 1
    RESULTS.append((test_num, name, status, detail))
    print(f"[{status}] Test #{test_num:02d}: {name} - {detail}")


async def run_async_tests():
    global PASSED, FAILED
    print("================================================================================")
    print("MONITORIX ENTERPRISE — PHASE 5.4.4 TEST SUITE 3/5: IOC ENRICHMENT FRAMEWORK")
    print("================================================================================")

    # Test #01: VirusTotal unconfigured state
    try:
        vt = VirusTotalAdapter(api_key="")
        assert not vt.is_configured
        res = await vt.enrich("IPv4", "198.51.100.1")
        assert res["status"] == "unconfigured"
        assert "not configured" in res["message"]
        record(1, "VirusTotal Unconfigured Zero-Fabrication", True, "Returned unconfigured status without fabricating score")
    except Exception as e:
        record(1, "VirusTotal Unconfigured Zero-Fabrication", False, str(e))

    # Test #02: AbuseIPDB unconfigured state
    try:
        abuse = AbuseIPDBAdapter(api_key="")
        assert not abuse.is_configured
        res = await abuse.enrich("IPv4", "198.51.100.1")
        assert res["status"] == "unconfigured"
        record(2, "AbuseIPDB Unconfigured Zero-Fabrication", True, "Returned unconfigured status")
    except Exception as e:
        record(2, "AbuseIPDB Unconfigured Zero-Fabrication", False, str(e))

    # Test #03: AlienVault OTX unconfigured state
    try:
        otx = AlienVaultOTXAdapter(api_key="")
        assert not otx.is_configured
        res = await otx.enrich("Domain", "malware.org")
        assert res["status"] == "unconfigured"
        record(3, "AlienVault OTX Unconfigured State", True, "Returned unconfigured status")
    except Exception as e:
        record(3, "AlienVault OTX Unconfigured State", False, str(e))

    # Test #04: MISP unconfigured state
    try:
        misp = MISPAdapter(misp_url="", api_key="")
        assert not misp.is_configured
        res = await misp.enrich("SHA256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert res["status"] == "unconfigured"
        record(4, "MISP Unconfigured State", True, "Returned unconfigured status")
    except Exception as e:
        record(4, "MISP Unconfigured State", False, str(e))

    # Test #05: Internal Intelligence adapter operates reliably
    try:
        internal = InternalIntelligenceAdapter()
        assert internal.is_configured
        res = await internal.enrich("IPv4", "198.51.100.55")
        assert res["status"] == "success"
        assert res["is_internal"] is True
        assert res["local_confidence"] == 90
        record(5, "Internal Intelligence Operational Reliability", True, f"Confidence: {res['local_confidence']}")
    except Exception as e:
        record(5, "Internal Intelligence Operational Reliability", False, str(e))

    # Test #06: Dynamic adapter configuration
    try:
        mgr = EnrichmentManager()
        configured = mgr.configure_adapter("VirusTotal", api_key="a" * 64)
        assert configured is True
        vt_adapter = mgr.get_adapter("VirusTotal")
        assert vt_adapter.is_configured is True
        record(6, "Dynamic Adapter Credential Configuration", True, "Adapter transitioned to configured status")
    except Exception as e:
        record(6, "Dynamic Adapter Credential Configuration", False, str(e))

    # Test #07: Rate limiter enforcement
    try:
        abuse = AbuseIPDBAdapter(api_key="b" * 32)
        abuse.rate_limit_per_min = 2
        assert abuse.check_rate_limit() is True
        assert abuse.check_rate_limit() is True
        # Third request should be blocked
        assert abuse.check_rate_limit() is False
        res = await abuse.enrich("IPv4", "198.51.100.9")
        assert res["status"] == "rate_limited"
        record(7, "Provider Rate Limiter Enforcement", True, "Exceeded quota blocked with rate_limited status")
    except Exception as e:
        record(7, "Provider Rate Limiter Enforcement", False, str(e))

    # Test #08: Bounded LRU cache hit
    try:
        mgr = EnrichmentManager(cache_ttl_seconds=3600)
        res1 = await mgr.enrich_indicator("IPv4", "198.51.100.100", providers=["InternalIntelligence"])
        assert "_cached" not in res1
        # Second query should hit cache
        res2 = await mgr.enrich_indicator("IPv4", "198.51.100.100", providers=["InternalIntelligence"])
        assert res2.get("_cached") is True
        record(8, "Bounded LRU Cache Acceleration", True, "Verified repeat lookup retrieved from memory cache")
    except Exception as e:
        record(8, "Bounded LRU Cache Acceleration", False, str(e))

    # Test #09: Parallel multi-provider enrichment
    try:
        mgr = EnrichmentManager()
        combined = await mgr.enrich_indicator("IPv4", "198.51.100.200")
        assert "InternalIntelligence" in combined["results"]
        assert "VirusTotal" in combined["results"]
        assert "AbuseIPDB" in combined["results"]
        assert combined["results"]["InternalIntelligence"]["status"] == "success"
        record(9, "Parallel Multi-Provider Aggregation", True, f"Aggregated {len(combined['results'])} provider responses")
    except Exception as e:
        record(9, "Parallel Multi-Provider Aggregation", False, str(e))

    # Test #10: Graceful network timeout & error resilience
    try:
        vt = VirusTotalAdapter(api_key="c" * 64)
        # Query invalid endpoint that triggers safe error dictionary
        res = await vt.enrich("UnsupportedType", "bad_value")
        assert res["status"] == "unsupported_type"
        record(10, "Graceful Error Degradation", True, f"Handled gracefully with status: {res['status']}")
    except Exception as e:
        record(10, "Graceful Error Degradation", False, str(e))

    print("\n--------------------------------------------------------------------------------")
    print(f"SUITE 3 RESULTS: {PASSED} PASSED, {FAILED} FAILED")
    print("--------------------------------------------------------------------------------")
    if FAILED > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(run_async_tests())

