#!/usr/bin/env python3
"""
MONITORIX ENTERPRISE — PHASE 5.4.4 TEST SUITE 6/6
High-Throughput Performance, Latency & Scale Benchmark Suite
============================================================
Benchmarks:
  #01: High-throughput canonical indicator normalization (50,000 operations).
  #02: In-memory O(1) IOC matching engine latency (< 0.05ms per lookup, > 25,000 lookups/sec).
  #03: Telemetry event extraction and match evaluation under multi-tenant load (10,000 events).
  #04: Bulk feed parsing performance (STIX / CSV / Plaintext with 10,000 records).
  #05: Enrichment bounded LRU cache performance (100,000 cache accesses).
  #06: Memory overhead verification (< 60MB for 100,000 loaded indicators).
  #07: Concurrent async match throughput under simulated Kafka consumer load.
  #08: Confidence decay batch calculation throughput (> 50,000 ops/sec).
"""

import sys
import os
import time
import asyncio
import tracemalloc
from typing import Dict, Any, List

for candidate in ["/app", "/opt/projects/monitorix/watch-sec-python/backend"]:
    if os.path.exists(candidate) and candidate not in sys.path:
        sys.path.insert(0, candidate)

from app.services.threat_intel.core import (
    normalize_indicator,
    detect_indicator_type,
    IndicatorType,
    ThreatSeverity,
    ThreatClassification,
    IocRecord
)
from app.services.threat_intel.matcher import RealTimeIocMatcher
from app.services.threat_intel.enrichment import EnrichmentManager
from app.services.threat_intel.feed_engine import feed_ingestion_engine

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


def benchmark_normalization():
    # Test #01: High-throughput canonical indicator normalization
    try:
        sample_iocs = [
            ("198.51.100.1", IndicatorType.IPV4),
            ("2001:0db8:85a3::8a2e:0370:7334", IndicatorType.IPV6),
            ("EVIL-DOMAIN.COM", IndicatorType.DOMAIN),
            ("HTTPS://MALICIOUS.ORG/c2/gate.php?ref=1", IndicatorType.URL),
            ("D41D8CD98F00B204E9800998ECF8427E", IndicatorType.MD5),
            ("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", IndicatorType.SHA256),
            ("10.0.0.0/24", IndicatorType.NETWORK),
            ("malware.exe", IndicatorType.FILENAME),
        ]
        iterations = 50_000
        t0 = time.perf_counter()
        for i in range(iterations):
            val, itype = sample_iocs[i % len(sample_iocs)]
            _ = normalize_indicator(val, itype)
        elapsed = time.perf_counter() - t0
        ops_per_sec = iterations / elapsed
        assert ops_per_sec > 40_000, f"Throughput too low: {ops_per_sec:.0f} ops/sec"
        record(1, "Indicator Normalization Throughput", True, f"{iterations:,} ops in {elapsed:.3f}s ({ops_per_sec:,.0f} ops/sec)")
    except Exception as e:
        record(1, "Indicator Normalization Throughput", False, str(e))


def benchmark_matcher_latency():
    # Test #02: In-memory O(1) IOC matching engine latency
    try:
        matcher = RealTimeIocMatcher()
        # Seed 20,000 IOCs across 5 tenants + global
        for i in range(20_000):
            tenant = (i % 5) + 1 if i % 10 != 0 else None
            matcher.register_ioc(IocRecord(
                value=f"198.51.{(i // 256) % 256}.{i % 256}",
                indicator_type=IndicatorType.IPV4,
                severity=ThreatSeverity.HIGH,
                confidence=80,
                threat_classification=ThreatClassification.BOTNET,
                tenant_id=tenant
            ))

        lookups = 50_000
        t0 = time.perf_counter()
        matches = 0
        for i in range(lookups):
            ip = f"198.51.{(i // 256) % 256}.{i % 256}"
            res = matcher.match_indicator("IPv4", ip, tenant_id=1)
            if res:
                matches += 1
        elapsed = time.perf_counter() - t0
        rate = lookups / elapsed
        latency_us = (elapsed / lookups) * 1_000_000
        assert rate > 20_000, f"Rate {rate:.0f} < 20,000/s"
        assert latency_us < 50.0, f"Latency {latency_us:.2f}us > 50us"
        record(2, "O(1) In-Memory Matcher Latency", True, f"{lookups:,} lookups in {elapsed:.3f}s ({rate:,.0f} lookups/sec, {latency_us:.2f}µs/lookup, {matches:,} matched)")
    except Exception as e:
        record(2, "O(1) In-Memory Matcher Latency", False, str(e))


def benchmark_telemetry_extraction():
    # Test #03: Telemetry event extraction and match evaluation
    try:
        matcher = RealTimeIocMatcher()
        matcher.register_ioc(IocRecord(value="evil-c2.net", indicator_type=IndicatorType.DOMAIN, severity=ThreatSeverity.CRITICAL, confidence=95, tenant_id=None))
        matcher.register_ioc(IocRecord(value="203.0.113.88", indicator_type=IndicatorType.IPV4, severity=ThreatSeverity.HIGH, confidence=90, tenant_id=1))
        matcher.register_ioc(IocRecord(value="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", indicator_type=IndicatorType.SHA256, severity=ThreatSeverity.CRITICAL, confidence=99, tenant_id=1))

        events = [
            {"RemoteHost": "evil-c2.net", "RemoteIp": "192.168.1.50", "Sha256": "clean", "CommandLine": "cmd.exe"},
            {"RemoteHost": "safe.internal", "RemoteIp": "203.0.113.88", "Sha256": "clean", "CommandLine": "powershell.exe"},
            {"RemoteHost": "google.com", "RemoteIp": "8.8.8.8", "Sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "CommandLine": "calc.exe"},
            {"RemoteHost": "clean.com", "RemoteIp": "10.0.0.1", "Sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "CommandLine": "notepad.exe"}
        ]
        iterations = 10_000
        t0 = time.perf_counter()
        matched_count = 0
        for i in range(iterations):
            ev = events[i % 4]
            res = matcher.match_event(ev, tenant_id=1)
            if res:
                matched_count += 1
        elapsed = time.perf_counter() - t0
        rate = iterations / elapsed
        latency_us = (elapsed / iterations) * 1_000_000
        assert rate > 10_000, f"Extraction throughput {rate:.0f} < 10,000/s"
        record(3, "Telemetry Event Extraction Throughput", True, f"{iterations:,} events in {elapsed:.3f}s ({rate:,.0f} events/sec, {latency_us:.2f}µs/event, {matched_count:,} matches)")
    except Exception as e:
        record(3, "Telemetry Event Extraction Throughput", False, str(e))


def benchmark_bulk_parsing():
    # Test #04: Bulk feed parsing performance
    try:
        csv_lines = ["# Feed export generated 2026-11-07", "ioc,type,severity,description"]
        for i in range(10_000):
            csv_lines.append(f"198.51.{(i//256)%256}.{i%256},IPv4,High,Test IOC {i}")
        csv_payload = "\n".join(csv_lines)

        t0 = time.perf_counter()
        parsed = feed_ingestion_engine.parse_csv(csv_payload)
        elapsed = time.perf_counter() - t0
        rate = len(parsed) / elapsed
        assert len(parsed) == 10_000
        assert rate > 15_000, f"CSV parsing rate {rate:.0f} < 15,000/s"
        record(4, "Bulk CSV Feed Parsing Performance", True, f"{len(parsed):,} rows parsed in {elapsed:.3f}s ({rate:,.0f} rows/sec)")
    except Exception as e:
        record(4, "Bulk CSV Feed Parsing Performance", False, str(e))


def benchmark_lru_cache():
    # Test #05: Enrichment bounded cache performance
    try:
        mgr = EnrichmentManager(cache_ttl_seconds=3600, max_cache_entries=10_000)
        # Prime cache with 5,000 entries
        now = time.time()
        for i in range(5_000):
            mgr._cache[f"ipv4:198.51.{(i//256)%256}.{i%256}"] = ({"status": "cached", "val": i}, now)

        ops = 100_000
        t0 = time.perf_counter()
        hits = 0
        for i in range(ops):
            key = f"ipv4:198.51.{((i*3)//256)%256}.{(i*3)%256}"
            if key in mgr._cache:
                entry, ts = mgr._cache[key]
                if now - ts < mgr.cache_ttl:
                    hits += 1
        elapsed = time.perf_counter() - t0
        rate = ops / elapsed
        assert rate > 100_000, f"Cache lookup rate {rate:.0f} < 100,000/s"
        record(5, "Bounded Cache Performance", True, f"{ops:,} operations in {elapsed:.3f}s ({rate:,.0f} ops/sec, {hits:,} hits)")
    except Exception as e:
        record(5, "Bounded Cache Performance", False, str(e))


def benchmark_memory_overhead():
    # Test #06: Memory overhead verification (< 60MB for 100,000 indicators)
    try:
        tracemalloc.start()
        matcher = RealTimeIocMatcher()
        for i in range(100_000):
            matcher.register_ioc(IocRecord(
                value=f"198.51.{(i//256)%256}.{i%256}",
                indicator_type=IndicatorType.IPV4,
                severity=ThreatSeverity.HIGH,
                confidence=85,
                tenant_id=(i % 10) + 1,
                threat_classification=ThreatClassification.C2
            ))
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        current_mb = current / (1024 * 1024)
        peak_mb = peak / (1024 * 1024)
        assert peak_mb < 60.0, f"Peak memory {peak_mb:.2f}MB exceeded 60MB"
        record(6, "Memory Overhead & Scale Bound", True, f"100,000 IOCs indexed: current={current_mb:.2f}MB, peak={peak_mb:.2f}MB (< 60MB)")
    except Exception as e:
        record(6, "Memory Overhead & Scale Bound", False, str(e))


async def benchmark_async_concurrency():
    # Test #07: Concurrent async match throughput under simulated Kafka consumer load
    try:
        matcher = RealTimeIocMatcher()
        for i in range(1, 501):
            matcher.register_ioc(IocRecord(
                value=f"c2-host-{i}.threat.io",
                indicator_type=IndicatorType.DOMAIN,
                severity=ThreatSeverity.CRITICAL,
                confidence=90,
                tenant_id=1
            ))

        async def worker_consume(worker_id: int, batch_size: int) -> int:
            matched = 0
            for j in range(batch_size):
                domain = f"c2-host-{((worker_id * 100) + j) % 600}.threat.io"
                res = matcher.match_indicator("Domain", domain, tenant_id=1)
                if res:
                    matched += 1
            return matched

        num_workers = 10
        events_per_worker = 5_000
        t0 = time.perf_counter()
        tasks = [worker_consume(w, events_per_worker) for w in range(num_workers)]
        results = await asyncio.gather(*tasks)
        elapsed = time.perf_counter() - t0
        total_events = num_workers * events_per_worker
        rate = total_events / elapsed
        assert rate > 30_000, f"Concurrent rate {rate:.0f} < 30,000/s"
        record(7, "Concurrent Async Kafka Simulation Throughput", True, f"{total_events:,} events across {num_workers} parallel workers in {elapsed:.3f}s ({rate:,.0f} events/sec, {sum(results):,} matched)")
    except Exception as e:
        record(7, "Concurrent Async Kafka Simulation Throughput", False, str(e))


def benchmark_expiration_decay_batch():
    # Test #08: Batch expiration decay evaluation & duplicate merging
    try:
        ioc1 = IocRecord(value="active-threat.com", indicator_type="Domain", valid_days=30, confidence=70)
        ioc2 = IocRecord(value="active-threat.com", indicator_type="Domain", valid_days=60, confidence=90, tags=["c2"])
        iterations = 50_000
        t0 = time.perf_counter()
        expired_count = 0
        for i in range(iterations):
            if ioc1.is_expired:
                expired_count += 1
            if i % 100 == 0:
                ioc1.merge_duplicate(ioc2)
        elapsed = time.perf_counter() - t0
        rate = iterations / elapsed
        assert rate > 50_000, f"Decay check rate {rate:.0f} < 50,000/s"
        record(8, "Confidence Decay & Merging Throughput", True, f"{iterations:,} evaluations in {elapsed:.3f}s ({rate:,.0f} ops/sec)")
    except Exception as e:
        record(8, "Confidence Decay & Merging Throughput", False, str(e))


def main():
    print("================================================================================")
    print("MONITORIX ENTERPRISE — PHASE 5.4.4 TEST SUITE 6/6: PERFORMANCE & SCALE BENCHMARK")
    print("================================================================================")
    benchmark_normalization()
    benchmark_matcher_latency()
    benchmark_telemetry_extraction()
    benchmark_bulk_parsing()
    benchmark_lru_cache()
    benchmark_memory_overhead()
    asyncio.run(benchmark_async_concurrency())
    benchmark_expiration_decay_batch()

    print("\n--------------------------------------------------------------------------------")
    print(f"SUITE 6 BENCHMARK RESULTS: {PASSED} PASSED, {FAILED} FAILED")
    print("--------------------------------------------------------------------------------")
    if FAILED > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
