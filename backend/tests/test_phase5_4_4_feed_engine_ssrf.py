#!/usr/bin/env python3
"""
MONITORIX ENTERPRISE — PHASE 5.4.4 TEST SUITE 2/5
Feed Ingestion Engine & SSRF Security Defense Validation
=========================================================
Validates:
  #01: STIX 2.1 JSON bundle parsing (SDO indicators with patterns).
  #02: TAXII 2.1 envelope parsing and collection extraction.
  #03: CSV feed parsing with auto-detected columns and comments.
  #04: Generic structured JSON parsing.
  #05: Plaintext list parsing with comments and ports.
  #06: SSRF Defense: Loopback addresses (127.0.0.1, localhost, ::1) blocked.
  #07: SSRF Defense: Cloud metadata (169.254.169.254) blocked.
  #08: SSRF Defense: Private RFC1918 subnets (10.x, 172.16.x, 192.168.x) blocked.
  #09: SSRF Defense: Non-HTTP(S) protocols (file://, ftp://, gopher://) blocked.
  #10: Malicious & boundary payload handling (malformed JSON, corrupted CSV).
"""

import sys
import os
import json

# Ensure backend path is in sys.path
for candidate in ["/app", "/opt/projects/monitorix/watch-sec-python/backend"]:
    if os.path.exists(candidate) and candidate not in sys.path:
        sys.path.insert(0, candidate)

from app.services.threat_intel.feed_engine import (
    is_safe_feed_url,
    feed_ingestion_engine
)
from app.services.threat_intel.core import IndicatorType

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


def main():
    print("================================================================================")
    print("MONITORIX ENTERPRISE — PHASE 5.4.4 TEST SUITE 2/5: FEED ENGINE & SSRF DEFENSE")
    print("================================================================================")

    # Test #01: STIX 2.1 JSON bundle parsing
    try:
        stix_bundle = {
            "type": "bundle",
            "id": "bundle--12345",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--1",
                    "pattern": "[ipv4-addr:value = '198.51.100.22']",
                    "confidence": 90,
                    "labels": ["malicious-activity", "botnet"]
                },
                {
                    "type": "indicator",
                    "id": "indicator--2",
                    "pattern": "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
                    "confidence": 95,
                    "labels": ["ransomware"]
                },
                {
                    "type": "indicator",
                    "id": "indicator--3",
                    "pattern": "[domain-name:value = 'adversary.org']",
                    "confidence": 85,
                    "labels": ["c2"]
                }
            ]
        }
        records = feed_ingestion_engine.parse_stix21(json.dumps(stix_bundle), source_name="STIX-Test")
        assert len(records) == 3
        types = {r.type for r in records}
        assert IndicatorType.IPV4.value in types
        assert IndicatorType.SHA256.value in types
        assert IndicatorType.DOMAIN.value in types
        record(1, "STIX 2.1 Bundle Parsing", True, f"Successfully parsed {len(records)} SDO indicators")
    except Exception as e:
        record(1, "STIX 2.1 Bundle Parsing", False, str(e))

    # Test #02: TAXII 2.1 envelope parsing
    try:
        taxii_envelope = {
            "more": False,
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--taxii-1",
                    "pattern": "[url:value = 'https://malware-drop.com/beacon.exe']",
                    "confidence": 88
                }
            ]
        }
        records = feed_ingestion_engine.parse_taxii21_envelope(json.dumps(taxii_envelope), source_name="TAXII-Test")
        assert len(records) == 1
        assert records[0].type == IndicatorType.URL.value
        record(2, "TAXII 2.1 Envelope Parsing", True, f"Extracted URL indicator: {records[0].value}")
    except Exception as e:
        record(2, "TAXII 2.1 Envelope Parsing", False, str(e))

    # Test #03: CSV feed parsing with auto-detected columns and comments
    try:
        csv_content = """# Feodo Tracker CSV export
# First_seen,ioc_value,ioc_type,malware,confidence
2026-11-01,198.51.100.45,IPv4,Dridex,95
2026-11-02,c2-banker.net,Domain,QakBot,90
"""
        records = feed_ingestion_engine.parse_csv(csv_content, source_name="CSV-Test")
        assert len(records) == 2
        vals = {r.value for r in records}
        assert "198.51.100.45" in vals
        assert "c2-banker.net" in vals
        record(3, "CSV Feed Auto-Column Parsing", True, f"Parsed {len(records)} indicators ignoring # headers")
    except Exception as e:
        record(3, "CSV Feed Auto-Column Parsing", False, str(e))

    # Test #04: Generic structured JSON parsing
    try:
        json_content = {
            "threats": [
                {"indicator": "198.51.100.77", "type": "IPv4", "severity": "Critical", "confidence": 99},
                {"indicator": "d41d8cd98f00b204e9800998ecf8427e", "type": "MD5", "severity": "High", "confidence": 80}
            ]
        }
        records = feed_ingestion_engine.parse_generic_json(json.dumps(json_content), source_name="JSON-Test")
        assert len(records) == 2
        record(4, "Generic Structured JSON Parsing", True, f"Parsed {len(records)} indicators")
    except Exception as e:
        record(4, "Generic Structured JSON Parsing", False, str(e))

    # Test #05: Plaintext list parsing
    try:
        plain_content = """
# Blocklist
198.51.100.10:8080 # Active Botnet
198.51.100.11
evil-payload.com
"""
        records = feed_ingestion_engine.parse_plain_text(plain_content, source_name="Plain-Test")
        assert len(records) == 3
        vals = {r.value for r in records}
        assert "198.51.100.10" in vals
        assert "198.51.100.11" in vals
        assert "evil-payload.com" in vals
        record(5, "Plaintext Line Parsing & Comment Stripping", True, f"Parsed {len(records)} indicators")
    except Exception as e:
        record(5, "Plaintext Line Parsing & Comment Stripping", False, str(e))

    # Test #06: SSRF Defense - Loopback addresses blocked
    try:
        loopback_urls = [
            "http://127.0.0.1:8000/feed.txt",
            "http://localhost:8000/api",
            "https://127.0.0.53/dns-query",
            "http://[::1]/feed"
        ]
        blocked = 0
        for u in loopback_urls:
            safe, reason = is_safe_feed_url(u)
            if not safe:
                blocked += 1
        assert blocked == len(loopback_urls)
        record(6, "SSRF Defense: Loopback Blocked", True, f"Blocked all {blocked} loopback variants")
    except Exception as e:
        record(6, "SSRF Defense: Loopback Blocked", False, str(e))

    # Test #07: SSRF Defense - Cloud Metadata blocked
    try:
        metadata_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/"
        ]
        blocked = 0
        for u in metadata_urls:
            safe, reason = is_safe_feed_url(u)
            if not safe:
                blocked += 1
        assert blocked == len(metadata_urls)
        record(7, "SSRF Defense: Cloud Metadata Blocked", True, f"Blocked all {blocked} metadata endpoints")
    except Exception as e:
        record(7, "SSRF Defense: Cloud Metadata Blocked", False, str(e))

    # Test #08: SSRF Defense - Private RFC 1918 subnets blocked
    try:
        private_urls = [
            "http://10.0.0.1/threats.csv",
            "https://172.16.0.5:8443/iocs.json",
            "http://192.168.1.100/feed.txt"
        ]
        blocked = 0
        for u in private_urls:
            safe, reason = is_safe_feed_url(u)
            if not safe:
                blocked += 1
        assert blocked == len(private_urls)
        record(8, "SSRF Defense: RFC 1918 Private Subnets Blocked", True, f"Blocked all {blocked} private IP URLs")
    except Exception as e:
        record(8, "SSRF Defense: RFC 1918 Private Subnets Blocked", False, str(e))

    # Test #09: SSRF Defense - Non-HTTP(S) schemes blocked
    try:
        bad_schemes = [
            "file:///etc/passwd",
            "ftp://ftp.badsite.com/iocs.txt",
            "gopher://127.0.0.1:70/",
            "dict://127.0.0.1:11211/"
        ]
        blocked = 0
        for u in bad_schemes:
            safe, reason = is_safe_feed_url(u)
            if not safe:
                blocked += 1
        assert blocked == len(bad_schemes)
        record(9, "SSRF Defense: Prohibited URI Schemes Blocked", True, f"Blocked all {blocked} non-HTTP(S) schemes")
    except Exception as e:
        record(9, "SSRF Defense: Prohibited URI Schemes Blocked", False, str(e))

    # Test #10: Boundary and corrupted payloads handled gracefully
    try:
        assert feed_ingestion_engine.parse_plain_text("") == []
        assert feed_ingestion_engine.parse_csv("not,a,valid,csv") == []
        assert feed_ingestion_engine.parse_stix21("{invalid json") == []
        assert feed_ingestion_engine.parse_generic_json("[]") == []
        record(10, "Boundary & Malformed Payloads Resilience", True, "Zero crashes on corrupted or empty inputs")
    except Exception as e:
        record(10, "Boundary & Malformed Payloads Resilience", False, str(e))

    print("\n--------------------------------------------------------------------------------")
    print(f"SUITE 2 RESULTS: {PASSED} PASSED, {FAILED} FAILED")
    print("--------------------------------------------------------------------------------")
    if FAILED > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
