#!/usr/bin/env python3
"""
MONITORIX ENTERPRISE — PHASE 5.4.4 TEST SUITE 1/5
Threat Intelligence Core: Normalization, Validation, Deduplication & Expiry
===========================================================================
Validates:
  #01: IPv4 canonical normalization (with port stripping, canonical string).
  #02: IPv6 canonical normalization (bracket stripping, compressed format).
  #03: Domain & Subdomain normalization (IDNA lowercase, port/protocol stripping).
  #04: URL canonicalization (scheme/netloc lowercase, path normalization, fragment stripping).
  #05: Hash normalization (SHA-256, MD5, SHA-1 lowercase hex formatting).
  #06: Email, FileName, and Network CIDR normalization.
  #07: Structural validation rejects malformed indicators.
  #08: Duplicate IOC detection and authoritative attribute merging.
  #09: Expiration decay model (active vs expired evaluation).
  #10: Admiralty source reliability and MITRE ATT&CK technique mapping.
"""

import sys
import os
import time
from datetime import datetime, timedelta

# Ensure backend path is in sys.path
for candidate in ["/app", "/opt/projects/monitorix/watch-sec-python/backend"]:
    if os.path.exists(candidate) and candidate not in sys.path:
        sys.path.insert(0, candidate)

from app.services.threat_intel.core import (
    IndicatorType,
    ThreatSeverity,
    ThreatClassification,
    IocRecord,
    normalize_indicator,
    detect_indicator_type,
    ADMIRALTY_RELIABILITY
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


def main():
    print("================================================================================")
    print("MONITORIX ENTERPRISE — PHASE 5.4.4 TEST SUITE 1/5: THREAT INTEL CORE")
    print("================================================================================")

    # Test #01: IPv4 normalization
    try:
        t, v = normalize_indicator("IPv4", "  198.51.100.14:8080 ")
        assert t == IndicatorType.IPV4.value and v == "198.51.100.14"
        record(1, "IPv4 Canonical Normalization", True, f"Normalized to {t}:{v}")
    except Exception as e:
        record(1, "IPv4 Canonical Normalization", False, str(e))

    # Test #02: IPv6 normalization
    try:
        t, v = normalize_indicator("IPv6", "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443")
        assert t == IndicatorType.IPV6.value and "2001:db8:85a3::8a2e:370:7334" == v
        record(2, "IPv6 Canonical Normalization", True, f"Normalized compressed to {v}")
    except Exception as e:
        record(2, "IPv6 Canonical Normalization", False, str(e))

    # Test #03: Domain & Subdomain normalization
    try:
        t1, v1 = normalize_indicator("Domain", "HTTPS://EVIL-C2.COM:443/login")
        assert t1 == IndicatorType.DOMAIN.value and v1 == "evil-c2.com"
        t2, v2 = normalize_indicator("Domain", "sub.c2.evil-corp.net")
        assert t2 == IndicatorType.SUBDOMAIN.value and v2 == "sub.c2.evil-corp.net"
        record(3, "Domain & Subdomain Normalization", True, f"Cleaned domain: {v1}, subdomain: {v2}")
    except Exception as e:
        record(3, "Domain & Subdomain Normalization", False, str(e))

    # Test #04: URL canonicalization
    try:
        t, v = normalize_indicator("URL", "HTTP://BadSite.com:8080/path/to/payload.exe?ref=c2#fragment")
        assert t == IndicatorType.URL.value
        assert v == "http://badsite.com:8080/path/to/payload.exe?ref=c2"  # Fragment stripped, netloc lowercased
        record(4, "URL Canonicalization", True, f"Canonical URL: {v}")
    except Exception as e:
        record(4, "URL Canonicalization", False, str(e))

    # Test #05: Hash normalization
    try:
        sha256_in = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        t_sha, v_sha = normalize_indicator("SHA256", sha256_in)
        assert t_sha == "SHA256" and v_sha == sha256_in.lower()

        md5_in = "D41D8CD98F00B204E9800998ECF8427E"
        t_md5, v_md5 = normalize_indicator("MD5", md5_in)
        assert t_md5 == "MD5" and v_md5 == md5_in.lower()

        sha1_in = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
        t_sha1, v_sha1 = normalize_indicator("SHA1", sha1_in)
        assert t_sha1 == "SHA1" and v_sha1 == sha1_in.lower()
        record(5, "Hash Lowercase Hex Normalization", True, "SHA-256, MD5, and SHA-1 verified")
    except Exception as e:
        record(5, "Hash Lowercase Hex Normalization", False, str(e))

    # Test #06: Email, FileName, and Network CIDR
    try:
        t_em, v_em = normalize_indicator("Email", " PhishUser@Malicious-Domain.COM ")
        assert v_em == "phishuser@malicious-domain.com"
        t_fn, v_fn = normalize_indicator("FileName", "C:\\Windows\\System32\\Mimikatz.EXE")
        assert v_fn == "mimikatz.exe"
        t_net, v_net = normalize_indicator("Network", "198.51.100.0/24")
        assert v_net == "198.51.100.0/24"
        record(6, "Email, FileName, and Network CIDR Normalization", True, f"Normalized {v_em}, {v_fn}, {v_net}")
    except Exception as e:
        record(6, "Email, FileName, and Network CIDR Normalization", False, str(e))

    # Test #07: Validation rejection of malformed indicators
    try:
        rejected = 0
        malformed = [
            ("IPv4", "999.999.999.999"),
            ("SHA256", "tooshort"),
            ("MD5", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
            ("Email", "not-an-email"),
            ("Domain", "invalid_domain..com")
        ]
        for m_type, m_val in malformed:
            try:
                normalize_indicator(m_type, m_val)
            except ValueError:
                rejected += 1
        assert rejected == len(malformed)
        record(7, "Structural Validation Rejection", True, f"Successfully rejected all {rejected} malformed IOCs")
    except Exception as e:
        record(7, "Structural Validation Rejection", False, str(e))

    # Test #08: Duplicate detection & attribute merging
    try:
        ioc1 = IocRecord(
            value="198.51.100.99",
            indicator_type="IPv4",
            threat_classification="Scanner",
            confidence=60,
            severity="Medium",
            tags=["scanner", "shodan"],
            mitre_technique="T1595"
        )
        ioc2 = IocRecord(
            value="198.51.100.99",
            indicator_type="IPv4",
            threat_classification="C2",
            confidence=95,
            severity="Critical",
            tags=["c2", "cobalt_strike"],
            mitre_technique="T1071.001",
            mitre_tactic="Command and Control"
        )
        ioc1.merge_duplicate(ioc2)
        assert ioc1.confidence == 95
        assert ioc1.severity == "Critical"
        assert "cobalt_strike" in ioc1.tags and "scanner" in ioc1.tags
        record(8, "Duplicate IOC Attribute Merging", True, f"Merged confidence: {ioc1.confidence}, tags: {ioc1.tags}")
    except Exception as e:
        record(8, "Duplicate IOC Attribute Merging", False, str(e))

    # Test #09: Expiration decay model
    try:
        active_ioc = IocRecord(value="active-threat.com", indicator_type="Domain", valid_days=30)
        assert not active_ioc.is_expired
        
        expired_ioc = IocRecord(value="expired-threat.com", indicator_type="Domain", valid_days=-1)
        assert expired_ioc.is_expired
        record(9, "Expiration Decay Evaluation", True, "Active and expired states verified")
    except Exception as e:
        record(9, "Expiration Decay Evaluation", False, str(e))

    # Test #10: Admiralty reliability rating
    try:
        assert ADMIRALTY_RELIABILITY["A"] == "Completely reliable"
        ioc = IocRecord(
            value="bad.example.com",
            indicator_type="Domain",
            source_reliability="B2",
            mitre_technique="T1071",
            mitre_tactic="Command and Control"
        )
        d = ioc.to_dict()
        assert d["source_reliability"] == "B2"
        assert d["mitre_technique"] == "T1071"
        record(10, "Admiralty Code & MITRE Association", True, f"Reliability: {d['source_reliability']}, MITRE: {d['mitre_technique']}")
    except Exception as e:
        record(10, "Admiralty Code & MITRE Association", False, str(e))

    print("\n--------------------------------------------------------------------------------")
    print(f"SUITE 1 RESULTS: {PASSED} PASSED, {FAILED} FAILED")
    print("--------------------------------------------------------------------------------")
    if FAILED > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
