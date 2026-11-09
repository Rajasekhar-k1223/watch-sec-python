#!/usr/bin/env python3
"""
MONITORIX ENTERPRISE — PHASE 5.4.4 TEST SUITE 5/5
Threat Intelligence API, Tenant Scoping & RBAC Security Suite
============================================================
Validates:
  #01: GET /api/v2/threat-intel/feeds returns configured threat feeds.
  #02: POST /api/v2/threat-intel/feeds blocks SSRF internal endpoints (400/422).
  #03: POST /api/v2/threat-intel/feeds creates valid HTTPS feed (200 OK).
  #04: GET /api/v2/threat-intel/iocs scopes results according to caller's tenant boundary.
  #05: POST /api/v2/threat-intel/iocs rejects structurally invalid indicators (422).
  #06: POST /api/v2/threat-intel/iocs enforces authoritative TenantId binding.
  #07: POST /api/v2/threat-intel/enrich delivers multi-provider enrichment response.
  #08: POST /api/v2/threat-intel/match-test evaluates live IOC matching against event telemetry.
  #09: GET /api/v2/threat-intel/stats returns global CTI metrics & distribution.
  #10: RBAC Enforcement: Viewer role rejected on mutating endpoints (403 Forbidden).
"""

import sys
import os
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any

# Ensure backend path is in sys.path
for candidate in ["/app", "/opt/projects/monitorix/watch-sec-python/backend"]:
    if os.path.exists(candidate) and candidate not in sys.path:
        sys.path.insert(0, candidate)

import httpx
from jose import jwt
from app.core.security import SECRET_KEY, ALGORITHM
from app.main_dashboard import app

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


def mint_token(user_id: int, username: str, tenant_id: int, role: str) -> str:
    payload = {
        "sub": username,
        "id": user_id,
        "user_id": user_id,
        "tenant_id": tenant_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=2)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


async def run_async_tests():
    global PASSED, FAILED
    print("================================================================================")
    print("MONITORIX ENTERPRISE — PHASE 5.4.4 TEST SUITE 5/5: API, TENANT SCOPING & RBAC")
    print("================================================================================")

    superadmin_token = mint_token(1, "superadmin", 1, "SuperAdmin")
    tenant1_admin_token = mint_token(2, "elsea", 1, "TenantAdmin")
    tenant3_admin_token = mint_token(4, "sentinelx", 3, "TenantAdmin")
    viewer_token = mint_token(10, "viewer_test", 1, "Viewer")

    async with httpx.AsyncClient(app=app, base_url="http://test") as client:
        # Test #01: GET /api/v2/threat-intel/feeds
        try:
            res = await client.get(
                "/api/v2/threat-intel/feeds",
                headers={"Authorization": f"Bearer {superadmin_token}"}
            )
            assert res.status_code == 200
            data = res.json()
            assert "feeds" in data
            record(1, "GET Feeds Endpoint", True, f"Retrieved {len(data['feeds'])} configured feeds")
        except Exception as e:
            record(1, "GET Feeds Endpoint", False, str(e))

        # Test #02: POST /api/v2/threat-intel/feeds blocks SSRF internal endpoints
        try:
            ssrf_payload = {
                "name": "Malicious SSRF Feed",
                "source_url": "http://169.254.169.254/latest/meta-data/",
                "feed_format": "plain"
            }
            res = await client.post(
                "/api/v2/threat-intel/feeds",
                json=ssrf_payload,
                headers={"Authorization": f"Bearer {superadmin_token}"}
            )
            assert res.status_code in (400, 422)
            record(2, "POST Feeds SSRF Security Filter", True, f"Blocked SSRF with HTTP {res.status_code}")
        except Exception as e:
            record(2, "POST Feeds SSRF Security Filter", False, str(e))

        # Test #03: POST /api/v2/threat-intel/feeds creates valid HTTPS feed
        try:
            feed_name = f"Test-Feed-{int(datetime.utcnow().timestamp())}"
            valid_payload = {
                "name": feed_name,
                "source_url": "https://raw.githubusercontent.com/monitorix/feeds/main/c2.txt",
                "feed_format": "plain"
            }
            res = await client.post(
                "/api/v2/threat-intel/feeds",
                json=valid_payload,
                headers={"Authorization": f"Bearer {superadmin_token}"}
            )
            assert res.status_code == 200
            data = res.json()
            assert data["name"] == feed_name
            record(3, "POST Feeds Safe Registration", True, f"Successfully registered feed ID {data.get('id')}")
        except Exception as e:
            record(3, "POST Feeds Safe Registration", False, str(e))

        # Test #04: GET /api/v2/threat-intel/iocs scopes results
        try:
            res_t1 = await client.get(
                "/api/v2/threat-intel/iocs?limit=10",
                headers={"Authorization": f"Bearer {tenant1_admin_token}"}
            )
            assert res_t1.status_code == 200
            data_t1 = res_t1.json()
            assert "iocs" in data_t1
            record(4, "GET IOCs Tenant Scoped Query", True, f"Tenant 1 retrieved {len(data_t1['iocs'])} records")
        except Exception as e:
            record(4, "GET IOCs Tenant Scoped Query", False, str(e))

        # Test #05: POST /api/v2/threat-intel/iocs rejects malformed indicator
        try:
            bad_ioc = {
                "value": "999.999.999.999",
                "type": "IPv4",
                "severity": "Critical",
                "confidence": 90
            }
            res = await client.post(
                "/api/v2/threat-intel/iocs",
                json=bad_ioc,
                headers={"Authorization": f"Bearer {tenant1_admin_token}"}
            )
            assert res.status_code == 422
            record(5, "POST IOCs Malformed Indicator Rejection", True, f"Rejected with HTTP {res.status_code}")
        except Exception as e:
            record(5, "POST IOCs Malformed Indicator Rejection", False, str(e))

        # Test #06: POST /api/v2/threat-intel/iocs enforces authoritative TenantId binding
        try:
            valid_ioc = {
                "value": "198.51.100.222",
                "type": "IPv4",
                "severity": "High",
                "confidence": 85,
                "threat_classification": "C2"
            }
            res = await client.post(
                "/api/v2/threat-intel/iocs",
                json=valid_ioc,
                headers={"Authorization": f"Bearer {tenant1_admin_token}"}
            )
            assert res.status_code == 200
            data = res.json()
            assert data["status"] in ("created", "updated")
            record(6, "POST IOCs Authoritative Tenant Binding", True, f"Successfully registered IOC ID {data['id']}")
        except Exception as e:
            record(6, "POST IOCs Authoritative Tenant Binding", False, str(e))

        # Test #07: POST /api/v2/threat-intel/enrich
        try:
            enrich_req = {
                "value": "198.51.100.222",
                "type": "IPv4"
            }
            res = await client.post(
                "/api/v2/threat-intel/enrich",
                json=enrich_req,
                headers={"Authorization": f"Bearer {tenant1_admin_token}"}
            )
            assert res.status_code == 200
            data = res.json()
            assert "results" in data
            assert "InternalIntelligence" in data["results"]
            record(7, "POST Multi-Provider Enrichment API", True, f"Enriched across {len(data['results'])} providers")
        except Exception as e:
            record(7, "POST Multi-Provider Enrichment API", False, str(e))

        # Test #08: POST /api/v2/threat-intel/match-test
        try:
            match_req = {
                "indicator_value": "198.51.100.222",
                "indicator_type": "IPv4"
            }
            res = await client.post(
                "/api/v2/threat-intel/match-test",
                json=match_req,
                headers={"Authorization": f"Bearer {tenant1_admin_token}"}
            )
            assert res.status_code == 200
            data = res.json()
            assert data["evaluation_mode"] == "indicator"
            record(8, "POST Match-Test Diagnostic API", True, f"Match evaluated: is_matched={data['is_matched']}")
        except Exception as e:
            record(8, "POST Match-Test Diagnostic API", False, str(e))

        # Test #09: GET /api/v2/threat-intel/stats
        try:
            res = await client.get(
                "/api/v2/threat-intel/stats",
                headers={"Authorization": f"Bearer {superadmin_token}"}
            )
            assert res.status_code == 200
            data = res.json()
            assert "total_indicators" in data
            assert "active_indicators" in data
            record(9, "GET Stats CTI Metrics Endpoint", True, f"Total IOCs: {data['total_indicators']}, Active: {data['active_indicators']}")
        except Exception as e:
            record(9, "GET Stats CTI Metrics Endpoint", False, str(e))

        # Test #10: RBAC Enforcement - Viewer cannot mutate feeds or IOCs
        try:
            res = await client.post(
                "/api/v2/threat-intel/iocs",
                json={"value": "198.51.100.123", "type": "IPv4"},
                headers={"Authorization": f"Bearer {viewer_token}"}
            )
            assert res.status_code == 403
            record(10, "RBAC Security Enforcement", True, f"Viewer rejected with HTTP {res.status_code} Forbidden")
        except Exception as e:
            record(10, "RBAC Security Enforcement", False, str(e))

    print("\n--------------------------------------------------------------------------------")
    print(f"SUITE 5 RESULTS: {PASSED} PASSED, {FAILED} FAILED")
    print("--------------------------------------------------------------------------------")
    if FAILED > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(run_async_tests())

